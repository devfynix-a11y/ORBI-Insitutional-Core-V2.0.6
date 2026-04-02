import { getAdminSupabase, getSupabase } from '../../services/supabaseClient.js';
import { InternalBroker } from '../../BROKER/index.js';
import { settlementScheduler } from '../payments/settlementScheduler.js';
import { RedisClusterFactory } from './RedisClusterFactory.js';
import { logger } from './logger.js';

type HealthStatus = 'healthy' | 'degraded' | 'unavailable' | 'not_configured';
type PlatformStatus = 'HEALTHY' | 'DEGRADED' | 'CRITICAL';

type QueueHealth = {
  status: HealthStatus;
  queue: {
    pending: number;
    processing: number;
    completed: number;
    failed: number;
    total_active: number;
  };
  scheduler: {
    running: boolean;
    pendingCount: Record<string, number>;
    backlogTotal: number;
  };
};

type OperationalCounts = {
  settlementBacklog: number;
  failedWebhookCount: number;
  reconciliationMismatchCount: number;
  heldForReviewCount: number;
  walletDriftCount: number;
};

type DependencyOverrides = {
  getSupabaseClient?: typeof getSupabase;
  getAdminSupabaseClient?: typeof getAdminSupabase;
  getQueueStatus?: () => Promise<QueueHealth['queue']>;
  getSettlementHealth?: () => Promise<{ running: boolean; pendingCount: Record<string, number> }>;
  isRedisConfigured?: () => boolean;
  getRedisClient?: () => any;
};

export type OperationalHealthSnapshot = {
  status: PlatformStatus;
  capturedAt: string;
  connectivity: {
    db: { status: HealthStatus; latencyMs: number | null; error?: string };
    redis: { status: HealthStatus; latencyMs: number | null; error?: string };
  };
  jobs: QueueHealth;
  metrics: OperationalCounts;
};

const operationalLogger = logger.child({ component: 'operational-health' });

const PROMETHEUS_STATUS_VALUE: Record<PlatformStatus, number> = {
  HEALTHY: 1,
  DEGRADED: 0.5,
  CRITICAL: 0,
};

const CONNECTIVITY_STATUS_VALUE: Record<HealthStatus, number> = {
  healthy: 1,
  degraded: 0.5,
  unavailable: 0,
  not_configured: -1,
};

export class OperationalHealthService {
  constructor(private readonly deps: DependencyOverrides = {}) {}

  private getDbClient() {
    return (this.deps.getAdminSupabaseClient || getAdminSupabase)() || (this.deps.getSupabaseClient || getSupabase)();
  }

  private async measureDbConnectivity(): Promise<OperationalHealthSnapshot['connectivity']['db']> {
    const client = this.getDbClient();
    if (!client) {
      return { status: 'unavailable', latencyMs: null, error: 'Supabase client unavailable' };
    }

    const start = Date.now();
    const { error } = await client
      .from('payment_metrics_snapshots')
      .select('id', { head: true, count: 'exact' })
      .limit(1);

    const latencyMs = Date.now() - start;
    if (error) {
      operationalLogger.warn('ops_health.db_connectivity_failed', { latency_ms: latencyMs, error: error.message });
      return { status: 'unavailable', latencyMs, error: error.message };
    }

    return { status: 'healthy', latencyMs };
  }

  private async measureRedisConnectivity(): Promise<OperationalHealthSnapshot['connectivity']['redis']> {
    const isRedisConfigured = this.deps.isRedisConfigured || (() => RedisClusterFactory.isAvailable());
    if (!isRedisConfigured()) {
      return { status: 'not_configured', latencyMs: null };
    }

    const getRedisClient = this.deps.getRedisClient || (() => RedisClusterFactory.getClient('monitor'));
    const client = getRedisClient();
    if (!client || typeof client.ping !== 'function') {
      return { status: 'unavailable', latencyMs: null, error: 'Redis client unavailable' };
    }

    const start = Date.now();
    try {
      await client.ping();
      return { status: 'healthy', latencyMs: Date.now() - start };
    } catch (error: any) {
      const latencyMs = Date.now() - start;
      operationalLogger.warn('ops_health.redis_connectivity_failed', {
        latency_ms: latencyMs,
        error: error?.message || String(error),
      });
      return { status: 'unavailable', latencyMs, error: error?.message || String(error) };
    }
  }

  private async collectQueueHealth(): Promise<QueueHealth> {
    try {
      const [queue, scheduler] = await Promise.all([
        (this.deps.getQueueStatus || (() => InternalBroker.getQueueStatus()))(),
        (this.deps.getSettlementHealth || (() => settlementScheduler.healthCheck()))(),
      ]);

      const backlogTotal = Object.values(scheduler.pendingCount || {}).reduce((sum, value) => sum + Number(value || 0), 0);
      const status: HealthStatus = !scheduler.running
        ? 'degraded'
        : queue.failed > 0
          ? 'degraded'
          : 'healthy';

      return {
        status,
        queue,
        scheduler: {
          running: scheduler.running,
          pendingCount: scheduler.pendingCount || {},
          backlogTotal,
        },
      };
    } catch (error: any) {
      operationalLogger.error('ops_health.queue_collection_failed', undefined, error);
      return {
        status: 'unavailable',
        queue: { pending: 0, processing: 0, completed: 0, failed: 0, total_active: 0 },
        scheduler: { running: false, pendingCount: {}, backlogTotal: 0 },
      };
    }
  }

  private async countRows(table: string, apply: (query: any) => any): Promise<number> {
    const client = this.getDbClient();
    if (!client) return 0;

    const query = apply(client.from(table).select('*', { count: 'exact', head: true }));
    const { count, error } = await query;
    if (error) {
      operationalLogger.warn('ops_health.metric_count_failed', { table, error: error.message });
      return 0;
    }

    return Number(count || 0);
  }

  private async collectOperationalCounts(settlementBacklog: number): Promise<OperationalCounts> {
    const [failedWebhookCount, reconciliationMismatchCount, heldForReviewCount, walletDriftCount] = await Promise.all([
      this.countRows('provider_webhook_events', (query) => query.in('application_status', ['failed', 'rejected'])),
      this.countRows('reconciliation_reports', (query) => query.eq('status', 'MISMATCH').neq('type', 'WALLET_DRIFT')),
      this.countRows('transactions', (query) => query.eq('status', 'held_for_review')),
      this.countRows('reconciliation_reports', (query) => query.eq('status', 'MISMATCH').eq('type', 'WALLET_DRIFT')),
    ]);

    return {
      settlementBacklog,
      failedWebhookCount,
      reconciliationMismatchCount,
      heldForReviewCount,
      walletDriftCount,
    };
  }

  private deriveOverallStatus(snapshot: Omit<OperationalHealthSnapshot, 'status'>): PlatformStatus {
    if (snapshot.connectivity.db.status === 'unavailable') {
      return 'CRITICAL';
    }

    if (snapshot.connectivity.redis.status === 'unavailable' || snapshot.jobs.status === 'unavailable') {
      return 'CRITICAL';
    }

    if (snapshot.jobs.status === 'degraded') {
      return 'DEGRADED';
    }

    return 'HEALTHY';
  }

  async captureSnapshot(): Promise<OperationalHealthSnapshot> {
    const [db, redis, jobs] = await Promise.all([
      this.measureDbConnectivity(),
      this.measureRedisConnectivity(),
      this.collectQueueHealth(),
    ]);

    const metrics = await this.collectOperationalCounts(jobs.scheduler.backlogTotal);

    const partialSnapshot = {
      capturedAt: new Date().toISOString(),
      connectivity: { db, redis },
      jobs,
      metrics,
    };

    return {
      status: this.deriveOverallStatus(partialSnapshot),
      ...partialSnapshot,
    };
  }

  async persistSnapshot(snapshot?: OperationalHealthSnapshot): Promise<OperationalHealthSnapshot> {
    const resolvedSnapshot = snapshot || await this.captureSnapshot();
    const client = this.getDbClient();
    if (!client) {
      throw new Error('Supabase client unavailable for snapshot persistence');
    }

    const { error } = await client.from('payment_metrics_snapshots').insert({
      data: resolvedSnapshot,
      created_at: resolvedSnapshot.capturedAt,
    });

    if (error) {
      operationalLogger.error('ops_health.snapshot_persist_failed', { captured_at: resolvedSnapshot.capturedAt }, error);
      throw new Error(`Failed to persist operational snapshot: ${error.message}`);
    }

    operationalLogger.info('ops_health.snapshot_persisted', {
      captured_at: resolvedSnapshot.capturedAt,
      status: resolvedSnapshot.status,
      settlement_backlog: resolvedSnapshot.metrics.settlementBacklog,
      failed_webhooks: resolvedSnapshot.metrics.failedWebhookCount,
    });

    return resolvedSnapshot;
  }

  renderPrometheus(snapshot: OperationalHealthSnapshot): string {
    const lines = [
      '# HELP orbi_operational_status Operational platform health status.',
      '# TYPE orbi_operational_status gauge',
      `orbi_operational_status ${PROMETHEUS_STATUS_VALUE[snapshot.status]}`,
      '# HELP orbi_db_connectivity Database connectivity status.',
      '# TYPE orbi_db_connectivity gauge',
      `orbi_db_connectivity ${CONNECTIVITY_STATUS_VALUE[snapshot.connectivity.db.status]}`,
      '# HELP orbi_redis_connectivity Redis connectivity status.',
      '# TYPE orbi_redis_connectivity gauge',
      `orbi_redis_connectivity ${CONNECTIVITY_STATUS_VALUE[snapshot.connectivity.redis.status]}`,
      '# HELP orbi_db_latency_ms Database health probe latency in milliseconds.',
      '# TYPE orbi_db_latency_ms gauge',
      `orbi_db_latency_ms ${snapshot.connectivity.db.latencyMs ?? -1}`,
      '# HELP orbi_redis_latency_ms Redis health probe latency in milliseconds.',
      '# TYPE orbi_redis_latency_ms gauge',
      `orbi_redis_latency_ms ${snapshot.connectivity.redis.latencyMs ?? -1}`,
      '# HELP orbi_job_queue_pending Pending background jobs.',
      '# TYPE orbi_job_queue_pending gauge',
      `orbi_job_queue_pending ${snapshot.jobs.queue.pending}`,
      '# HELP orbi_job_queue_processing Processing background jobs.',
      '# TYPE orbi_job_queue_processing gauge',
      `orbi_job_queue_processing ${snapshot.jobs.queue.processing}`,
      '# HELP orbi_job_queue_failed Failed background jobs.',
      '# TYPE orbi_job_queue_failed gauge',
      `orbi_job_queue_failed ${snapshot.jobs.queue.failed}`,
      '# HELP orbi_settlement_scheduler_running Settlement scheduler running state.',
      '# TYPE orbi_settlement_scheduler_running gauge',
      `orbi_settlement_scheduler_running ${snapshot.jobs.scheduler.running ? 1 : 0}`,
      '# HELP orbi_settlement_backlog Settlement backlog count.',
      '# TYPE orbi_settlement_backlog gauge',
      `orbi_settlement_backlog ${snapshot.metrics.settlementBacklog}`,
      '# HELP orbi_failed_webhook_count Failed or rejected webhook applications.',
      '# TYPE orbi_failed_webhook_count gauge',
      `orbi_failed_webhook_count ${snapshot.metrics.failedWebhookCount}`,
      '# HELP orbi_reconciliation_mismatch_count Reconciliation mismatches excluding wallet drift.',
      '# TYPE orbi_reconciliation_mismatch_count gauge',
      `orbi_reconciliation_mismatch_count ${snapshot.metrics.reconciliationMismatchCount}`,
      '# HELP orbi_held_for_review_count Transactions currently held for review.',
      '# TYPE orbi_held_for_review_count gauge',
      `orbi_held_for_review_count ${snapshot.metrics.heldForReviewCount}`,
      '# HELP orbi_wallet_drift_count Wallet drift mismatches detected.',
      '# TYPE orbi_wallet_drift_count gauge',
      `orbi_wallet_drift_count ${snapshot.metrics.walletDriftCount}`,
      '# HELP orbi_settlement_phase_backlog Settlement backlog by phase.',
      '# TYPE orbi_settlement_phase_backlog gauge',
    ];

    for (const [phase, count] of Object.entries(snapshot.jobs.scheduler.pendingCount || {})) {
      const label = phase.toLowerCase().replace(/[^a-z0-9]+/g, '_');
      lines.push(`orbi_settlement_phase_backlog{phase="${label}"} ${count}`);
    }

    return `${lines.join('\n')}\n`;
  }
}

export const operationalHealthService = new OperationalHealthService();

