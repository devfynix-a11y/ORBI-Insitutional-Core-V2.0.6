import assert from 'node:assert/strict';
import test from 'node:test';

import { OperationalHealthService } from '../backend/infrastructure/OperationalHealthService.js';

function createSupabaseStub(counts: Record<string, number>) {
  const inserted: any[] = [];

  return {
    inserted,
    from(table: string) {
      const state: { filters: string[]; insertPayload?: any } = { filters: [] };
      const query: any = {
        select() {
          return query;
        },
        limit() {
          return query;
        },
        eq(column: string, value: string) {
          state.filters.push(`eq:${column}:${value}`);
          return query;
        },
        neq(column: string, value: string) {
          state.filters.push(`neq:${column}:${value}`);
          return query;
        },
        in(column: string, values: string[]) {
          state.filters.push(`in:${column}:${values.join(',')}`);
          return query;
        },
        insert(payload: any) {
          state.insertPayload = payload;
          inserted.push({ table, payload });
          return query;
        },
        then(resolve: (value: any) => any) {
          if (state.insertPayload !== undefined) {
            return Promise.resolve(resolve({ data: null, error: null }));
          }

          const key = `${table}|${state.filters.sort().join('|')}`;
          return Promise.resolve(resolve({ count: counts[key] || 0, error: null }));
        },
      };
      return query;
    },
  };
}

test('operational health snapshot aggregates connectivity queue and counts', async () => {
  const supabase = createSupabaseStub({
    'payment_metrics_snapshots|': 1,
    'provider_webhook_events|in:application_status:failed,rejected': 4,
    'reconciliation_reports|eq:status:MISMATCH|neq:type:WALLET_DRIFT': 2,
    'transactions|eq:status:held_for_review': 3,
    'reconciliation_reports|eq:status:MISMATCH|eq:type:WALLET_DRIFT': 1,
  });

  const service = new OperationalHealthService({
    getAdminSupabaseClient: () => supabase as any,
    getQueueStatus: async () => ({ pending: 2, processing: 1, completed: 7, failed: 0, total_active: 10 }),
    getSettlementHealth: async () => ({
      running: true,
      pendingCount: {
        EXTERNAL_PENDING: 5,
        RECONCILIATION_RUNNING: 2,
      },
    }),
    isRedisConfigured: () => true,
    getRedisClient: () => ({ ping: async () => 'PONG' }),
  });

  const snapshot = await service.captureSnapshot();

  assert.equal(snapshot.status, 'HEALTHY');
  assert.equal(snapshot.connectivity.db.status, 'healthy');
  assert.equal(snapshot.connectivity.redis.status, 'healthy');
  assert.equal(snapshot.jobs.scheduler.backlogTotal, 7);
  assert.equal(snapshot.metrics.settlementBacklog, 7);
  assert.equal(snapshot.metrics.failedWebhookCount, 4);
  assert.equal(snapshot.metrics.reconciliationMismatchCount, 2);
  assert.equal(snapshot.metrics.heldForReviewCount, 3);
  assert.equal(snapshot.metrics.walletDriftCount, 1);
});

test('operational health snapshot becomes critical when db connectivity is unavailable', async () => {
  const service = new OperationalHealthService({
    getSupabaseClient: () => null as any,
    getAdminSupabaseClient: () => null as any,
    getQueueStatus: async () => ({ pending: 0, processing: 0, completed: 0, failed: 0, total_active: 0 }),
    getSettlementHealth: async () => ({ running: true, pendingCount: {} }),
    isRedisConfigured: () => false,
  });

  const snapshot = await service.captureSnapshot();

  assert.equal(snapshot.status, 'CRITICAL');
  assert.equal(snapshot.connectivity.db.status, 'unavailable');
  assert.equal(snapshot.connectivity.redis.status, 'not_configured');
});

test('operational health can persist a snapshot into payment_metrics_snapshots', async () => {
  const supabase = createSupabaseStub({
    'payment_metrics_snapshots|': 1,
    'provider_webhook_events|in:application_status:failed,rejected': 0,
    'reconciliation_reports|eq:status:MISMATCH|neq:type:WALLET_DRIFT': 0,
    'transactions|eq:status:held_for_review': 0,
    'reconciliation_reports|eq:status:MISMATCH|eq:type:WALLET_DRIFT': 0,
  });

  const service = new OperationalHealthService({
    getAdminSupabaseClient: () => supabase as any,
    getQueueStatus: async () => ({ pending: 0, processing: 0, completed: 0, failed: 0, total_active: 0 }),
    getSettlementHealth: async () => ({ running: true, pendingCount: {} }),
    isRedisConfigured: () => false,
  });

  const snapshot = await service.persistSnapshot();

  assert.equal(supabase.inserted.length, 1);
  assert.equal(supabase.inserted[0].table, 'payment_metrics_snapshots');
  assert.deepEqual(supabase.inserted[0].payload.data, snapshot);
});

test('operational health renders Prometheus metrics with enterprise counters', async () => {
  const service = new OperationalHealthService();
  const output = service.renderPrometheus({
    status: 'DEGRADED',
    capturedAt: new Date().toISOString(),
    connectivity: {
      db: { status: 'healthy', latencyMs: 12 },
      redis: { status: 'not_configured', latencyMs: null },
    },
    jobs: {
      status: 'degraded',
      queue: { pending: 3, processing: 1, completed: 4, failed: 2, total_active: 10 },
      scheduler: {
        running: true,
        backlogTotal: 6,
        pendingCount: { EXTERNAL_PENDING: 4, READY_FOR_INTERNAL_COMMIT: 2 },
      },
    },
    metrics: {
      settlementBacklog: 6,
      failedWebhookCount: 2,
      reconciliationMismatchCount: 1,
      heldForReviewCount: 5,
      walletDriftCount: 1,
    },
  });

  assert.match(output, /orbi_operational_status 0\.5/);
  assert.match(output, /orbi_failed_webhook_count 2/);
  assert.match(output, /orbi_settlement_phase_backlog\{phase="external_pending"\} 4/);
  assert.match(output, /orbi_settlement_phase_backlog\{phase="ready_for_internal_commit"\} 2/);
});
