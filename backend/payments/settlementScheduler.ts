/**
 * SETTLEMENT SCHEDULER
 * ===================
 * Automatically advances external settlements through reconciliation and commit.
 */

import { getSupabase } from '../supabaseClient.js';
import { Audit } from '../security/audit.js';
import {
  settlementLifecycleManager,
  SettlementPhase,
} from './settlementLifecycleManager.js';

export class SettlementScheduler {
  private sb = getSupabase();
  private isRunning = false;
  private schedulerInterval?: ReturnType<typeof setInterval>;
  private checkIntervalMs = 60 * 1000;

  private get client() {
    this.sb = this.sb || getSupabase();
    if (!this.sb) throw new Error('DB_OFFLINE');
    return this.sb;
  }

  start(): void {
    if (this.isRunning) return;
    this.isRunning = true;

    this.processSettlements().catch((error) => {
      console.error('[SettlementScheduler] Initial processing error:', error.message);
    });

    this.schedulerInterval = setInterval(() => {
      this.processSettlements().catch((error) => {
        console.error('[SettlementScheduler] Processing error:', error.message);
      });
    }, this.checkIntervalMs);
  }

  stop(): void {
    if (this.schedulerInterval) {
      clearInterval(this.schedulerInterval);
      this.schedulerInterval = undefined;
    }
    this.isRunning = false;
  }

  private async processSettlements(): Promise<void> {
    await this.processAutoSettleTimeouts();
    await this.processStuckReconciliations();
    await this.retryFailedSettlements();
  }

  private async processAutoSettleTimeouts(): Promise<void> {
    const now = new Date().toISOString();

    const { data: settlements } = await this.client
      .from('settlement_lifecycle')
      .select('id,user_id,amount,provider_id,external_settlement_id,currency,auto_settle_at')
      .eq('current_phase', SettlementPhase.EXTERNAL_PENDING)
      .lte('auto_settle_at', now)
      .is('auto_settle_executed_at', null);

    for (const settlement of settlements || []) {
      try {
        const reconciliationPassed =
          await settlementLifecycleManager.startReconciliation(settlement.id);

        await this.client
          .from('settlement_lifecycle')
          .update({
            auto_settle_executed_at: new Date().toISOString(),
          })
          .eq('id', settlement.id);

        if (reconciliationPassed) {
          await settlementLifecycleManager.commitToInternalLedger(settlement.id);

          await Audit.log('FINANCIAL', settlement.user_id, 'SETTLEMENT_AUTO_COMMITTED', {
            settlementId: settlement.id,
            amount: settlement.amount,
            provider: settlement.provider_id,
          });
        }
      } catch (error: any) {
        console.error(
          `[SettlementScheduler] Error processing settlement ${settlement.id}:`,
          error.message,
        );

        await Audit.log('SECURITY', settlement.user_id, 'SETTLEMENT_AUTO_COMMIT_ERROR', {
          settlementId: settlement.id,
          error: error.message,
        });
      }
    }
  }

  private async processStuckReconciliations(): Promise<void> {
    const stuckBefore = new Date(Date.now() - 10 * 60 * 1000).toISOString();

    const { data: stuckSettlements } = await this.client
      .from('settlement_lifecycle')
      .select('id,user_id,amount,phase_started_at')
      .eq('current_phase', SettlementPhase.RECONCILIATION_RUNNING)
      .lt('phase_started_at', stuckBefore);

    for (const settlement of stuckSettlements || []) {
      await this.client
        .from('settlement_lifecycle')
        .update({
          current_phase: SettlementPhase.FAILED,
          phase_completed_at: new Date().toISOString(),
        })
        .eq('id', settlement.id);

      await Audit.log('SECURITY', settlement.user_id, 'SETTLEMENT_RECONCILIATION_TIMEOUT', {
        settlementId: settlement.id,
        amount: settlement.amount,
        phaseStartedAt: settlement.phase_started_at,
      });
    }
  }

  private async retryFailedSettlements(): Promise<void> {
    const { data: failedSettlements } = await this.client
      .from('settlement_lifecycle')
      .select('id,user_id,retry_count,phase_completed_at,updated_at,created_at')
      .eq('current_phase', SettlementPhase.FAILED)
      .lt('retry_count', 3);

    for (const settlement of failedSettlements || []) {
      const retryCount = settlement.retry_count || 0;
      const failedAt = settlement.phase_completed_at || settlement.updated_at || settlement.created_at;
      const minutesSinceFailure = Math.floor(
        (Date.now() - new Date(failedAt).getTime()) / 60000,
      );
      const backoffMinutes = [1, 5, 30][retryCount] || 60;

      if (minutesSinceFailure < backoffMinutes) continue;

      await this.client
        .from('settlement_lifecycle')
        .update({
          current_phase: SettlementPhase.EXTERNAL_PENDING,
          phase_started_at: new Date().toISOString(),
          retry_count: retryCount + 1,
          auto_settle_at: new Date().toISOString(),
        })
        .eq('id', settlement.id);

      await Audit.log('FINANCIAL', settlement.user_id, 'SETTLEMENT_RETRY_INITIATED', {
        settlementId: settlement.id,
        attempt: retryCount + 1,
      });
    }
  }

  async settlementReceivedManually(settlementId: string): Promise<void> {
    const { data: settlement } = await this.client
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', settlementId)
      .single();

    if (!settlement) throw new Error('Settlement not found');

    const reconciliationPassed =
      await settlementLifecycleManager.startReconciliation(settlementId);

    if (!reconciliationPassed) {
      throw new Error('Reconciliation check failed');
    }

    await settlementLifecycleManager.commitToInternalLedger(settlementId);

    await Audit.log('FINANCIAL', settlement.user_id, 'SETTLEMENT_MANUALLY_CONFIRMED', {
      settlementId,
      amount: settlement.amount,
    });
  }

  async disputeSettlement(
    settlementId: string,
    userId: string,
    reason: string,
  ): Promise<void> {
    const { data: settlement } = await this.client
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', settlementId)
      .eq('user_id', userId)
      .single();

    if (!settlement) throw new Error('Settlement not found');

    await this.client
      .from('settlement_lifecycle')
      .update({
        current_phase: SettlementPhase.DISPUTE_UNDER_REVIEW,
        phase_started_at: new Date().toISOString(),
        metadata: {
          ...(settlement.metadata || {}),
          dispute_reason: reason,
          disputed_at: new Date().toISOString(),
        },
      })
      .eq('id', settlementId);

    await Audit.log('SECURITY', userId, 'SETTLEMENT_DISPUTED', {
      settlementId,
      amount: settlement.amount,
      reason,
      provider: settlement.provider_id,
    });
  }

  async resolveDispute(
    settlementId: string,
    adminId: string,
    resolution: 'APPROVE' | 'REJECT',
    notes?: string,
  ): Promise<void> {
    const { data: settlement } = await this.client
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', settlementId)
      .single();

    if (!settlement) throw new Error('Settlement not found');

    if (resolution === 'APPROVE') {
      const reconciliationPassed =
        await settlementLifecycleManager.startReconciliation(settlementId);

      if (reconciliationPassed) {
        await settlementLifecycleManager.commitToInternalLedger(settlementId);
      }

      await Audit.log('FINANCIAL', settlement.user_id, 'SETTLEMENT_DISPUTE_APPROVED', {
        settlementId,
        resolvedBy: adminId,
        notes,
      });
      return;
    }

    await this.client
      .from('settlement_lifecycle')
      .update({
        current_phase: SettlementPhase.REVERSED,
        phase_completed_at: new Date().toISOString(),
      })
      .eq('id', settlementId);

    await Audit.log('SECURITY', settlement.user_id, 'SETTLEMENT_DISPUTE_REJECTED', {
      settlementId,
      resolvedBy: adminId,
      notes,
    });
  }

  async healthCheck(): Promise<{
    running: boolean;
    pendingCount: Record<string, number>;
  }> {
    const phases = [
      SettlementPhase.EXTERNAL_PENDING,
      SettlementPhase.RECONCILIATION_RUNNING,
      SettlementPhase.READY_FOR_INTERNAL_COMMIT,
      SettlementPhase.FAILED,
      SettlementPhase.DISPUTE_UNDER_REVIEW,
    ];

    const pendingCount: Record<string, number> = {};
    for (const phase of phases) {
      const { count } = await this.client
        .from('settlement_lifecycle')
        .select('*', { count: 'exact', head: true })
        .eq('current_phase', phase);

      pendingCount[phase] = count || 0;
    }

    return {
      running: this.isRunning,
      pendingCount,
    };
  }
}

export const settlementScheduler = new SettlementScheduler();
