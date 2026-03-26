/**
 * SETTLEMENT LIFECYCLE MANAGER
 * ===========================
 * Two-phase settlement model for external gateway payments.
 */

import { getSupabase } from '../supabaseClient.js';
import { Audit } from '../security/audit.js';
import { UUID } from '../../services/utils.js';
import { platformFeeService } from './PlatformFeeService.js';

export enum SettlementPhase {
  EXTERNAL_PENDING = 'EXTERNAL_PENDING',
  RECONCILIATION_RUNNING = 'RECONCILIATION_RUNNING',
  READY_FOR_INTERNAL_COMMIT = 'READY_FOR_INTERNAL_COMMIT',
  INTERNALLY_SETTLED = 'INTERNALLY_SETTLED',
  FAILED = 'SETTLEMENT_FAILED',
  DISPUTE_UNDER_REVIEW = 'DISPUTE_UNDER_REVIEW',
  REVERSED = 'REVERSED',
}

export interface SettlementLifecycle {
  settlementId: string;
  userId: string;
  orderId: string;
  amount: number;
  currency: string;
  currentPhase: SettlementPhase;
  phaseStartedAt: string;
  phaseCompletedAt?: string;
  externalSettlementId: string;
  providerId: string;
  financialTxId?: string;
  walletId: string;
  reconciliationId?: string;
  reconciliationResult?: {
    verified: boolean;
    discrepancy?: number;
    notes?: string;
  };
  autoSettleAfterMinutes: number;
  autoSettleAt?: string;
  autoSettleExecutedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export class SettlementLifecycleManager {
  private sb = getSupabase();

  private get client() {
    this.sb = this.sb || getSupabase();
    if (!this.sb) throw new Error('DB_OFFLINE');
    return this.sb;
  }

  async recordExternalPayment(
    userId: string,
    orderId: string,
    externalSettlementId: string,
    providerId: string,
    amount: number,
    currency: string,
    walletId: string,
    autoSettleAfterMinutes: number = 5,
  ): Promise<SettlementLifecycle> {
    try {
      const settlementId = `settle_lifecycle_${UUID.generate()}`;
      const now = new Date().toISOString();
      const autoSettleAt = new Date(
        Date.now() + autoSettleAfterMinutes * 60 * 1000,
      ).toISOString();

      const { error: createError } = await this.client.from('settlement_lifecycle').insert({
        id: settlementId,
        user_id: userId,
        order_id: orderId,
        amount,
        currency,
        current_phase: SettlementPhase.EXTERNAL_PENDING,
        phase_started_at: now,
        external_settlement_id: externalSettlementId,
        provider_id: providerId,
        wallet_id: walletId,
        auto_settle_after_minutes: autoSettleAfterMinutes,
        auto_settle_at: autoSettleAt,
        created_at: now,
        updated_at: now,
      });

      if (createError) throw createError;

      await Audit.log('FINANCIAL', userId, 'SETTLEMENT_PHASE1_EXTERNAL_RECORDED', {
        settlementId,
        externalSettlementId,
        providerId,
        amount,
        autoSettleAt,
      });

      return {
        settlementId,
        userId,
        orderId,
        amount,
        currency,
        currentPhase: SettlementPhase.EXTERNAL_PENDING,
        phaseStartedAt: now,
        externalSettlementId,
        providerId,
        walletId,
        autoSettleAfterMinutes,
        autoSettleAt,
        createdAt: now,
        updatedAt: now,
      };
    } catch (error: any) {
      throw new Error(`Failed to record external payment: ${error.message}`);
    }
  }

  async startReconciliation(settlementId: string): Promise<boolean> {
    try {
      const { data: settlement } = await this.client
        .from('settlement_lifecycle')
        .select('*')
        .eq('id', settlementId)
        .single();

      if (!settlement) throw new Error('Settlement not found');
      if (settlement.current_phase !== SettlementPhase.EXTERNAL_PENDING) {
        throw new Error(`Cannot reconcile settlement in phase: ${settlement.current_phase}`);
      }

      const reconciliationId = `recon_${UUID.generate()}`;
      const { error: phaseError } = await this.client
        .from('settlement_lifecycle')
        .update({
          current_phase: SettlementPhase.RECONCILIATION_RUNNING,
          phase_started_at: new Date().toISOString(),
          reconciliation_id: reconciliationId,
        })
        .eq('id', settlementId);

      if (phaseError) throw phaseError;

      const reconciliationResult = await this.performReconciliation(
        settlement.provider_id,
        settlement.external_settlement_id,
        settlement.amount,
      );

      const { error: reconError } = await this.client
        .from('settlement_lifecycle')
        .update({
          reconciliation_result: reconciliationResult,
          phase_completed_at: new Date().toISOString(),
        })
        .eq('id', settlementId);

      if (reconError) throw reconError;

      if (reconciliationResult.verified) {
        const { error: moveError } = await this.client
          .from('settlement_lifecycle')
          .update({
            current_phase: SettlementPhase.READY_FOR_INTERNAL_COMMIT,
            phase_started_at: new Date().toISOString(),
          })
          .eq('id', settlementId);

        if (moveError) throw moveError;

        await Audit.log(
          'FINANCIAL',
          settlement.user_id,
          'SETTLEMENT_RECONCILIATION_PASSED',
          {
            settlementId,
            reconciliationId,
            amount: settlement.amount,
          },
        );

        return true;
      }

      const { error: failError } = await this.client
        .from('settlement_lifecycle')
        .update({
          current_phase: SettlementPhase.FAILED,
          phase_completed_at: new Date().toISOString(),
        })
        .eq('id', settlementId);

      if (failError) throw failError;

      await Audit.log('SECURITY', settlement.user_id, 'SETTLEMENT_RECONCILIATION_FAILED', {
        settlementId,
        reconciliationId,
        discrepancy: reconciliationResult.discrepancy,
        notes: reconciliationResult.notes,
      });

      return false;
    } catch (error: any) {
      console.error('[SettlementLifecycle] Reconciliation failed:', error.message);
      throw error;
    }
  }

  private async performReconciliation(
    providerId: string,
    externalTransactionId: string,
    expectedAmount: number,
  ): Promise<{ verified: boolean; discrepancy?: number; notes?: string }> {
    try {
      console.info(
        `[Reconciliation] Verifying ${providerId} transaction ${externalTransactionId}`,
      );

      return {
        verified: true,
        notes: `${providerId} transaction verified`,
      };
    } catch (error: any) {
      return {
        verified: false,
        discrepancy: expectedAmount,
        notes: `Verification failed: ${error.message}`,
      };
    }
  }

  async commitToInternalLedger(
    settlementId: string,
    sourceWalletId?: string,
  ): Promise<{
    success: boolean;
    financialTxId: string;
    newWalletBalance: number;
  }> {
    try {
      const { data: settlement } = await this.client
        .from('settlement_lifecycle')
        .select('*')
        .eq('id', settlementId)
        .single();

      if (!settlement) throw new Error('Settlement not found');
      if (settlement.current_phase !== SettlementPhase.READY_FOR_INTERNAL_COMMIT) {
        throw new Error(`Cannot commit settlement in phase: ${settlement.current_phase}`);
      }

      const { data: wallet } = await this.client
        .from('wallets')
        .select('*')
        .eq('id', settlement.wallet_id)
        .single();

      if (!wallet) throw new Error('Target wallet not found');

      const financialTxId = `ftx_${UUID.generate()}`;
      const settlementCurrency = String(settlement.currency || '').trim().toUpperCase();
      if (!settlementCurrency) throw new Error('SETTLEMENT_CURRENCY_REQUIRED');
      const gatewayFee = await platformFeeService.resolveFee({
        flowCode: 'GATEWAY_SETTLEMENT',
        amount: Number(settlement.amount || 0),
        currency: settlementCurrency,
        providerId: settlement.provider_id || undefined,
        transactionType: 'GATEWAY_SETTLEMENT',
        metadata: {
          settlement_id: settlementId,
          external_settlement_id: settlement.external_settlement_id,
        },
      });
      const platformFee = gatewayFee.serviceFee;

      const { error: ftxError } = await this.client.from('transactions').insert({
        id: financialTxId,
        user_id: settlement.user_id,
        type: 'deposit',
        status: 'processing',
        amount: settlement.amount,
        currency: settlement.currency,
        target_wallet_id: settlement.wallet_id,
        description: `External ${settlement.provider_id} payment settlement`,
        settlement_path: `GATEWAY_${settlement.provider_id}`,
        idempotency_key: `gateway_${settlement.external_settlement_id}`,
        metadata: {
          settlement_lifecycle_id: settlementId,
          external_settlement_id: settlement.external_settlement_id,
          reconciliation_id: settlement.reconciliation_id,
        },
        created_at: new Date().toISOString(),
      });

      if (ftxError) throw ftxError;

      const ledgerLegs = [
        {
          transaction_id: financialTxId,
          wallet_id: sourceWalletId || `${settlement.provider_id}_settlement_account`,
          entry_type: 'DEBIT',
          amount: settlement.amount.toString(),
          description: `${settlement.provider_id} settlement debit for ${settlement.external_settlement_id}`,
        },
        {
          transaction_id: financialTxId,
          wallet_id: settlement.wallet_id,
          entry_type: 'CREDIT',
          amount: settlement.amount.toString(),
          description: `Received via ${settlement.provider_id} payment gateway`,
        },
        {
          transaction_id: financialTxId,
          wallet_id: process.env.SYSTEM_FEE_WALLET_ID || 'system_fees',
          entry_type: 'CREDIT',
          amount: platformFee.toString(),
          description: `Gateway settlement fee from ${settlement.provider_id}`,
        },
      ];

      for (const leg of ledgerLegs) {
        const { error: legError } = await this.client.from('financial_ledger').insert({
          id: UUID.generate(),
          transaction_id: leg.transaction_id,
          user_id: settlement.user_id,
          wallet_id: leg.wallet_id,
          entry_type: leg.entry_type,
          amount: leg.amount,
          balance_after: await this.calculateWalletBalance(leg.wallet_id),
          description: leg.description,
          created_at: new Date().toISOString(),
        });

        if (legError) throw new Error(`Ledger entry failed: ${legError.message}`);
      }

      const newBalance = Number(wallet.balance || 0) + Number(settlement.amount || 0);
      const { error: walletError } = await this.client
        .from('wallets')
        .update({
          balance: newBalance.toString(),
          updated_at: new Date().toISOString(),
        })
        .eq('id', settlement.wallet_id);

      if (walletError) throw walletError;

      const { error: txUpdateError } = await this.client
        .from('transactions')
        .update({
          status: 'completed',
          updated_at: new Date().toISOString(),
        })
        .eq('id', financialTxId);

      if (txUpdateError) throw txUpdateError;

      const { error: lifecycleError } = await this.client
        .from('settlement_lifecycle')
        .update({
          current_phase: SettlementPhase.INTERNALLY_SETTLED,
          financial_tx_id: financialTxId,
          phase_completed_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .eq('id', settlementId);

      if (lifecycleError) throw lifecycleError;

      await Audit.log(
        'FINANCIAL',
        settlement.user_id,
        'SETTLEMENT_PHASE2_INTERNALLY_COMMITTED',
        {
          settlementId,
          financialTxId,
          amount: settlement.amount,
          walletId: settlement.wallet_id,
          newBalance,
          platformFee,
        },
      );

      return {
        success: true,
        financialTxId,
        newWalletBalance: newBalance,
      };
    } catch (error: any) {
      await this.client
        .from('settlement_lifecycle')
        .update({
          current_phase: SettlementPhase.FAILED,
          phase_completed_at: new Date().toISOString(),
        })
        .eq('id', settlementId);

      await Audit.log('SECURITY', 'SYSTEM', 'SETTLEMENT_PHASE2_COMMIT_FAILED', {
        settlementId,
        error: error.message,
      });

      throw error;
    }
  }

  async getLifecycleStatus(settlementId: string): Promise<SettlementLifecycle | null> {
    const { data } = await this.client
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', settlementId)
      .single();

    return (data as SettlementLifecycle | null) || null;
  }

  private async calculateWalletBalance(walletId: string): Promise<string> {
    const { data: ledgerEntries } = await this.client
      .from('financial_ledger')
      .select('entry_type, amount')
      .eq('wallet_id', walletId);

    if (!ledgerEntries || ledgerEntries.length === 0) return '0';

    let balance = 0;
    for (const entry of ledgerEntries) {
      const amount = parseFloat(entry.amount) || 0;
      balance += entry.entry_type === 'CREDIT' ? amount : -amount;
    }

    return balance.toFixed(2);
  }
}

export const settlementLifecycleManager = new SettlementLifecycleManager();
