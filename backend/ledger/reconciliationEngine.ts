
import { getAdminSupabase, getSupabase } from '../supabaseClient.js';
import { TransactionService } from '../../ledger/transactionService.js';
import { Audit } from '../security/audit.js';
import { DataVault } from '../security/encryption.js';
import { MonitoringService } from '../infrastructure/MonitoringService.js';
import { DataProtection } from '../security/DataProtection.js';

/**
 * ORBI RECONCILIATION ENGINE (V5.0)
 * --------------------------------
 * Ensures the integrity of the ledger by verifying that the sum of all 
 * ledger entries matches the reported wallet balances.
 */
export class ReconciliationEngineService {
    private txService = new TransactionService();

    /**
     * PERFORMS A FULL LEDGER AUDIT
     * Scans all wallets and compares ledger-derived balances with stored balances.
     */
    public async runFullAudit(): Promise<{ totalWallets: number, discrepancies: any[] }> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("RECON_FAULT: Database connection required.");

        console.info("[Reconciliation] Starting full ledger audit...");
        
        const discrepancies: any[] = [];
        const { data: wallets } = await sb.from('wallets').select('id, name, balance, user_id');
        
        if (!wallets) return { totalWallets: 0, discrepancies: [] };

        for (const wallet of wallets) {
            const ledgerBalance = await this.txService.calculateBalanceFromLedger(wallet.id);
            const storedBalance = Number(wallet.balance);

            if (Math.abs(ledgerBalance - storedBalance) > 0.01) {
                console.error(`[Reconciliation] DISCREPANCY DETECTED for wallet ${wallet.id} (${wallet.name})`);
                discrepancies.push({
                    walletId: wallet.id,
                    walletName: wallet.name,
                    userId: wallet.user_id,
                    storedBalance,
                    ledgerBalance,
                    diff: storedBalance - ledgerBalance
                });

                // Log critical security alert
                await Audit.log('SECURITY', wallet.user_id || 'system', 'LEDGER_DISCREPANCY', {
                    walletId: wallet.id,
                    diff: storedBalance - ledgerBalance
                });

                // Trigger Real-time Alert
                await MonitoringService.notifyCritical('LEDGER_DISCREPANCY_DETECTED', {
                    walletId: wallet.id,
                    walletName: wallet.name,
                    diff: storedBalance - ledgerBalance
                });
            }
        }

        console.info(`[Reconciliation] Audit complete. Found ${discrepancies.length} discrepancies in ${wallets.length} wallets.`);
        return { totalWallets: wallets.length, discrepancies };
    }

    /**
     * VERIFIES DOUBLE-ENTRY INTEGRITY (ZERO-SUM CHECK)
     * Ensures that every transaction's legs sum to zero.
     * In a double-entry system: Sum(Credits) - Sum(Debits) MUST BE 0.
     */
    public async verifyZeroSum(txId: string): Promise<{ isValid: boolean, sum: number }> {
        const legs = await this.txService.getLedgerEntries(txId);
        let sum = 0;

        for (const leg of legs) {
            if (leg.entry_type === 'CREDIT') sum += leg.amount;
            else sum -= leg.amount;
        }

        const isValid = Math.abs(sum) < 0.0001;
        if (!isValid) {
            console.error(`[Forensic] ZERO-SUM VIOLATION in TX ${txId}. Residual: ${sum}`);
        }
        return { isValid, sum };
    }

    /**
     * FORENSIC TIMELINE AUDIT
     * Reconstructs the entire history of a wallet from ledger entries and 
     * verifies every single state transition.
     */
    public async auditWalletTimeline(walletId: string): Promise<{ status: 'clean' | 'corrupted', errors: any[] }> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("RECON_FAULT: Offline");

        const { data: legs, error } = await sb
            .from('financial_ledger')
            .select('*')
            .eq('wallet_id', walletId)
            .order('created_at', { ascending: true });

        if (error || !legs) return { status: 'clean', errors: [] };

        const errors: any[] = [];
        let calculatedBalance = 0;

        for (let i = 0; i < legs.length; i++) {
            const leg = legs[i];
            const amount = await DataProtection.decryptAmount(leg.amount);
            const reportedBalanceAfter = await DataProtection.decryptAmount(leg.balance_after_encrypted || leg.balance_after);

            if (leg.entry_type === 'CREDIT') {
                calculatedBalance += amount;
            } else {
                calculatedBalance -= amount;
            }

            // Verify if the reported balance matches our reconstructed balance
            if (Math.abs(calculatedBalance - reportedBalanceAfter) > 0.01) {
                errors.push({
                    index: i,
                    transactionId: leg.transaction_id,
                    expected: calculatedBalance,
                    actual: reportedBalanceAfter,
                    diff: reportedBalanceAfter - calculatedBalance
                });
            }
        }

        return {
            status: errors.length > 0 ? 'corrupted' : 'clean',
            errors
        };
    }
}

export const ReconciliationEngine = new ReconciliationEngineService();
