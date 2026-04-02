import { getSupabase, getAdminSupabase } from '../supabaseClient.js';
import { TransactionService } from '../../ledger/transactionService.js';
import { UUID } from '../../services/utils.js';
import { DataVault } from '../security/encryption.js';
import { DataProtection } from '../security/DataProtection.js';
import { Audit } from '../security/audit.js';
import { Messaging } from '../features/MessagingService.js';

export class TreasuryService {

    /**
     * SWEEP ALL ORGANIZATIONS
     * Triggers auto-sweep for all organizations. Intended for background jobs.
     */
    public async sweepAllOrganizations(): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        try {
            // Find all unique organization IDs that have active corporate goals
            const { data: goals } = await sb.from('goals')
                .select('organization_id')
                .eq('is_corporate', true)
                .eq('status', 'ACTIVE');

            if (!goals || goals.length === 0) return;

            const orgIds = Array.from(new Set(goals.map(g => g.organization_id).filter(id => !!id)));

            for (const orgId of orgIds) {
                // We can push this to the WorkerNode or execute directly
                // Executing directly here since this might be called from a worker already
                await this.executeAutoSweep(orgId);
            }
        } catch (e: any) {
            console.error(`[Treasury] Global Auto-Sweep failed: ${e.message}`);
        }
    }

    /**
     * AUTO-SWEEPING ENGINE
     * Sweeps excess liquidity from operating vaults into Corporate Treasury Goals.
     */
    public async executeAutoSweep(organizationId: string): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        try {
            // 1. Find all corporate goals for this organization that have auto-sweep enabled in metadata
            const { data: goals } = await sb.from('goals')
                .select('*')
                .eq('organization_id', organizationId)
                .eq('is_corporate', true)
                .eq('status', 'ACTIVE');

            if (!goals || goals.length === 0) return;

            // Filter goals that have sweep_threshold defined
            const sweepGoals = goals.filter(g => g.metadata && g.metadata.auto_sweep === true && g.metadata.sweep_threshold > 0);
            if (sweepGoals.length === 0) return;

            // 2. Find the organization's primary operating vault
            // Assuming the organization has a primary admin user or a dedicated org vault
            // For now, let's find the operating vault of the ADMIN of this organization
            const { data: admins } = await sb.from('users')
                .select('id')
                .eq('organization_id', organizationId)
                .eq('org_role', 'ADMIN');

            if (!admins || admins.length === 0) return;

            const adminId = admins[0].id;

            const { data: operatingVault } = await sb.from('platform_vaults')
                .select('id, balance')
                .eq('user_id', adminId)
                .eq('vault_role', 'OPERATING')
                .single();

            if (!operatingVault) return;

            const txService = new TransactionService();
            const currentBalance = await txService.getLatestBalance(adminId, operatingVault.id);

            // 3. Execute Sweeps
            for (const goal of sweepGoals) {
                const threshold = Number(goal.metadata.sweep_threshold);
                
                if (currentBalance > threshold) {
                    const excess = currentBalance - threshold;
                    
                    // Cap the sweep to the remaining amount needed for the goal
                    const currentSaved = Number(goal.current) || 0;
                    const targetAmount = Number(goal.target) || 0;
                    const remainingNeeded = targetAmount - currentSaved;

                    if (remainingNeeded <= 0) continue; // Goal already met

                    const sweepAmount = Math.min(excess, remainingNeeded);

                    if (sweepAmount > 0) {
                        const txId = UUID.generate();
                        const legs = [
                            {
                                transactionId: txId,
                                walletId: operatingVault.id,
                                type: 'DEBIT' as 'DEBIT',
                                amount: sweepAmount,
                                currency: goal.currency,
                                description: `Auto-Sweep to Treasury: ${goal.name}`,
                                timestamp: new Date().toISOString()
                            },
                            {
                                transactionId: txId,
                                walletId: goal.id, // Assuming goal acts as a wallet or has a linked wallet
                                type: 'CREDIT' as 'CREDIT',
                                amount: sweepAmount,
                                currency: goal.currency,
                                description: `Inbound Auto-Sweep from Operating Vault`,
                                timestamp: new Date().toISOString()
                            }
                        ];

                        await txService.postTransactionWithLedger({
                            id: txId,
                            user_id: adminId,
                            amount: sweepAmount,
                            description: `Treasury Auto-Sweep: ${goal.name}`,
                            type: 'transfer',
                            status: 'completed',
                            walletId: operatingVault.id,
                            toWalletId: goal.id,
                            metadata: { is_auto_sweep: true, goal_id: goal.id }
                        }, legs);

                        // Update goal current
                        await sb.from('goals')
                            .update({ current: currentSaved + sweepAmount })
                            .eq('id', goal.id);

                        await Audit.log('FINANCIAL', adminId, 'TREASURY_AUTO_SWEEP', { goalId: goal.id, amount: sweepAmount });
                    }
                }
            }

        } catch (e: any) {
            console.error(`[Treasury] Auto-Sweep failed for org ${organizationId}: ${e.message}`);
        }
    }

    /**
     * MAKER-CHECKER APPROVAL ENGINE
     * Requests approval for a withdrawal from a Corporate Treasury Goal.
     */
    public async requestWithdrawal(userId: string, goalId: string, amount: number, destinationWalletId: string, reason: string): Promise<string> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("Database connection required");

        // 1. Verify Goal and User
        const { data: goal } = await sb.from('goals').select('*').eq('id', goalId).single();
        if (!goal || !goal.is_corporate) throw new Error("Invalid Corporate Goal");

        const { data: user } = await sb.from('users').select('organization_id, org_role').eq('id', userId).single();
        if (!user || user.organization_id !== goal.organization_id) throw new Error("Unauthorized");

        // 2. Create Pending Transaction
        const txId = UUID.generate();
        const txService = new TransactionService();
        
        // We do NOT post ledger legs yet. We just create a transaction record in 'held_for_review' state.
        const { error } = await sb.from('transactions').insert({
            id: txId,
            reference_id: `TREAS-${UUID.generateShortCode(8)}`,
            user_id: userId,
            amount: await DataProtection.encryptAmount(amount),
            description: await DataProtection.encryptDescription(`Treasury Withdrawal Request: ${reason}`),
            type: 'transfer',
            status: 'held_for_review',
            wallet_id: goalId,
            to_wallet_id: destinationWalletId,
            metadata: {
                is_treasury_withdrawal: true,
                goal_id: goalId,
                reason: reason,
                approvals_required: 2, // Example: Requires 2 approvals
                approvals_received: 0,
                approved_by: []
            }
        });

        if (error) throw new Error(`Failed to create withdrawal request: ${error.message}`);

        await Audit.log('SECURITY', userId, 'TREASURY_WITHDRAWAL_REQUESTED', { txId, goalId, amount });

        // Notify Finance/Admin users
        const { data: admins } = await sb.from('users')
            .select('id, language')
            .eq('organization_id', user.organization_id)
            .in('org_role', ['ADMIN', 'FINANCE']);
            
        if (admins) {
            for (const admin of admins) {
                if (admin.id !== userId) {
                    const language = admin.language || 'en';
                    const subject = language === 'sw' ? 'Ombi la Kutoa Fedha za Hazina' : 'Pending Treasury Withdrawal';
                    const body = language === 'sw' 
                        ? `Ombi jipya la kutoa fedha za hazina la ${amount} linahitaji idhini yako. Sababu: ${reason}` 
                        : `A new treasury withdrawal request for ${amount} requires your approval. Reason: ${reason}`;

                    await Messaging.dispatch(
                        admin.id,
                        'info',
                        subject,
                        body,
                        { 
                            sms: true,
                            email: true,
                            template: 'Treasury_Withdrawal_Request',
                            variables: {
                                amount: amount.toLocaleString(),
                                currency: 'TZS',
                                reason
                            }
                        }
                    );
                }
            }
        }

        return txId;
    }

    /**
     * APPROVE TREASURY WITHDRAWAL
     * Finance admins can approve pending withdrawals.
     */
    public async approveWithdrawal(adminId: string, txId: string): Promise<boolean> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("Database connection required");

        // 1. Verify Admin
        const { data: admin } = await sb.from('users').select('organization_id, org_role').eq('id', adminId).single();
        if (!admin || (admin.org_role !== 'ADMIN' && admin.org_role !== 'FINANCE')) {
            throw new Error("Unauthorized: Only Finance or Admin can approve");
        }

        // 2. Fetch Transaction
        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).single();
        if (!tx || tx.status !== 'held_for_review' || !tx.metadata?.is_treasury_withdrawal) {
            throw new Error("Invalid or already processed withdrawal request");
        }

        // Prevent self-approval if strict
        if (tx.user_id === adminId) {
            throw new Error("Maker-Checker Violation: Cannot approve your own request");
        }

        const metadata = tx.metadata;
        if (metadata.approved_by.includes(adminId)) {
            throw new Error("Already approved by this admin");
        }

        metadata.approved_by.push(adminId);
        metadata.approvals_received += 1;

        // 3. Check if fully approved
        if (metadata.approvals_received >= metadata.approvals_required) {
            // Execute the withdrawal
            const amount = await DataProtection.decryptAmount(tx.amount);
            const txService = new TransactionService();
            
            const legs = [
                {
                    transactionId: txId,
                    walletId: tx.wallet_id,
                    type: 'DEBIT' as 'DEBIT',
                    amount: amount,
                    currency: tx.currency,
                    description: `Approved Treasury Withdrawal`,
                    timestamp: new Date().toISOString()
                },
                {
                    transactionId: txId,
                    walletId: tx.to_wallet_id,
                    type: 'CREDIT' as 'CREDIT',
                    amount: amount,
                    currency: tx.currency,
                    description: `Inbound Treasury Funds`,
                    timestamp: new Date().toISOString()
                }
            ];

            await txService.addLedgerEntries(txId, legs);
            await txService.updateTransactionStatus(txId, 'completed', 'Fully Approved by Finance');

            // Update goal current
            const { data: goal } = await sb.from('goals').select('current').eq('id', tx.metadata.goal_id).single();
            if (goal) {
                await sb.from('goals')
                    .update({ current: Math.max(0, Number(goal.current) - amount) })
                    .eq('id', tx.metadata.goal_id);
            }

            await Audit.log('FINANCIAL', adminId, 'TREASURY_WITHDRAWAL_EXECUTED', { txId });
            
            // Notify the Maker
            const { data: makerUser } = await sb.from('users').select('language').eq('id', tx.user_id).maybeSingle();
            const makerLang = makerUser?.language || 'en';
            const subject = makerLang === 'sw' ? 'Utoaji Fedha za Hazina Umeidhinishwa' : 'Treasury Withdrawal Approved';
            const body = makerLang === 'sw' 
                ? `Ombi lako la kutoa fedha za hazina la ${amount} limeidhinishwa kikamilifu na fedha zimehamishiwa kwenye akaunti yako ya uendeshaji.` 
                : `Your treasury withdrawal request for ${amount} has been fully approved and the funds have been transferred to your operating wallet.`;

            await Messaging.dispatch(
                tx.user_id,
                'info',
                subject,
                body,
                { 
                    sms: true,
                    email: true,
                    template: 'Treasury_Withdrawal_Approved',
                    variables: {
                        amount: amount.toLocaleString(),
                        currency: tx.currency
                    }
                }
            );

            return true;
        } else {
            // Update metadata with new approval
            await sb.from('transactions').update({ metadata }).eq('id', txId);
            await Audit.log('SECURITY', adminId, 'TREASURY_WITHDRAWAL_APPROVED_PARTIAL', { txId });
            return false; // Still pending more approvals
        }
    }
    /**
     * GET PENDING APPROVALS
     * Retrieves all pending treasury withdrawals for a specific organization.
     */
    public async getPendingApprovals(organizationId: string): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];
        
        // Find all goals for this org
        const { data: goals } = await sb.from('goals').select('id').eq('organization_id', organizationId);
        if (!goals || goals.length === 0) return [];
        const goalIds = goals.map(g => g.id);

        // Find transactions held for review targeting these goals
        const { data: txs } = await sb.from('transactions')
            .select('*, users!transactions_user_id_fkey(full_name, email)')
            .eq('status', 'held_for_review')
            .in('wallet_id', goalIds);
            
        return txs || [];
    }

    /**
     * CONFIGURE AUTO SWEEP
     * Updates the auto-sweep settings for a corporate goal.
     */
    public async configureAutoSweep(goalId: string, enabled: boolean, threshold: number): Promise<boolean> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return false;
        
        const { data: goal } = await sb.from('goals').select('metadata').eq('id', goalId).single();
        if (!goal) return false;

        const metadata = goal.metadata || {};
        metadata.auto_sweep = enabled;
        metadata.sweep_threshold = threshold;

        const { error } = await sb.from('goals').update({ metadata }).eq('id', goalId);
        return !error;
    }
}

export const Treasury = new TreasuryService();
