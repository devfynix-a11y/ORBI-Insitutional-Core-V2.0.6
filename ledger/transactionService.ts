
import { Transaction, LedgerEntry, TransactionStatus, Wallet } from '../types.js';
import { getSupabase, getAdminSupabase } from '../services/supabaseClient.js';
import { DataVault, VaultError } from '../backend/security/encryption.js'; 
import { Audit } from '../backend/security/audit.js';
import { UUID } from '../services/utils.js';
import { RegulatoryService } from './regulatoryService.js';
import { Messaging } from '../backend/features/MessagingService.js';
import { SocketRegistry } from '../backend/infrastructure/SocketRegistry.js';
import { TransactionStateMachine } from '../backend/ledger/stateMachine.js';
import { RiskComplianceEngine } from '../backend/security/RiskComplianceEngine.js';
import { PerfMonitor } from '../backend/infrastructure/PerfMonitor.js';

/**
 * INSTITUTIONAL LEDGER SERVICE (V22.0 Titanium)
 * -------------------------------------------
 * The source of truth for the Sovereign Cluster.
 */
export class TransactionService {
    
    /**
     * CALCULATE BALANCE FROM LEDGER
     * Derives the current balance by summing all ledger entries for a wallet.
     * This is the ultimate source of truth for wallet balances.
     */
    public async calculateBalanceFromLedger(walletId: string): Promise<number> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return 0;

        try {
            const { data: legs, error } = await sb
                .from('financial_ledger')
                .select('amount, entry_type')
                .eq('wallet_id', walletId);

            if (error) throw error;
            if (!legs || legs.length === 0) return 0;

            let balance = 0;
            for (const leg of legs) {
                const amount = Number(await DataVault.decrypt(leg.amount));
                if (leg.entry_type === 'CREDIT') {
                    balance += amount;
                } else {
                    balance -= amount;
                }
            }

            return Math.round(balance * 10000) / 10000;
        } catch (e: any) {
            console.error(`[Ledger] Balance calculation failed for ${walletId}: ${e.message}`);
            return 0;
        }
    }

    public async getLatestBalance(userId: string, walletId: string | null): Promise<number> {
        if (!walletId) return 0;
        
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return 0;

        try {
            const ledgerBalance = await this.calculateBalanceFromLedger(walletId);

            // Compare cached balances vs ledger (source of truth)
            const { data: wallet } = await sb
                .from('wallets')
                .select('balance')
                .eq('id', walletId)
                .maybeSingle();
            if (wallet && wallet.balance !== null && wallet.balance !== undefined) {
                const cached = Number(wallet.balance) || 0;
                if (Math.abs(cached - ledgerBalance) > 0.01) {
                    throw new Error('INTERNAL_BALANCE_MISMATCH');
                }
            }

            const { data: vault } = await sb
                .from('platform_vaults')
                .select('balance')
                .eq('id', walletId)
                .maybeSingle();
            if (vault && vault.balance !== null && vault.balance !== undefined) {
                const cached = Number(vault.balance) || 0;
                if (Math.abs(cached - ledgerBalance) > 0.01) {
                    throw new Error('INTERNAL_BALANCE_MISMATCH');
                }
            }

            const { data: goal } = await sb
                .from('goals')
                .select('current')
                .eq('id', walletId)
                .maybeSingle();
            if (goal && goal.current !== null && goal.current !== undefined) {
                const cached = Number(await DataVault.decrypt(goal.current)) || 0;
                if (Math.abs(cached - ledgerBalance) > 0.01) {
                    throw new Error('INTERNAL_BALANCE_MISMATCH');
                }
            }

            return ledgerBalance;
        } catch (e) {
            console.error(`[Ledger] Failed to fetch latest balance for ${walletId}:`, e);
        }
        
        const ledgerBalance = await this.calculateBalanceFromLedger(walletId);
        if (ledgerBalance === null || ledgerBalance === undefined || isNaN(ledgerBalance)) {
            console.error(`[Ledger] Debug: getLatestBalance returned invalid balance: ${ledgerBalance} for wallet: ${walletId}`);
        }
        return ledgerBalance;
    }

    /**
     * BUDGET ENFORCEMENT ENGINE
     * Checks if a transaction exceeds a corporate hard budget.
     */
    public async enforceBudgetLimits(userId: string, categoryId: string, amount: number, txId: string, referenceId?: string): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb || !categoryId) return;

        try {
            const { data: category } = await sb.from('categories')
                .select('*')
                .eq('id', categoryId)
                .single();

            if (!category) return;

            const target = await this.resolveBudgetTarget(category);
            if (target <= 0) return;

            const startDate = this.resolveBudgetPeriodStart(category.period);

            const { data: txs } = await sb.from('transactions')
                .select('amount')
                .eq('category_id', categoryId)
                .gte('created_at', startDate.toISOString())
                .neq('status', 'failed')
                .neq('status', 'reversed');

            let totalSpent = 0;
            if (txs) {
                for (const tx of txs) {
                    totalSpent += Number(await DataVault.decrypt(tx.amount));
                }
            }

            const newTotal = totalSpent + amount;
            const isCorporate = category.is_corporate === true;
            const isHardLimit = isCorporate && category.hard_limit === true;
            const budgetCurrency = category.currency || 'TZS';

            if (newTotal > target) {
                if (isHardLimit) {
                    await sb.from('budget_alerts').insert({
                        category_id: categoryId,
                        user_id: userId,
                        organization_id: category.organization_id,
                        transaction_id: txId,
                        amount: amount,
                        alert_type: 'EXCEEDED_BLOCKED'
                    });
                    
                    this.notifyAdmins(category.organization_id, 'Budget Exceeded (Blocked)', `A transaction of ${amount} ${budgetCurrency} for ${category.name} was blocked because it exceeded the hard limit.`);
                    
                    throw new Error(`BUDGET_EXCEEDED: Transaction blocked. Enterprise hard limit of ${target} ${budgetCurrency} for ${category.name} exceeded.`);
                } else {
                    await sb.from('budget_alerts').insert({
                        category_id: categoryId,
                        user_id: userId,
                        organization_id: category.organization_id || null,
                        transaction_id: txId,
                        amount: amount,
                        alert_type: isCorporate ? 'EXCEEDED_WARNING' : 'PERSONAL_BUDGET_EXCEEDED'
                    });

                    if (isCorporate && category.organization_id) {
                        this.notifyAdmins(category.organization_id, 'Budget Exceeded (Warning)', `A transaction of ${amount} ${budgetCurrency} for ${category.name} exceeded the budget target.`);
                    }
                }
            } else if (newTotal >= target * 0.8 && totalSpent < target * 0.8) {
                await sb.from('budget_alerts').insert({
                    category_id: categoryId,
                    user_id: userId,
                    organization_id: category.organization_id || null,
                    transaction_id: txId,
                    amount: amount,
                    alert_type: isCorporate ? 'WARNING_80_PERCENT' : 'PERSONAL_WARNING_80_PERCENT'
                });
                
                if (isCorporate && category.organization_id) {
                    this.notifyAdmins(
                        category.organization_id, 
                        'Budget Warning (80%)', 
                        `Spending for ${category.name} has reached 80% of the budget target.`,
                        'Onyo la Bajeti (80%)',
                        `Matumizi ya ${category.name} yamefikia 80% ya lengo la bajeti.`
                    );
                }
            }
        } catch (e: any) {
            if (e.message.includes('BUDGET_EXCEEDED')) throw e;
            console.error(`[Ledger] Budget enforcement failed: ${e.message}`);
        }
    }

    private async notifyAdmins(orgId: string, subjectEn: string, bodyEn: string, subjectSw?: string, bodySw?: string) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;
        const { data: admins } = await sb.from('users')
            .select('id, language')
            .eq('organization_id', orgId)
            .in('org_role', ['ADMIN', 'FINANCE']);
            
        if (admins) {
            for (const admin of admins) {
                const language = admin.language || 'en';
                const subject = language === 'sw' && subjectSw ? subjectSw : subjectEn;
                const body = language === 'sw' && bodySw ? bodySw : bodyEn;
                await Messaging.dispatch(admin.id, 'info', subject, body, { sms: true });
            }
        }
    }

    private resolveBudgetPeriodStart(period?: string): Date {
        const now = new Date();
        if (period === 'QUARTERLY') {
            const quarter = Math.floor(now.getMonth() / 3);
            return new Date(now.getFullYear(), quarter * 3, 1);
        }
        if (period === 'ANNUAL') {
            return new Date(now.getFullYear(), 0, 1);
        }
        return new Date(now.getFullYear(), now.getMonth(), 1);
    }

    private async resolveBudgetTarget(category: any): Promise<number> {
        if (category?.target_amount !== undefined && category?.target_amount !== null) {
            const value = typeof category.target_amount === 'string'
                ? Number(await DataVault.decrypt(category.target_amount))
                : Number(category.target_amount);
            if (!isNaN(value) && value > 0) return value;
        }
        if (category?.budget !== undefined && category?.budget !== null) {
            const value = typeof category.budget === 'string'
                ? Number(await DataVault.decrypt(category.budget))
                : Number(category.budget);
            if (!isNaN(value) && value > 0) return value;
        }
        return 0;
    }

    private async emitFinancialEvent(eventType: string, aggregateId: string, payload: any, actor: string = 'system') {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        try {
            await sb.from('financial_events').insert({
                event_type: eventType,
                aggregate_id: aggregateId,
                payload,
                actor
            });
        } catch (e: any) {
            console.error(`[Ledger] Financial event emit failed for ${eventType}/${aggregateId}: ${e.message}`);
        }
    }

    private async buildBudgetSnapshot(categoryId: string): Promise<any | null> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return null;

        const { data: category } = await sb.from('categories')
            .select('*')
            .eq('id', categoryId)
            .maybeSingle();
        if (!category) return null;

        const target = await this.resolveBudgetTarget(category);
        if (target <= 0) return null;

        const startDate = this.resolveBudgetPeriodStart(category.period);
        const { data: txs } = await sb.from('transactions')
            .select('amount')
            .eq('category_id', categoryId)
            .gte('created_at', startDate.toISOString())
            .neq('status', 'failed')
            .neq('status', 'reversed');

        let spent = 0;
        if (txs) {
            for (const tx of txs) {
                spent += Number(await DataVault.decrypt(tx.amount));
            }
        }

        const remaining = Math.max(target - spent, 0);
        return {
            category_id: categoryId,
            category_name: category.name,
            is_corporate: category.is_corporate === true,
            target_amount: target,
            spent_amount: Math.round(spent * 10000) / 10000,
            remaining_amount: Math.round(remaining * 10000) / 10000,
            utilization_ratio: target > 0 ? Math.round((spent / target) * 10000) / 10000 : 0,
            period_start: startDate.toISOString(),
            period_type: category.period || 'MONTHLY'
        };
    }

    private async emitPurposeLifecycleEvents(txId: string, t: Partial<Transaction>, referenceId: string) {
        const amount = Number(t.amount || 0);
        const metadata = t.metadata || {};
        const categoryId = t.categoryId ? String(t.categoryId) : '';
        const goalId = metadata?.goal_id ? String(metadata.goal_id) : '';
        const movement = metadata?.movement ? String(metadata.movement).toLowerCase() : '';

        if (categoryId) {
            const snapshot = await this.buildBudgetSnapshot(categoryId);
            if (snapshot) {
                await this.emitFinancialEvent('BUDGET_BUCKET_UPDATED', categoryId, {
                    ...snapshot,
                    transaction_id: txId,
                    transaction_type: t.type || 'expense',
                    amount,
                    reference_id: referenceId
                });
            }
        }

        if (goalId && movement === 'allocate_to_goal') {
            await this.emitFinancialEvent('GOAL_FUNDS_LOCKED', goalId, {
                goal_id: goalId,
                transaction_id: txId,
                amount,
                reference_id: referenceId,
                state: 'SAVED_LOCKED',
                source_wallet_id: metadata?.source_wallet_id || t.walletId || null
            });
        }

        if (goalId && movement === 'withdraw_from_goal') {
            await this.emitFinancialEvent('GOAL_FUNDS_RELEASED', goalId, {
                goal_id: goalId,
                transaction_id: txId,
                amount,
                reference_id: referenceId,
                state: 'RELEASED',
                destination_wallet_id: metadata?.destination_wallet_id || t.toWalletId || null,
                security_verification: metadata?.security_verification || null
            });
        }
    }

    /**
     * POST TRANSACTION WITH ATOMIC LEDGER LEGS
     * Enforces double-entry consistency across all mapped vaults using a single DB transaction.
     */
    async postTransactionWithLedger(t: Partial<Transaction>, ledgerEntries: LedgerEntry[]) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("LEDGER_FAULT: Cloud connectivity required for atomic commits.");
        
        const txId = t.id ? String(t.id) : UUID.generate();
        const referenceId = t.referenceId || `REF-${UUID.generateShortCode(12)}`;

        // EXACTLY-ONCE PROTECTION: Check if reference_id already exists
        const { data: existingTx } = await sb.from('transactions')
            .select('id, status')
            .eq('reference_id', referenceId)
            .maybeSingle();

        if (existingTx) {
            console.warn(`[Ledger] IDEMPOTENCY_VIOLATION: Duplicate transaction attempt for reference: ${referenceId}. Existing ID: ${existingTx.id}, Status: ${existingTx.status}`);
            throw new Error(`IDEMPOTENCY_VIOLATION: Transaction with reference ${referenceId} already exists with status ${existingTx.status}`);
        }
        
        // 1. Encrypt PII Metadata
        const [encAmt, encDesc] = await Promise.all([
            DataVault.encrypt(t.amount || 0), 
            DataVault.encrypt(t.description || 'Sovereign Transaction')
        ]);

        // 2. Prepare Legs with balances (Parallelize balance fetching)
        const walletIds = Array.from(new Set((ledgerEntries || []).map(l => l.walletId).filter((id): id is string => !!id)));
        const initialBalances = await Promise.all(
            walletIds.map(async id => ({ id, balance: await this.getLatestBalance(t.user_id || 'system', id) }))
        );
        
        const balanceCache: Record<string, number> = {};
        initialBalances.forEach(b => balanceCache[b.id] = b.balance);

        const preparedLegs = [];
        const internalWalletIds = new Set<string>();
        if (walletIds.length > 0) {
            const [wallets, vaults, goals] = await Promise.all([
                sb.from('wallets').select('id').in('id', walletIds),
                sb.from('platform_vaults').select('id').in('id', walletIds),
                sb.from('goals').select('id').in('id', walletIds),
            ]);
            (wallets.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
            (vaults.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
            (goals.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
        }
        if (walletIds.length > 0 && internalWalletIds.size === 0) {
            throw new Error('INTERNAL_WALLET_REQUIRED: Ledger commits must involve ORBI internal wallets.');
        }
        for (const leg of ledgerEntries) {
            const walletId = leg.walletId;
            if (!walletId) continue;
            
            const current = balanceCache[walletId];
            const after = leg.type === 'CREDIT' ? (current + leg.amount) : (current - leg.amount);
            const finalAfter = Math.round(after * 10000) / 10000;

            if (finalAfter < 0 && internalWalletIds.has(String(walletId))) {
                throw new Error(`INSUFFICIENT_FUNDS: Wallet ${walletId} would go negative.`);
            }
            
            balanceCache[walletId] = finalAfter;

            const [eAmt, eAft] = await Promise.all([
                DataVault.encrypt(leg.amount), 
                DataVault.encrypt(finalAfter)
            ]);

            preparedLegs.push({
                wallet_id: walletId,
                entry_type: leg.type,
                amount: eAmt,
                balance_before: current,
                balance_after: finalAfter,
                balance_after_encrypted: eAft,
                description: leg.description
            });
        }

        const finalLegs = preparedLegs;

        // 3. Atomic Commit via V2 RPC
        const { error: rpcError } = await sb.rpc('post_transaction_v2', {
            p_tx_id: txId,
            p_user_id: t.user_id,
            p_wallet_id: t.walletId || null,
            p_to_wallet_id: t.toWalletId || null,
            p_amount: encAmt,
            p_description: encDesc,
            p_type: t.type || 'expense',
            p_status: t.status || 'completed',
            p_date: t.date || new Date().toISOString().split('T')[0],
            p_metadata: t.metadata || {},
            p_category_id: t.categoryId || null,
            p_legs: finalLegs,
            p_reference_id: referenceId
        });

        if (rpcError) {
            console.error(`[Ledger] Atomic commit failed for TX ${txId}:
                Error=${rpcError.message}
                Details=${JSON.stringify(rpcError)}
                Reference_ID=${referenceId}
                User_ID=${t.user_id}
            `);
            throw new Error(`LEDGER_COMMIT_FAULT: ${rpcError.message}`);
        }

        // 3.5 Log initial 'created' event
        await this.logTransactionEvent(txId, null, 'created', 'system', { initial_status: t.status || 'completed' });

        // 3.7 EVENT SOURCING: Emit to financial_events
        await this.emitFinancialEvent('TRANSACTION_POSTED', txId, {
            amount: t.amount,
            type: t.type,
            wallet_id: t.walletId,
            to_wallet_id: t.toWalletId,
            reference_id: referenceId
        });
        await this.emitPurposeLifecycleEvents(txId, t, referenceId);

        // 4. Trigger AML Risk Monitoring
        try {
            const txForMonitor: Transaction = {
                id: txId,
                user_id: t.user_id || 'system',
                amount: t.amount || 0,
                description: t.description || 'Sovereign Transaction',
                type: t.type || 'expense',
                status: t.status || 'completed',
                date: t.date || new Date().toISOString().split('T')[0],
                createdAt: t.createdAt || new Date().toISOString(),
                status_history: t.status_history || [],
                walletId: t.walletId || 'UNKNOWN',
                toWalletId: t.toWalletId,
                categoryId: t.categoryId,
                referenceId: t.referenceId,
                metadata: t.metadata
            };
            await RiskComplianceEngine.monitorTransaction(txForMonitor);
        } catch (e) {
            console.error(`[Ledger] AML Monitoring failed for ${txId}:`, e);
            // Non-blocking error
        }
    }

    /**
     * ADD LEDGER ENTRIES (APPEND-ONLY)
     * Adds new legs to an existing transaction and updates wallet balances.
     */
    async addLedgerEntries(txId: string, ledgerEntries: LedgerEntry[]) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("LEDGER_FAULT: Cloud connectivity required.");

        // 1. Prepare Legs with balances
        const preparedLegs = [];
        const internalWalletIds = new Set<string>();
        const walletIds = Array.from(new Set((ledgerEntries || []).map(l => l.walletId).filter((id): id is string => !!id)));
        if (walletIds.length > 0) {
            const [wallets, vaults, goals] = await Promise.all([
                sb.from('wallets').select('id').in('id', walletIds),
                sb.from('platform_vaults').select('id').in('id', walletIds),
                sb.from('goals').select('id').in('id', walletIds),
            ]);
            (wallets.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
            (vaults.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
            (goals.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
        }
        if (walletIds.length > 0 && internalWalletIds.size === 0) {
            throw new Error('INTERNAL_WALLET_REQUIRED: Ledger updates must involve ORBI internal wallets.');
        }
        const balanceCache: Record<string, number> = {};
        const finalBalances: Record<string, number> = {};

        for (const leg of ledgerEntries) {
            const walletId = leg.walletId;
            if (!walletId) continue;
            
            if (balanceCache[walletId] === undefined) {
                balanceCache[walletId] = await this.getLatestBalance('system', walletId);
            }
            
            const current = balanceCache[walletId];
            const after = leg.type === 'CREDIT' ? (current + leg.amount) : (current - leg.amount);
            const finalAfter = Math.round(after * 10000) / 10000;
            
            if (finalAfter === null || finalAfter === undefined || isNaN(finalAfter)) {
                console.error(`[Ledger] Debug: Settlement Fault - Invalid balance_after calculation. Wallet: ${walletId}, Current: ${current}, Amount: ${leg.amount}, Type: ${leg.type}, After: ${after}, FinalAfter: ${finalAfter}`);
            }

            if (finalAfter < 0 && internalWalletIds.has(String(walletId))) {
                throw new Error(`INSUFFICIENT_FUNDS: Wallet ${walletId} would go negative.`);
            }
            
            balanceCache[walletId] = finalAfter;
            finalBalances[walletId] = finalAfter;

            const [eAmt, eAft] = await Promise.all([
                DataVault.encrypt(leg.amount), 
                DataVault.encrypt(finalAfter)
            ]);

            preparedLegs.push({
                transaction_id: txId,
                wallet_id: walletId,
                entry_type: leg.type,
                amount: eAmt,
                balance_before: current,
                balance_after: finalAfter,
                balance_after_encrypted: eAft,
                description: leg.description,
                created_at: new Date().toISOString()
            });
        }

        // 2. Atomic Commit via RPC
        const { error: rpcError } = await sb.rpc('append_ledger_entries_v1', {
            p_tx_id: txId,
            p_legs: preparedLegs
        });

        if (rpcError) {
            console.error(`[Ledger] Append legs failed for TX ${txId}: ${rpcError.message}`);
            throw new Error(`LEDGER_APPEND_FAULT: ${rpcError.message}`);
        }
    }

    /**
     * VERIFY WALLET BALANCE
     * Compares the cached balance in the wallets table with the sum of ledger entries.
     * Triggers a reconciliation event if a mismatch is detected.
     */
    public async verifyWalletBalance(walletId: string): Promise<{ valid: boolean, drift: number }> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return { valid: false, drift: 0 };

        try {
            // 1. Get cached balance
            const { data: wallet } = await sb.from('wallets').select('balance').eq('id', walletId).single();
            const cachedBalance = Number(wallet?.balance || 0);

            // 2. Calculate from ledger
            const ledgerBalance = await this.calculateBalanceFromLedger(walletId);

            const drift = Math.round((cachedBalance - ledgerBalance) * 10000) / 10000;
            const isValid = Math.abs(drift) < 0.0001;

            if (!isValid) {
                console.warn(`[Ledger] BALANCE_DRIFT_DETECTED for ${walletId}: Cached=${cachedBalance}, Ledger=${ledgerBalance}, Drift=${drift}`);
                
                // Log reconciliation event
                await sb.from('reconciliation_reports').insert({
                    type: 'WALLET_DRIFT',
                    expected_balance: ledgerBalance,
                    actual_balance: cachedBalance,
                    difference: drift,
                    status: 'MISMATCH',
                    metadata: { wallet_id: walletId }
                });
            }

            return { valid: isValid, drift };
        } catch (e: any) {
            console.error(`[Ledger] Balance verification failed for ${walletId}: ${e.message}`);
            return { valid: false, drift: 0 };
        }
    }

    public async updateTransactionStatus(id: string, status: TransactionStatus, notes?: string) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        // 1. Fetch transaction to check current status and get user_id
        const { data: tx } = await sb.from('transactions').select('*').eq('id', id).single();
        if (!tx) return;

        const oldStatus = tx.status as TransactionStatus;

        // 2. Validate transition
        if (!TransactionStateMachine.isValidTransition(oldStatus, status)) {
            console.warn(`[Ledger] Invalid state transition attempted: ${oldStatus} -> ${status} for TX ${id}`);
            return;
        }

        // 3. Update the status in the database
        await sb.from('transactions').update({ 
            status, 
            status_notes: notes 
        }).eq('id', id);

        // 4. Log the event for audit trail
        await this.logTransactionEvent(id, oldStatus, status, 'system', { notes });

        // 5. Notify the user via the Nexus Stream (WebSocket)
        SocketRegistry.notifyTransactionUpdate(tx.user_id, { ...tx, status, status_notes: notes });
        
        // If it's a settlement confirmation, also notify about balance update
        if (status === 'completed' || status === 'settled') {
            const balance = await this.calculateBalanceFromLedger(tx.wallet_id);
            SocketRegistry.notifyBalanceUpdate(tx.user_id, tx.wallet_id, balance);

            if (oldStatus !== 'completed' && oldStatus !== 'settled') {
                try {
                    const { BankingEngine } = await import('../backend/ledger/transactionEngine.js');
                    await BankingEngine.sendTransferNotifications(id, { ...tx, status, status_notes: notes });
                } catch (e: any) {
                    console.error(`[Ledger] Participant notification dispatch failed for ${id}: ${e.message}`);
                }
            }
        }

        try {
            const { ServiceActorOps } = await import('../backend/features/ServiceActorOps.js');
            await ServiceActorOps.handleTransactionStatusChange(id, status);
        } catch (e: any) {
            console.error(`[Ledger] Service actor post-status sync failed for ${id}: ${e.message}`);
        }
    }

    /**
     * LOG TRANSACTION EVENT
     * Records a state transition in the transaction_events table.
     */
    public async logTransactionEvent(transactionId: string, oldState: string | null, newState: string, actor: string = 'system', metadata: any = {}) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        try {
            await sb.from('transaction_events').insert({
                transaction_id: transactionId,
                old_state: oldState,
                new_state: newState,
                actor,
                metadata
            });
        } catch (e: any) {
            console.error(`[Ledger] Failed to log transaction event for ${transactionId}: ${e.message}`);
        }
    }

    public async getLatestTransactions(userId: string, limit: number = 50, offset: number = 0): Promise<any[]> {
        // Use Admin Client to bypass RLS policies for aggregated views (Incoming + Outgoing)
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) {
            console.error("[Ledger] API Connection required for transaction retrieval.");
            return [];
        }

        return await PerfMonitor.track(`Ledger.getLatestTransactions:${userId}:${limit}:${offset}`, async () => {
            try {
            // 1. Get User's Wallet IDs (to find incoming transactions)
            const [{ data: wallets }, { data: vaults }] = await Promise.all([
                sb.from('wallets').select('id').eq('user_id', userId),
                sb.from('platform_vaults').select('id').eq('user_id', userId),
            ]);
            
            const walletIds = [
                ...(wallets?.map(w => w.id) || []),
                ...(vaults?.map(v => v.id) || [])
            ];

            console.log(`[Ledger] Fetching transactions for user ${userId}. Wallets: ${walletIds.length}`);

            // 2. Query Transactions (Outgoing OR Incoming)
            let query = sb
                .from('transactions')
                .select('id, reference_id, user_id, amount, currency, description, type, status, created_at, wallet_id, to_wallet_id, metadata, category_id')
                .order('created_at', { ascending: false })
                .range(offset, offset + limit - 1);

            if (walletIds.length > 0) {
                // OR syntax: user_id.eq.userId,to_wallet_id.in.(ids)
                query = query.or(`user_id.eq.${userId},to_wallet_id.in.(${walletIds.join(',')})`);
            } else {
                query = query.eq('user_id', userId);
            }

            const { data, error } = await query;

            if (error) {
                console.error(`[Ledger] Query Error: ${error.message}`);
                throw error;
            }
            
            if (!data) return [];

            const translated = await DataVault.translate(data);

            const { data: movementRows } = await sb
                .from('external_fund_movements')
                .select('id, direction, status, gross_amount, currency, description, created_at, source_wallet_id, target_wallet_id, provider_id, external_reference, metadata')
                .eq('user_id', userId)
                .order('created_at', { ascending: false })
                .range(offset, offset + limit - 1);
            
            // 3. ENRICHMENT: Fetch Wallet Names and User Details for both sides
            const allWalletIds = new Set<string>();
            const allUserIds = new Set<string>();

            translated.forEach((tx: any) => {
                if (tx.walletId) allWalletIds.add(tx.walletId);
                if (tx.toWalletId) allWalletIds.add(tx.toWalletId);
                if (tx.user_id) allUserIds.add(tx.user_id);
            });
            (movementRows || []).forEach((mv: any) => {
                if (mv.source_wallet_id) allWalletIds.add(String(mv.source_wallet_id));
                if (mv.target_wallet_id) allWalletIds.add(String(mv.target_wallet_id));
            });

            const walletIdList = Array.from(allWalletIds);
            const { data: walletNames } = walletIdList.length
                ? await sb.from('wallets').select('id, name, user_id').in('id', walletIdList)
                : { data: [] as any[] };
            const { data: vaultNames } = walletIdList.length
                ? await sb.from('platform_vaults').select('id, name, user_id').in('id', walletIdList)
                : { data: [] as any[] };
            const { data: goalNames } = walletIdList.length
                ? await sb.from('goals').select('id, name, user_id').in('id', walletIdList)
                : { data: [] as any[] };
            
            const walletMap: Record<string, any> = {};
            [...(walletNames || []), ...(vaultNames || []), ...(goalNames || [])].forEach(w => {
                walletMap[w.id] = w;
                if (w.user_id) allUserIds.add(w.user_id);
            });

            const userIdList = Array.from(allUserIds);
            const { data: userDetails } = userIdList.length
                ? await sb.from('users').select('id, full_name, customer_id').in('id', userIdList)
                : { data: [] as any[] };
            const userMap: Record<string, any> = {};
            (userDetails || []).forEach(u => userMap[u.id] = u);

            const movementItems = (movementRows || []).map((mv: any) => {
                const direction = String(mv.direction || '').toUpperCase();
                const movementStatusRaw = String(mv.status || '').toLowerCase();
                const movementStatus =
                    ['initiated', 'processing', 'completed', 'failed'].includes(movementStatusRaw)
                        ? movementStatusRaw
                        : movementStatusRaw === 'pending'
                          ? 'initiated'
                          : movementStatusRaw;
                const txDirection =
                    direction === 'EXTERNAL_TO_INTERNAL'
                        ? 'CREDIT'
                        : direction === 'INTERNAL_TO_EXTERNAL'
                          ? 'DEBIT'
                          : 'DEBIT';
                const sourceWallet = walletMap[String(mv.source_wallet_id || '')];
                const targetWallet = walletMap[String(mv.target_wallet_id || '')];
                return {
                    id: mv.external_reference || mv.id,
                    internalId: mv.id,
                    referenceId: mv.external_reference || mv.id,
                    user_id: userId,
                    amount: Number(mv.gross_amount || 0),
                    currency: mv.currency,
                    description: mv.description || 'External transfer',
                    type:
                        direction === 'INTERNAL_TO_EXTERNAL'
                            ? 'withdrawal'
                            : direction === 'EXTERNAL_TO_INTERNAL'
                              ? 'deposit'
                              : 'external_transfer',
                    status: movementStatus,
                    created_at: mv.created_at,
                    walletId: mv.source_wallet_id,
                    toWalletId: mv.target_wallet_id,
                    metadata: {
                        ...(mv.metadata || {}),
                        external_movement_id: mv.id,
                        external_reference: mv.external_reference,
                        provider_id: mv.provider_id,
                        settlement_path: 'EXTERNAL_ROUTING',
                    },
                    direction: txDirection,
                    sourceWalletName: sourceWallet?.name || 'External Source',
                    targetWalletName: targetWallet?.name || 'External Destination',
                    counterparty: {
                        label: txDirection === 'DEBIT' ? 'To' : 'From',
                        name: mv.provider_id || 'External',
                    },
                };
            });

            // 4. MAP TO TWO-SIDED VIEW
            const ledgerItems = translated.map((tx: any) => {
                const isSender = tx.user_id === userId;
                const sourceWallet = walletMap[tx.walletId];
                const targetWallet = walletMap[tx.toWalletId];
                
                const senderUser = userMap[tx.user_id];
                const receiverUserId = targetWallet?.user_id || tx.metadata?.recipient_snapshot?.id;
                const receiverUser = userMap[receiverUserId];

                const direction = isSender ? 'DEBIT' : 'CREDIT';
                const statusRaw = String(tx.status || '').toLowerCase();
                const normalizedStatus =
                    statusRaw === 'processing'
                        ? 'processing'
                        : statusRaw === 'failed' || statusRaw === 'reversed' || statusRaw === 'refunded' || statusRaw === 'cancelled'
                          ? 'failed'
                          : statusRaw === 'created' || statusRaw === 'pending' || statusRaw === 'authorized'
                            ? 'initiated'
                            : 'completed';
                
                return {
                    ...tx,
                    id: tx.reference_id || tx.id, // Overwrite ID with reference_id for frontend
                    internalId: tx.id, // Keep original UUID as internalId
                    referenceId: tx.reference_id || tx.id,
                    direction,
                    status: normalizedStatus,
                    sourceWalletName: sourceWallet?.name || 'Orbi Vault',
                    targetWalletName: targetWallet?.name || 'External Destination',
                    sender: {
                        id: tx.user_id,
                        name: senderUser?.full_name || 'System',
                        customerId: senderUser?.customer_id || 'N/A'
                    },
                    receiver: {
                        id: receiverUserId || 'N/A',
                        name: receiverUser?.full_name || tx.metadata?.recipient_snapshot?.name || 'External Recipient',
                        customerId: receiverUser?.customer_id || 'N/A'
                    },
                    // Generic "Counterparty" for simplified UI display
                    counterparty: isSender ? {
                        label: 'To',
                        name: receiverUser?.full_name || tx.metadata?.recipient_snapshot?.name || 'External Recipient',
                        id: receiverUser?.customer_id || 'N/A'
                    } : {
                        label: 'From',
                        name: senderUser?.full_name || 'System',
                        id: senderUser?.customer_id || 'N/A'
                    }
                };
            });
            const combined = [...ledgerItems, ...movementItems];
            combined.sort((a: any, b: any) => {
                const aTime = new Date(a.created_at || a.createdAt || 0).getTime();
                const bTime = new Date(b.created_at || b.createdAt || 0).getTime();
                return bTime - aTime;
            });
            return combined;
            } catch (e: any) {
                console.error(`[Ledger] Forensic fetch failed: ${e.message}`);
                return [];
            }
        });
    }

    /**
     * FORENSIC / AUDIT FETCH
     * Retrieves all transactions across the platform for staff/auditors.
     */
    public async getAllTransactions(limit: number = 100, offset: number = 0): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) {
            console.error("[Ledger] API Connection required for global transaction retrieval.");
            return [];
        }

        return await PerfMonitor.track(`Ledger.getAllTransactions:${limit}:${offset}`, async () => {
            try {
                const { data, error } = await sb
                    .from('transactions')
                    .select('id, reference_id, user_id, amount, currency, description, type, status, created_at, wallet_id, to_wallet_id, metadata, category_id')
                    .order('created_at', { ascending: false })
                    .range(offset, offset + limit - 1);

                if (error) throw error;
                if (!data) return [];

                const translated = await DataVault.translate(data);

            // Enrichment for Global View
            const allWalletIds = new Set<string>();
            const allUserIds = new Set<string>();

            translated.forEach((tx: any) => {
                if (tx.walletId) allWalletIds.add(tx.walletId);
                if (tx.toWalletId) allWalletIds.add(tx.toWalletId);
                if (tx.user_id) allUserIds.add(tx.user_id);
            });

                const walletIdList = Array.from(allWalletIds);
                const { data: walletNames } = walletIdList.length
                    ? await sb.from('wallets').select('id, name, user_id').in('id', walletIdList)
                    : { data: [] as any[] };
                const { data: vaultNames } = walletIdList.length
                    ? await sb.from('platform_vaults').select('id, name, user_id').in('id', walletIdList)
                    : { data: [] as any[] };
            
            const walletMap: Record<string, any> = {};
            [...(walletNames || []), ...(vaultNames || [])].forEach(w => {
                walletMap[w.id] = w;
                if (w.user_id) allUserIds.add(w.user_id);
            });

                const userIdList = Array.from(allUserIds);
                const { data: userDetails } = userIdList.length
                    ? await sb.from('users').select('id, full_name, customer_id').in('id', userIdList)
                    : { data: [] as any[] };
            const userMap: Record<string, any> = {};
            (userDetails || []).forEach(u => userMap[u.id] = u);

                return translated.map((tx: any) => {
                const sourceWallet = walletMap[tx.walletId];
                const targetWallet = walletMap[tx.toWalletId];
                const senderUser = userMap[tx.user_id];
                const receiverUserId = targetWallet?.user_id || tx.metadata?.recipient_snapshot?.id;
                const receiverUser = userMap[receiverUserId];

                return {
                    ...tx,
                    id: tx.reference_id || tx.id, // Overwrite ID with reference_id for frontend
                    internalId: tx.id, // Keep original UUID as internalId
                    referenceId: tx.reference_id || tx.id,
                    sourceWalletName: sourceWallet?.name || 'Orbi Vault',
                    targetWalletName: targetWallet?.name || 'External Destination',
                    sender: {
                        id: tx.user_id,
                        name: senderUser?.full_name || 'System',
                        customerId: senderUser?.customer_id || 'N/A'
                    },
                    receiver: {
                        id: receiverUserId || 'N/A',
                        name: receiverUser?.full_name || tx.metadata?.recipient_snapshot?.name || 'External Recipient',
                        customerId: receiverUser?.customer_id || 'N/A'
                    }
                };
                });
            } catch (e: any) {
                console.error(`[Ledger] Global Forensic fetch failed: ${e.message}`);
                return [];
            }
        });
    }

    /**
     * LEDGER FORENSICS
     * Retrieves all ledger legs for a specific transaction.
     */
    public async getLedgerEntries(transactionId: string): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];

        try {
            const { data, error } = await sb
                .from('financial_ledger')
                .select('*')
                .eq('transaction_id', transactionId);

            if (error) throw error;
            
            // Decrypt amounts and balances for forensic view
            return await Promise.all((data || []).map(async (leg: any) => {
                const amount = await DataVault.decrypt(leg.amount);
                const balanceAfter = await DataVault.decrypt(leg.balance_after_encrypted || leg.balance_after);
                
                return {
                    ...leg,
                    amount: (amount === VaultError.INTEGRITY_FAIL || amount === VaultError.HEALING_REQUIRED) ? 0 : Number(amount),
                    balance_after: (balanceAfter === VaultError.INTEGRITY_FAIL || balanceAfter === VaultError.HEALING_REQUIRED) ? 0 : Number(balanceAfter)
                };
            }));
        } catch (e: any) {
            console.error(`[Ledger] Forensic leg fetch failed: ${e.message}`);
            return [];
        }
    }

    /**
     * GET DAILY NET MOVEMENTS
     * Aggregates net asset movements (CREDIT - DEBIT) per day, optionally grouped by category.
     */
    public async getDailyNetMovements(startDate: string, endDate: string): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];

        try {
            const { data, error } = await sb
                .from('financial_ledger')
                .select(`
                    amount,
                    entry_type,
                    created_at,
                    transactions (
                        category_id
                    )
                `)
                .gte('created_at', startDate)
                .lte('created_at', endDate);

            if (error) throw error;

            const movements: Record<string, Record<string, number>> = {};

            for (const leg of (data || [])) {
                const amount = Number(await DataVault.decrypt(leg.amount));
                const date = leg.created_at.split('T')[0];
                const categoryId = leg.transactions?.[0]?.category_id || 'uncategorized';

                if (!movements[date]) movements[date] = {};
                if (!movements[date][categoryId]) movements[date][categoryId] = 0;

                if (leg.entry_type === 'CREDIT') {
                    movements[date][categoryId] += amount;
                } else {
                    movements[date][categoryId] -= amount;
                }
            }

            return Object.entries(movements).map(([date, categories]) => ({
                date,
                categories
            }));
        } catch (e: any) {
            console.error(`[Ledger] Daily movements failed: ${e.message}`);
            return [];
        }
    }

    /**
     * GET AGGREGATED WALLET BALANCES
     * Aggregates total balances for wallets with specific names (e.g., 'Orbi', 'PaySafe').
     */
    public async getAggregatedWalletBalances(walletNames: string[]): Promise<Record<string, number>> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return {};

        try {
            const { data, error } = await sb
                .from('wallets')
                .select('name, balance')
                .in('name', walletNames);

            if (error) throw error;

            const aggregation: Record<string, number> = {};
            walletNames.forEach(name => aggregation[name] = 0);

            (data || []).forEach(wallet => {
                if (aggregation[wallet.name] !== undefined) {
                    aggregation[wallet.name] += Number(wallet.balance) || 0;
                }
            });

            return aggregation;
        } catch (e: any) {
            console.error(`[Ledger] Aggregation failed: ${e.message}`);
            return {};
        }
    }

    /**
     * GET FEE TRANSACTIONS
     * Retrieves all ledger entries associated with fee collector wallets.
     */
    public async getWalletHistory(walletId: string, limit: number = 50, offset: number = 0): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];

        try {
            const { data, error } = await sb
                .from('financial_ledger')
                .select('*, transactions(*)')
                .eq('wallet_id', walletId)
                .order('created_at', { ascending: false })
                .range(offset, offset + limit - 1);

            if (error) throw error;
            if (!data) return [];

            return await Promise.all(data.map(async (leg: any) => {
                const amount = await DataVault.decrypt(leg.amount);
                const balanceAfter = await DataVault.decrypt(leg.balance_after_encrypted || leg.balance_after);
                
                return {
                    ...leg,
                    amount: Number(amount),
                    balance_after: Number(balanceAfter),
                    transaction: leg.transactions
                };
            }));
        } catch (e: any) {
            console.error(`[Ledger] Wallet history fetch failed for ${walletId}: ${e.message}`);
            return [];
        }
    }

    /**
     * RECONCILE ALL WALLETS
     * Runs a full integrity check across all wallets in the system.
     */
    public async reconcileAllWallets(): Promise<{ total: number, valid: number, invalid: number }> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return { total: 0, valid: 0, invalid: 0 };

        const { data: wallets } = await sb.from('wallets').select('id');
        const { data: vaults } = await sb.from('platform_vaults').select('id');

        const allIds = [...(wallets?.map(w => w.id) || []), ...(vaults?.map(v => v.id) || [])];
        
        let valid = 0;
        let invalid = 0;

        for (const id of allIds) {
            const result = await this.verifyWalletBalance(id);
            if (result.valid) valid++;
            else invalid++;
        }

        return { total: allIds.length, valid, invalid };
    }

    /**
     * FIX WALLET BALANCE
     * Forces the cached balance to match the ledger sum.
     * WARNING: Use only after manual audit.
     */
    public async fixWalletBalance(walletId: string, actorId: string): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("VAULT_OFFLINE");

        const ledgerBalance = await this.calculateBalanceFromLedger(walletId);
        const encryptedBalance = await DataVault.encrypt(ledgerBalance);

        await sb.rpc('update_wallet_balance', {
            target_wallet_id: walletId,
            new_balance: ledgerBalance,
            new_encrypted: encryptedBalance
        });

        Audit.log('SECURITY', actorId, 'WALLET_BALANCE_FIXED', { walletId, newBalance: ledgerBalance });
    }

    public async getSystemBalance(): Promise<{ total: number, breakdown: Record<string, number> }> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return { total: 0, breakdown: {} };

        const { data: vaults } = await sb.from('platform_vaults').select('vault_role, balance');
        
        let total = 0;
        const breakdown: Record<string, number> = {};

        if (vaults) {
            vaults.forEach(v => {
                const bal = Number(v.balance || 0);
                total += bal;
                breakdown[v.vault_role] = (breakdown[v.vault_role] || 0) + bal;
            });
        }

        return { total, breakdown };
    }

    /**
     * GET AUDIT LOG
     * Retrieves security and financial audit trails for a specific entity.
     */
    public async getAuditLog(entityId: string, limit: number = 100): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];

        const { data } = await sb
            .from('audit_trail')
            .select('*')
            .or(`actor_id.eq.${entityId},metadata->>target_id.eq.${entityId}`)
            .order('timestamp', { ascending: false })
            .limit(limit);

        return data || [];
    }

    public async getFeeTransactions(feeType?: string): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];

        try {
            // 1. Get all fee collector wallet IDs
            let query = sb.from('fee_collector_wallets').select('fee_type, vault_id');
            if (feeType) {
                query = query.eq('fee_type', feeType);
            }
            const { data: feeWallets, error: walletError } = await query;
            if (walletError || !feeWallets) return [];
            
            const targetVaultIds = (feeWallets || []).map(w => w.vault_id);

            // 2. Query financial_ledger for these wallet IDs
            const { data, error } = await sb
                .from('financial_ledger')
                .select('*, transactions(*)')
                .in('wallet_id', targetVaultIds)
                .order('created_at', { ascending: false });
            
            if (error) throw error;
            
            // 3. Decrypt and return
            return await Promise.all((data || []).map(async (leg: any) => ({
                ...leg,
                amount: Number(await DataVault.decrypt(leg.amount)),
                balance_after: Number(await DataVault.decrypt(leg.balance_after_encrypted || leg.balance_after))
            })));
        } catch (e: any) {
            console.error(`[Ledger] Fee transaction fetch failed: ${e.message}`);
            return [];
        }
    }

    public async reverseTransaction(txId: string, actorId: string): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("VAULT_OFFLINE");

        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).single();
        const { data: legs } = await sb.from('financial_ledger').select('*').eq('transaction_id', txId);

        if (!tx || !legs) throw new Error("FORENSIC_VOID: Transaction history not found.");

        const reversalTxId = UUID.generate();
        const reversalLegs: LedgerEntry[] = await Promise.all((legs || []).map(async (leg: any) => {
            const amount = Number(await DataVault.decrypt(leg.amount));
            return {
                transactionId: reversalTxId,
                walletId: leg.wallet_id,
                type: leg.entry_type === 'CREDIT' ? 'DEBIT' : 'CREDIT',
                amount,
                currency: leg.currency || tx.currency || 'TZS',
                description: `FORENSIC_REVERSAL: Ref ${txId.substring(0,8)}`,
                timestamp: new Date().toISOString()
            };
        }));

        await this.postTransactionWithLedger({
            id: reversalTxId,
            user_id: tx.user_id,
            amount: Number(await DataVault.decrypt(tx.amount)),
            description: `Auto-Reversal of ${txId.substring(0,8)}`,
            type: 'transfer',
            status: 'completed'
        }, reversalLegs);

        await this.updateTransactionStatus(txId, 'reversed', `Authorized by forensic agent: ${actorId}`);
    }

    public async lockTransactionForReview(
        txId: string,
        actorId: string,
        options: {
            actorRole: 'USER' | 'STAFF' | 'SYSTEM';
            reason: string;
            requestReverse?: boolean;
            userLock?: boolean;
            reviewWindowHours?: number;
        }
    ): Promise<any> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('VAULT_OFFLINE');

        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).single();
        if (!tx) throw new Error('TRANSACTION_NOT_FOUND');
        if (['reversed', 'failed', 'refunded', 'cancelled'].includes(String(tx.status || '').toLowerCase())) {
            throw new Error('TRANSACTION_NOT_REVERSIBLE');
        }

        if (options.actorRole === 'USER') {
            if (tx.user_id !== actorId) throw new Error('ACCESS_DENIED');
            if (String(tx.type || '').toLowerCase() !== 'transfer') {
                throw new Error('USER_LOCK_TRANSFER_ONLY');
            }
            const ageMs = Date.now() - new Date(tx.created_at || tx.date || Date.now()).getTime();
            if (ageMs > 60 * 60 * 1000) {
                throw new Error('USER_LOCK_WINDOW_EXPIRED');
            }
        }

        const lockAt = new Date().toISOString();
        const reviewWindowHours = Math.max(1, Number(options.reviewWindowHours || 24));
        const autoReverseAt = new Date(Date.now() + reviewWindowHours * 60 * 60 * 1000).toISOString();
        const metadata = {
            ...(tx.metadata || {}),
            transaction_lock: {
                locked: true,
                lock_type: options.userLock ? 'USER_TRANSFER_RECALL' : 'ADMIN_REVIEW_LOCK',
                locked_by: actorId,
                locked_role: options.actorRole,
                previous_status: tx.status,
                locked_at: lockAt,
                reason: options.reason,
                request_reverse: options.requestReverse === true,
                auto_reverse_after_hours: reviewWindowHours,
                auto_reverse_at: autoReverseAt,
                audit_status: 'PENDING',
            },
            manual_review: true,
            issue_reported_at: lockAt,
            issue_reason: options.reason,
        };

        const currentStatus = String(tx.status || '').toLowerCase();
        const nextStatus = currentStatus === 'held_for_review' ? 'held_for_review' : 'held_for_review';
        if (currentStatus !== 'held_for_review') {
            await this.updateTransactionStatus(txId, 'held_for_review', options.reason);
        }

        const { data: updated, error } = await sb
            .from('transactions')
            .update({
                status: nextStatus,
                status_notes: options.reason,
                metadata,
                updated_at: new Date().toISOString(),
            })
            .eq('id', txId)
            .select('*')
            .single();
        if (error) throw error;

        await this.logTransactionEvent(txId, tx.status, 'held_for_review', actorId, {
            reason: options.reason,
            actor_role: options.actorRole,
            request_reverse: options.requestReverse === true,
            user_lock: options.userLock === true,
            auto_reverse_at: autoReverseAt,
        });

        await this.notifyTransactionIssueStakeholders(updated || tx, {
            issueType: options.userLock ? 'USER_TRANSFER_RECALL_REQUESTED' : 'TRANSACTION_LOCKED_FOR_REVIEW',
            reason: options.reason,
            actorId,
            actorRole: options.actorRole,
            autoReverseAt,
        });

        return updated || { ...tx, status: 'held_for_review', metadata };
    }

    public async recordAuditDecision(
        txId: string,
        actorId: string,
        passed: boolean,
        notes: string,
        actorRole: 'STAFF' | 'SYSTEM' = 'STAFF'
    ): Promise<any> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('VAULT_OFFLINE');

        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).single();
        if (!tx) throw new Error('TRANSACTION_NOT_FOUND');
        if (String(tx.status || '').toLowerCase() !== 'held_for_review') {
            throw new Error('TRANSACTION_NOT_UNDER_REVIEW');
        }

        const metadata = {
            ...(tx.metadata || {}),
            transaction_lock: {
                ...(tx.metadata?.transaction_lock || {}),
                audit_status: passed ? 'PASSED' : 'FAILED',
                audit_passed: passed,
                audited_by: actorId,
                audited_by_role: actorRole,
                audited_at: new Date().toISOString(),
                audit_notes: notes,
            },
        };

        const { data: updated, error } = await sb
            .from('transactions')
            .update({
                metadata,
                status_notes: notes,
                updated_at: new Date().toISOString(),
            })
            .eq('id', txId)
            .select('*')
            .single();
        if (error) throw error;

        await this.logTransactionEvent(txId, tx.status, tx.status, actorId, {
            audit_status: passed ? 'PASSED' : 'FAILED',
            audit_notes: notes,
            actor_role: actorRole,
        });

        await this.notifyTransactionIssueStakeholders(updated || tx, {
            issueType: passed ? 'TRANSACTION_AUDIT_PASSED' : 'TRANSACTION_AUDIT_FAILED',
            reason: notes,
            actorId,
            actorRole,
            autoReverseAt: metadata.transaction_lock?.auto_reverse_at,
        });

        return updated || { ...tx, metadata };
    }

    public async approveReviewedTransaction(txId: string, actorId: string, notes: string): Promise<any> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('VAULT_OFFLINE');

        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).single();
        if (!tx) throw new Error('TRANSACTION_NOT_FOUND');
        if (String(tx.status || '').toLowerCase() !== 'held_for_review') {
            throw new Error('TRANSACTION_NOT_UNDER_REVIEW');
        }

        const auditStatus = String(tx.metadata?.transaction_lock?.audit_status || '').toUpperCase();
        if (auditStatus !== 'PASSED') {
            throw new Error('AUDIT_PASS_REQUIRED');
        }

        const previousStatus = String(tx.metadata?.transaction_lock?.previous_status || '').toLowerCase();
        const nextStatus: TransactionStatus =
            previousStatus === 'pending' ? 'pending'
            : previousStatus === 'authorized' ? 'authorized'
            : 'completed';

        const metadata = {
            ...(tx.metadata || {}),
            transaction_lock: {
                ...(tx.metadata?.transaction_lock || {}),
                locked: false,
                resolved_by: actorId,
                resolved_at: new Date().toISOString(),
                resolution: 'APPROVED',
                resolution_notes: notes,
            },
            manual_review: false,
        };

        if (previousStatus === 'processing' && String(tx.type || '').toLowerCase() === 'transfer') {
            try {
                const { BankingEngine } = await import('../backend/ledger/transactionEngine.js');
                await BankingEngine.completeSettlement(txId, tx);
            } catch (e: any) {
                throw new Error(`APPROVAL_SETTLEMENT_FAILED: ${e.message}`);
            }
        } else {
            await this.updateTransactionStatus(txId, nextStatus, notes);
        }

        const { data: updated, error } = await sb
            .from('transactions')
            .update({
                metadata,
                updated_at: new Date().toISOString(),
                status_notes: notes,
            })
            .eq('id', txId)
            .select('*')
            .single();
        if (error) throw error;

        await this.logTransactionEvent(txId, 'held_for_review', updated?.status || nextStatus, actorId, {
            approval_notes: notes,
            approved_by: actorId,
        });

        await this.notifyTransactionIssueStakeholders(updated || tx, {
            issueType: 'TRANSACTION_REVIEW_APPROVED',
            reason: notes,
            actorId,
            actorRole: 'STAFF',
        });

        return updated || { ...tx, metadata, status: nextStatus };
    }

    public async approveAllAuditPassedTransactions(actorId: string, notes: string): Promise<{ approved: number; failed: number; approvedIds: string[]; failedItems: any[]; }> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('VAULT_OFFLINE');

        const { data: held } = await sb
            .from('transactions')
            .select('*')
            .eq('status', 'held_for_review');

        const candidates = (held || []).filter((tx: any) =>
            String(tx.metadata?.transaction_lock?.audit_status || '').toUpperCase() === 'PASSED'
        );

        const approvedIds: string[] = [];
        const failedItems: any[] = [];

        for (const tx of candidates) {
            try {
                await this.approveReviewedTransaction(tx.id, actorId, notes);
                approvedIds.push(String(tx.id));
            } catch (e: any) {
                failedItems.push({ id: tx.id, error: e.message });
            }
        }

        await Audit.log('ADMIN', actorId, 'BULK_APPROVE_AUDIT_PASSED_TRANSACTIONS', {
            approved: approvedIds.length,
            failed: failedItems.length,
            approvedIds,
        });

        return {
            approved: approvedIds.length,
            failed: failedItems.length,
            approvedIds,
            failedItems,
        };
    }

    public async reverseTransactionWithReason(
        txId: string,
        actorId: string,
        reason: string,
        actorRole: 'USER' | 'STAFF' | 'SYSTEM' = 'STAFF'
    ): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('VAULT_OFFLINE');

        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).single();
        if (!tx) throw new Error('TRANSACTION_NOT_FOUND');
        if (['reversed', 'failed', 'refunded', 'cancelled'].includes(String(tx.status || '').toLowerCase())) {
            throw new Error('TRANSACTION_NOT_REVERSIBLE');
        }

        await this.reverseTransaction(txId, actorId);

        const metadata = {
            ...(tx.metadata || {}),
            reversal_reason: reason,
            reversed_at: new Date().toISOString(),
            reversed_by: actorId,
            reversed_by_role: actorRole,
        };

        await sb.from('transactions').update({
            metadata,
            status_notes: reason,
            updated_at: new Date().toISOString(),
        }).eq('id', txId);

        await this.notifyTransactionIssueStakeholders({ ...tx, metadata, status: 'reversed' }, {
            issueType: 'TRANSACTION_REVERSED',
            reason,
            actorId,
            actorRole,
        });
    }

    public async autoReverseHeldTransactions(): Promise<number> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return 0;

        const nowIso = new Date().toISOString();
        const { data: held } = await sb
            .from('transactions')
            .select('*')
            .eq('status', 'held_for_review');

        let reversedCount = 0;
        for (const tx of held || []) {
            try {
                const autoReverseAt = tx.metadata?.transaction_lock?.auto_reverse_at;
                const lockedAt = tx.metadata?.transaction_lock?.locked_at || tx.updated_at || tx.created_at;
                const dueAt = autoReverseAt || new Date(new Date(lockedAt).getTime() + 24 * 60 * 60 * 1000).toISOString();
                if (new Date(dueAt).getTime() > Date.now()) continue;

                await this.reverseTransactionWithReason(
                    tx.id,
                    'SYSTEM_TIMEOUT',
                    'AUTO_REVERSAL_AFTER_24_HOURS: Transaction remained under review beyond permitted window.',
                    'SYSTEM'
                );
                reversedCount++;
            } catch (e: any) {
                console.error(`[Ledger] Held transaction auto-reversal failed for ${tx.id}: ${e.message}`);
            }
        }

        if (reversedCount > 0) {
            await Audit.log('SECURITY', 'SYSTEM_TIMEOUT', 'HELD_TRANSACTIONS_AUTO_REVERSED', {
                count: reversedCount,
                processed_at: nowIso,
            });
        }

        return reversedCount;
    }

    private async notifyTransactionIssueStakeholders(tx: any, details: {
        issueType: string;
        reason: string;
        actorId: string;
        actorRole: string;
        autoReverseAt?: string;
    }) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        const amount = tx.amount ? Number(await DataVault.decrypt(tx.amount).catch(() => tx.amount)) : 0;
        const reference = tx.reference_id || tx.referenceId || tx.id;
        const subject = `Transaction Issue: ${details.issueType}`;
        const body = [
            `Transaction ${reference} requires attention.`,
            `Reason: ${details.reason}`,
            `Actor: ${details.actorRole}`,
            details.autoReverseAt ? `Auto-reverse at: ${details.autoReverseAt}` : null,
        ].filter(Boolean).join(' ');

        const { data: staff } = await sb
            .from('staff')
            .select('id')
            .in('role', ['ADMIN', 'SUPER_ADMIN', 'CUSTOMER_CARE', 'AUDIT'])
            .eq('account_status', 'active');

        await Promise.all((staff || []).map(async (member: any) => {
            try {
                await Messaging.dispatch(member.id, 'security', subject, body, { push: true, sms: false, email: true });
            } catch (e: any) {
                console.error(`[Ledger] Staff issue notification failed for ${member.id}: ${e.message}`);
            }
        }));

        try {
            await Messaging.dispatch(
                tx.user_id,
                'security',
                subject,
                `Reference ${reference}. ${details.reason}${details.autoReverseAt ? ` Funds remain under review until ${details.autoReverseAt}.` : ''}`,
                { push: true, sms: true, email: true }
            );
        } catch (e: any) {
            console.error(`[Ledger] User issue notification failed for ${tx.user_id}: ${e.message}`);
        }

        await Audit.log('SECURITY', details.actorId, details.issueType, {
            txId: tx.id,
            reference,
            reason: details.reason,
            actorRole: details.actorRole,
            amount,
            autoReverseAt: details.autoReverseAt || null,
        });
    }

    public async reserveEscrow(userId: string, walletId: string, amount: number, description: string, referenceId: string): Promise<void> {
        const escrowNode = await RegulatoryService.resolveSystemNode('ESCROW_VAULT');
        const legs: LedgerEntry[] = [
            { transactionId: referenceId, walletId, type: 'DEBIT', amount, currency: 'USD', description: `Escrow Hold: ${description}`, timestamp: new Date().toISOString() },
            { transactionId: referenceId, walletId: escrowNode, type: 'CREDIT', amount, currency: 'USD', description: `Inbound Escrow: ${description}`, timestamp: new Date().toISOString() }
        ];

        await this.postTransactionWithLedger({
            id: referenceId,
            user_id: userId,
            amount: amount,
            description: `Compliance Escrow: ${description}`,
            type: 'escrow',
            status: 'processing',
            walletId
        }, legs);
    }
}
