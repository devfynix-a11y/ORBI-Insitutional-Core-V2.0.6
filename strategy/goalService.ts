
import { Goal } from '../types.js';
import { Storage, STORAGE_KEYS } from '../backend/storage.js';
import { getSupabase, getAdminSupabase, createAuthenticatedClient } from '../services/supabaseClient.js';
import { DataVault } from '../backend/security/encryption.js';
import { DataProtection } from '../backend/security/DataProtection.js';
import { TransactionService } from '../ledger/transactionService.js';
import { Audit } from '../backend/security/audit.js';

import { UUID } from '../services/utils.js';

export class GoalService {
    private ledger = new TransactionService();
    private static readonly AUTO_TRIGGER_TYPES = new Set([
        'DEPOSIT',
        'SALARY',
        'REMITTANCE',
        'CARD_DEPOSIT',
        'EXTERNAL_DEPOSIT',
        'AGENT_CASH_DEPOSIT',
        'MANUAL_REPLAY',
    ]);
    private getDb(token?: string) {
        if (token) {
            const client = createAuthenticatedClient(token);
            if (client) return client;
        }
        return getSupabase();
    }

    private getAdminDb() {
        return getAdminSupabase() || getSupabase();
    }

    private roundMoney(value: number): number {
        return Math.round((Number(value) || 0) * 100) / 100;
    }

    private getMonthBounds(anchor: Date = new Date()) {
        const start = new Date(anchor.getFullYear(), anchor.getMonth(), 1);
        const end = new Date(anchor.getFullYear(), anchor.getMonth() + 1, 1);
        return { start, end };
    }

    private async getMonthlyAutoAllocated(
        sb: any,
        goalId: string,
        anchor: Date = new Date(),
    ): Promise<number> {
        const { start, end } = this.getMonthBounds(anchor);
        const { data, error } = await sb
            .from('goal_auto_allocation_events')
            .select('allocated_amount')
            .eq('goal_id', goalId)
            .eq('status', 'COMPLETED')
            .gte('created_at', start.toISOString())
            .lt('created_at', end.toISOString());

        if (error || !data) return 0;
        return data.reduce((sum: number, row: any) => sum + Number(row.allocated_amount || 0), 0);
    }

    private async reserveAutoAllocationEvent(sb: any, payload: any) {
        const now = new Date().toISOString();
        const eventPayload = {
            status: 'PROCESSING',
            allocated_amount: 0,
            metadata: {},
            reason: null,
            ...payload,
            updated_at: now,
        };
        const { data, error } = await sb
            .from('goal_auto_allocation_events')
            .insert(eventPayload)
            .select('*')
            .single();

        if (error) {
            if (error.code === '23505') {
                return null;
            }
            throw new Error(error.message);
        }

        return data;
    }

    private async markAutoAllocationEvent(
        sb: any,
        eventId: string,
        status: 'COMPLETED' | 'SKIPPED' | 'FAILED',
        updates?: Record<string, any>,
    ) {
        const { error } = await sb
            .from('goal_auto_allocation_events')
            .update({
                status,
                updated_at: new Date().toISOString(),
                ...updates,
            })
            .eq('id', eventId);

        if (error) {
            console.error('[GoalService] Failed to update auto-allocation event:', error.message);
        }
    }

    async runAutoAllocationsForCredit(args: {
        userId: string;
        sourceTransactionId: string;
        sourceReferenceId?: string | null;
        sourceWalletId?: string | null;
        sourceAmount: number;
        currency?: string | null;
        triggerType: string;
        metadata?: Record<string, any>;
    }) {
        const sb = this.getAdminDb();
        if (!sb) {
            return { success: false, applied: [], skipped: [], reason: 'DB_OFFLINE' };
        }

        const normalizedTrigger = String(args.triggerType || '').trim().toUpperCase();
        if (!GoalService.AUTO_TRIGGER_TYPES.has(normalizedTrigger)) {
            return { success: true, applied: [], skipped: [], reason: 'TRIGGER_NOT_SUPPORTED' };
        }

        const grossSourceAmount = this.roundMoney(args.sourceAmount);
        if (grossSourceAmount <= 0) {
            return { success: true, applied: [], skipped: [], reason: 'NO_SOURCE_AMOUNT' };
        }

        const { data: sourceTx, error: txError } = await sb
            .from('transactions')
            .select('id, user_id, wallet_id, to_wallet_id, type, status, reference_id, metadata')
            .eq('id', args.sourceTransactionId)
            .maybeSingle();

        if (txError) throw new Error(txError.message);
        if (!sourceTx) {
            return { success: false, applied: [], skipped: [], reason: 'SOURCE_TRANSACTION_NOT_FOUND' };
        }
        if (String(sourceTx.user_id || '') !== String(args.userId)) {
            return { success: false, applied: [], skipped: [], reason: 'SOURCE_TRANSACTION_MISMATCH' };
        }
        if (!['completed', 'settled'].includes(String(sourceTx.status || '').toLowerCase())) {
            return { success: false, applied: [], skipped: [], reason: 'SOURCE_TRANSACTION_NOT_SETTLED' };
        }

        const operatingWalletId = await this.resolveOperatingWalletId(sb, args.userId);
        const sourceWalletId = String(args.sourceWalletId || sourceTx.to_wallet_id || operatingWalletId);
        if (String(sourceWalletId) !== String(operatingWalletId)) {
            return {
                success: true,
                applied: [],
                skipped: [],
                reason: 'NON_OPERATING_CREDIT',
            };
        }

        const { data: goals, error: goalsError } = await sb
            .from('goals')
            .select('id, user_id, name, target, current, funding_strategy, auto_allocation_enabled, linked_income_percentage, monthly_target, created_at')
            .eq('user_id', args.userId)
            .eq('auto_allocation_enabled', true)
            .order('created_at', { ascending: true });

        if (goalsError) throw new Error(goalsError.message);
        if (!goals || goals.length === 0) {
            return { success: true, applied: [], skipped: [], reason: 'NO_AUTO_GOALS' };
        }

        let remainingAvailable = grossSourceAmount;
        const applied: any[] = [];
        const skipped: any[] = [];

        for (const rawGoal of goals) {
            const goalId = String(rawGoal.id);
            const fundingStrategy = String(rawGoal.funding_strategy || 'manual').toLowerCase();
            const currentAmount = Number(rawGoal.current || 0);
            const targetAmount = Number(rawGoal.target || 0);
            const goalRemaining = this.roundMoney(targetAmount - currentAmount);

            const reservedEvent = await this.reserveAutoAllocationEvent(sb, {
                user_id: args.userId,
                goal_id: goalId,
                source_transaction_id: args.sourceTransactionId,
                source_reference_id: args.sourceReferenceId || sourceTx.reference_id || null,
                source_wallet_id: sourceWalletId,
                source_amount: grossSourceAmount,
                trigger_type: normalizedTrigger,
                metadata: {
                    currency: args.currency || null,
                    funding_strategy: fundingStrategy,
                    source_transaction_type: sourceTx.type || null,
                    ...(args.metadata || {}),
                },
            });

            if (!reservedEvent) {
                skipped.push({ goalId, reason: 'ALREADY_PROCESSED' });
                continue;
            }

            if (goalRemaining <= 0) {
                await this.markAutoAllocationEvent(sb, reservedEvent.id, 'SKIPPED', {
                    reason: 'GOAL_ALREADY_FUNDED',
                });
                skipped.push({ goalId, reason: 'GOAL_ALREADY_FUNDED' });
                continue;
            }

            if (remainingAvailable <= 0) {
                await this.markAutoAllocationEvent(sb, reservedEvent.id, 'SKIPPED', {
                    reason: 'SOURCE_FUNDS_CONSUMED',
                });
                skipped.push({ goalId, reason: 'SOURCE_FUNDS_CONSUMED' });
                continue;
            }

            let desiredAmount = 0;
            if (fundingStrategy === 'percentage') {
                const percentage = Number(rawGoal.linked_income_percentage || 0);
                if (percentage <= 0) {
                    await this.markAutoAllocationEvent(sb, reservedEvent.id, 'SKIPPED', {
                        reason: 'PERCENTAGE_NOT_CONFIGURED',
                    });
                    skipped.push({ goalId, reason: 'PERCENTAGE_NOT_CONFIGURED' });
                    continue;
                }
                desiredAmount = this.roundMoney((grossSourceAmount * percentage) / 100);
            } else if (fundingStrategy === 'fixed') {
                const monthlyTarget = Number(rawGoal.monthly_target || 0);
                if (monthlyTarget <= 0) {
                    await this.markAutoAllocationEvent(sb, reservedEvent.id, 'SKIPPED', {
                        reason: 'MONTHLY_TARGET_NOT_CONFIGURED',
                    });
                    skipped.push({ goalId, reason: 'MONTHLY_TARGET_NOT_CONFIGURED' });
                    continue;
                }
                const alreadyAllocatedThisMonth = await this.getMonthlyAutoAllocated(sb, goalId);
                desiredAmount = this.roundMoney(monthlyTarget - alreadyAllocatedThisMonth);
            } else {
                await this.markAutoAllocationEvent(sb, reservedEvent.id, 'SKIPPED', {
                    reason: 'MANUAL_STRATEGY',
                });
                skipped.push({ goalId, reason: 'MANUAL_STRATEGY' });
                continue;
            }

            desiredAmount = this.roundMoney(Math.min(desiredAmount, goalRemaining, remainingAvailable));
            if (desiredAmount <= 0) {
                await this.markAutoAllocationEvent(sb, reservedEvent.id, 'SKIPPED', {
                    reason: 'NO_ALLOCATABLE_AMOUNT',
                });
                skipped.push({ goalId, reason: 'NO_ALLOCATABLE_AMOUNT' });
                continue;
            }

            try {
                const allocation = await this.allocateFunds(goalId, desiredAmount, sourceWalletId);
                remainingAvailable = this.roundMoney(remainingAvailable - desiredAmount);
                await this.markAutoAllocationEvent(sb, reservedEvent.id, 'COMPLETED', {
                    allocated_amount: desiredAmount,
                    metadata: {
                        ...(reservedEvent.metadata || {}),
                        allocation_result: allocation,
                    },
                    reason: null,
                });
                applied.push({
                    goalId,
                    name: rawGoal.name,
                    amount: desiredAmount,
                    strategy: fundingStrategy,
                });
            } catch (error: any) {
                await this.markAutoAllocationEvent(sb, reservedEvent.id, 'FAILED', {
                    reason: error?.message || 'AUTO_ALLOCATION_FAILED',
                });
                skipped.push({
                    goalId,
                    reason: error?.message || 'AUTO_ALLOCATION_FAILED',
                });
                console.error('[GoalService] Auto-allocation failed:', error);
            }
        }

        await Audit.log('FINANCIAL', args.userId, 'GOAL_AUTO_ALLOCATION_RUN', {
            sourceTransactionId: args.sourceTransactionId,
            sourceReferenceId: args.sourceReferenceId || sourceTx.reference_id || null,
            triggerType: normalizedTrigger,
            sourceAmount: grossSourceAmount,
            sourceWalletId,
            appliedCount: applied.length,
            appliedAmount: applied.reduce((sum, item) => sum + Number(item.amount || 0), 0),
            skippedCount: skipped.length,
        });

        return {
            success: true,
            triggerType: normalizedTrigger,
            sourceTransactionId: args.sourceTransactionId,
            sourceWalletId,
            sourceAmount: grossSourceAmount,
            applied,
            skipped,
            remainingAvailable,
        };
    }

    async replayAutoAllocationsForTransaction(
        userId: string,
        sourceTransactionId: string,
        token?: string,
    ) {
        const sb = this.getAdminDb();
        if (!sb) throw new Error('DB_OFFLINE');

        const { data: tx, error } = await sb
            .from('transactions')
            .select('id, user_id, amount, currency, type, status, wallet_id, to_wallet_id, reference_id, metadata')
            .eq('id', sourceTransactionId)
            .maybeSingle();
        if (error) throw new Error(error.message);
        if (!tx) throw new Error('SOURCE_TRANSACTION_NOT_FOUND');
        if (String(tx.user_id || '') !== String(userId)) throw new Error('SOURCE_TRANSACTION_MISMATCH');

        const txType = String(tx.type || '').toLowerCase();
        const triggerType =
            txType === 'salary'
                ? 'SALARY'
                : txType === 'deposit' && tx.metadata?.service_context === 'AGENT_CASH'
                    ? 'AGENT_CASH_DEPOSIT'
                    : 'MANUAL_REPLAY';
        let sourceAmount = Number(tx.amount || 0);
        if (typeof tx.amount === 'string') {
            try {
                sourceAmount = await DataProtection.decryptAmount(tx.amount);
            } catch {
                sourceAmount = Number(tx.amount || 0);
            }
        }

        return this.runAutoAllocationsForCredit({
            userId,
            sourceTransactionId: String(tx.id),
            sourceReferenceId: tx.reference_id || null,
            sourceWalletId: tx.to_wallet_id || tx.wallet_id || null,
            sourceAmount,
            currency: tx.currency || null,
            triggerType,
            metadata: {
                replayed: true,
                replay_token_present: Boolean(token),
            },
        });
    }

    private async resolveOwnedWalletRecord(sb: any, userId: string, walletId: string): Promise<{ id: string; user_id: string; currency?: string; table: 'wallets' | 'platform_vaults' } | null> {
        const { data: wallet } = await sb
            .from('wallets')
            .select('id, user_id, currency, type, is_primary')
            .eq('id', walletId)
            .maybeSingle();
        if (wallet) {
            return {
                id: String(wallet.id),
                user_id: String(wallet.user_id || ''),
                currency: wallet.currency || undefined,
                table: 'wallets'
            };
        }

        const { data: vault } = await sb
            .from('platform_vaults')
            .select('id, user_id, currency, vault_role, name')
            .eq('id', walletId)
            .maybeSingle();
        if (vault) {
            return {
                id: String(vault.id),
                user_id: String(vault.user_id || ''),
                currency: vault.currency || undefined,
                table: 'platform_vaults'
            };
        }

        return null;
    }

    private async resolveOperatingWalletId(sb: any, userId: string): Promise<string> {
        const { data: operatingVault } = await sb
            .from('platform_vaults')
            .select('id, vault_role, balance, created_at')
            .eq('user_id', userId)
            .eq('vault_role', 'OPERATING')
            .order('created_at', { ascending: true })
            .limit(1);
        if (operatingVault && operatingVault.length > 0) {
            return String(operatingVault[0].id);
        }

        const { data } = await sb
            .from('wallets')
            .select('id, is_primary, type')
            .eq('user_id', userId)
            .order('is_primary', { ascending: false })
            .limit(1);
        if (data && data.length > 0) {
            return String(data[0].id);
        }
        const { data: fallback } = await sb
            .from('wallets')
            .select('id')
            .eq('user_id', userId)
            .eq('type', 'operating')
            .limit(1);
        if (fallback && fallback.length > 0) {
            return String(fallback[0].id);
        }
        throw new Error('OPERATING_WALLET_REQUIRED: No operating wallet found for this user.');
    }

    async getFromDBLocal(): Promise<Goal[]> {
        const raw = Storage.getFromDB(STORAGE_KEYS.GOALS) as any[];
        return this.hydrateGoals(raw);
    }

    async fetchForUser(userId: string, token?: string): Promise<Goal[]> {
        const sb = this.getDb(token);
        if (!sb) return this.getFromDBLocal();

        const { data, error } = await sb.from('goals').select('*').eq('user_id', userId);
        if (error || !data) return [];

        return this.hydrateGoals(data);
    }

    private async hydrateGoals(raw: any[]): Promise<Goal[]> {
        return await Promise.all(raw.map(async g => ({
            ...g,
            target: typeof g.target === 'string' ? await DataProtection.decryptAmount(g.target) : g.target,
            current: typeof g.current === 'string' ? await DataProtection.decryptAmount(g.current) : g.current,
            fundingStrategy: g.funding_strategy || 'manual',
            autoAllocationEnabled: g.auto_allocation_enabled || false
        })));
    }

    async postGoal(g: Goal, token?: string) { 
        let encryptedTarget: any = g.target;
        let encryptedCurrent: any = g.current;
        try {
            encryptedTarget = await DataProtection.encryptAmount(Number(g.target || 0));
            encryptedCurrent = await DataProtection.encryptAmount(Number(g.current || 0));
        } catch (e: any) {
            console.warn('[GoalService] Encryption unavailable, storing raw goal amounts locally.', e?.message || e);
        }

        const sb = this.getDb(token);
        let localGoal = { ...g };
        if (sb) {
            const isUUID = (str: any) => typeof str === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(str);
            const goalId = isUUID(g.id) ? g.id : UUID.generate();
            
            const payload: any = {
                id: goalId,
                user_id: g.user_id,
                name: g.name,
                target: g.target,
                current: g.current || 0,
                deadline: g.deadline === '' ? null : g.deadline,
                color: g.color,
                icon: g.icon,
                funding_strategy: g.fundingStrategy || 'manual',
                auto_allocation_enabled: g.autoAllocationEnabled || false
            };
            
            // Remove undefined fields
            Object.keys(payload).forEach(key => payload[key] === undefined && delete payload[key]);

            const { data, error } = await sb.from('goals').upsert(payload).select().single();
            if (error) {
                console.error("[GoalService] Upsert error:", error);
                throw new Error(error.message);
            } else if (data) {
                const hydrated = await this.hydrateGoals([data]);
                localGoal = hydrated[0];
            }
        } else {
            if (!localGoal.id) {
                localGoal.id = UUID.generate();
            }
        }

        let items = Storage.getFromDB<any>(STORAGE_KEYS.GOALS);
        const localIndex = items.findIndex(i => String(i.id) === String(localGoal.id));
        const localPayload = {
            ...localGoal,
            target: encryptedTarget,
            current: encryptedCurrent
        };
        if (localIndex === -1) {
            items.push(localPayload);
        } else {
            items[localIndex] = { ...items[localIndex], ...localPayload };
        }
        Storage.saveToDB(STORAGE_KEYS.GOALS, items);
        return { data: localGoal, error: null }; 
    }

    async updateGoal(g: Partial<Goal> & { id: string | number }, token?: string) {
        const sb = this.getDb(token);
        const payload: any = {};

        if (g.name !== undefined) payload.name = g.name;
        if (g.target !== undefined) payload.target = g.target;
        if (g.deadline !== undefined) payload.deadline = g.deadline === '' ? null : g.deadline;
        if (g.color !== undefined) payload.color = g.color;
        if (g.icon !== undefined) payload.icon = g.icon;
        if (g.fundingStrategy !== undefined) payload.funding_strategy = g.fundingStrategy;
        if (g.autoAllocationEnabled !== undefined) payload.auto_allocation_enabled = g.autoAllocationEnabled;
        if (g.linkedIncomePercentage !== undefined) payload.linked_income_percentage = g.linkedIncomePercentage;
        if (g.monthlyTarget !== undefined) payload.monthly_target = g.monthlyTarget;

        if (sb) {
            const { data, error } = await sb
                .from('goals')
                .update(payload)
                .eq('id', g.id)
                .select()
                .single();
            if (error) {
                console.error('[GoalService] Update error:', error);
                throw new Error(error.message);
            }
            if (data) {
                const hydrated = await this.hydrateGoals([data]);
                const localGoal = hydrated[0];
                let items = Storage.getFromDB<any>(STORAGE_KEYS.GOALS);
                const index = items.findIndex(i => String(i.id) === String(localGoal.id));
                const localPayload = {
                    ...localGoal,
                    target: await DataProtection.encryptAmount(Number(localGoal.target || 0)),
                    current: await DataProtection.encryptAmount(Number(localGoal.current || 0))
                };
                if (index === -1) {
                    items.push(localPayload);
                } else {
                    items[index] = { ...items[index], ...localPayload };
                }
                Storage.saveToDB(STORAGE_KEYS.GOALS, items);
                return { data: localGoal, error: null };
            }
        }

        let items = Storage.getFromDB<any>(STORAGE_KEYS.GOALS);
        const index = items.findIndex(i => String(i.id) === String(g.id));
        if (index !== -1) {
            const currentItem = items[index];
            const updated = { ...currentItem };

            if (g.name !== undefined) updated.name = g.name;
            if (g.target !== undefined) {
                updated.target = await DataProtection.encryptAmount(Number(g.target || 0));
            }
            if (g.deadline !== undefined) updated.deadline = g.deadline === '' ? null : g.deadline;
            if (g.color !== undefined) updated.color = g.color;
            if (g.icon !== undefined) updated.icon = g.icon;
            if (g.fundingStrategy !== undefined) updated.fundingStrategy = g.fundingStrategy;
            if (g.autoAllocationEnabled !== undefined) updated.autoAllocationEnabled = g.autoAllocationEnabled;
            if (g.linkedIncomePercentage !== undefined) updated.linkedIncomePercentage = g.linkedIncomePercentage;
            if (g.monthlyTarget !== undefined) updated.monthlyTarget = g.monthlyTarget;

            items[index] = updated;
            Storage.saveToDB(STORAGE_KEYS.GOALS, items);
        }
        const goals = await this.getFromDBLocal();
        const updatedGoal = goals.find(item => String(item.id) === String(g.id));
        if (!updatedGoal) throw new Error('Goal not found');
        return { data: updatedGoal, error: null };
    }

    async allocateFunds(goalId: string, amount: number, sourceWalletId?: string, token?: string) {
        if (amount <= 0) {
            throw new Error('VALIDATION_ERROR: Allocation amount must be greater than zero.');
        }

        const sb = this.getDb(token);
        let goalName = 'Goal';
        let goalUserId = '';
        let currentAmount = 0;
        let currency = 'TZS';
        
        if (sb) {
            const { data: goal, error } = await sb
                .from('goals')
                .select('id, name, user_id, current, source_wallet_id')
                .eq('id', goalId)
                .single();
            if (error || !goal) {
                throw new Error(error?.message || 'Goal not found');
            }
            goalName = goal.name || goalName;
            goalUserId = goal.user_id || '';
            currentAmount = await DataProtection.decryptAmount(goal.current);
            const existingSource = goal.source_wallet_id as string | null;

            const operatingWalletId = await this.resolveOperatingWalletId(sb, goalUserId);
            if (sourceWalletId && String(sourceWalletId) !== String(operatingWalletId)) {
                throw new Error('OPERATING_WALLET_REQUIRED: Allocations must use the operating wallet.');
            }
            sourceWalletId = operatingWalletId;

            const wallet = await this.resolveOwnedWalletRecord(sb, goalUserId, sourceWalletId);
            if (!wallet) {
                throw new Error('Source wallet not found');
            }
            if (goalUserId && wallet.user_id && String(wallet.user_id) !== String(goalUserId)) {
                throw new Error('Unauthorized source wallet for goal allocation');
            }
            currency = wallet.currency || currency;

            if (existingSource && String(existingSource) !== String(sourceWalletId)) {
                throw new Error('SOURCE_WALLET_LOCKED: Goal allocations must use the original source wallet.');
            }
        } else {
            const goals = await this.getFromDBLocal();
            const goal = goals.find(g => String(g.id) === String(goalId));
            if (!goal) {
                throw new Error('Goal not found');
            }
            currentAmount = goal.current;
            goalName = goal.name || goalName;
            goalUserId = goal.user_id || '';
            if (!sourceWalletId) {
                throw new Error('VALIDATION_ERROR: Source wallet is required.');
            }
        }

        const newAmount = currentAmount + amount;
        const encryptedCurrent = await DataProtection.encryptAmount(newAmount);

        if (sb) {
            const referenceId = `GOAL-ALLOC-${UUID.generateShortCode(12)}`;
            await this.ledger.postTransactionWithLedger(
                {
                    user_id: goalUserId || 'system',
                    walletId: sourceWalletId,
                    toWalletId: goalId,
                    amount,
                    currency,
                    description: `Goal allocation: ${goalName}`,
                    type: 'goal_allocation',
                    status: 'completed',
                    date: new Date().toISOString().split('T')[0],
                    metadata: {
                        goal_id: goalId,
                        source_wallet_id: sourceWalletId,
                        movement: 'allocate_to_goal'
                    },
                    referenceId
                },
                [
                    {
                        transactionId: referenceId,
                        walletId: sourceWalletId,
                        type: 'DEBIT',
                        amount,
                        currency,
                        description: `Goal allocation debit: ${goalName}`,
                        timestamp: new Date().toISOString()
                    },
                    {
                        transactionId: referenceId,
                        walletId: goalId,
                        type: 'CREDIT',
                        amount,
                        currency,
                        description: `Goal allocation credit: ${goalName}`,
                        timestamp: new Date().toISOString()
                    }
                ]
            );

            const { error } = await sb
                .from('goals')
                .update({ source_wallet_id: sourceWalletId })
                .eq('id', goalId);
            if (error) {
                throw new Error(error.message);
            }
        }

        // Update local storage
        let items = Storage.getFromDB<any>(STORAGE_KEYS.GOALS);
        const index = items.findIndex(i => String(i.id) === String(goalId));
        if (index !== -1) {
            items[index].current = encryptedCurrent;
            Storage.saveToDB(STORAGE_KEYS.GOALS, items);
        }

        return { success: true, newAmount };
    }

    async withdrawFunds(goalId: string, amount: number, destinationWalletId?: string, verification?: any, token?: string) {
        const sb = this.getDb(token);

        let currentAmount = 0;
        let goalName = 'Goal';
        let goalUserId = '';
        let currency = 'TZS';
        let sourceWalletId = '';
        if (sb) {
            const { data: goal, error } = await sb
                .from('goals')
                .select('id, name, user_id, current, source_wallet_id')
                .eq('id', goalId)
                .single();
            if (error || !goal) {
                throw new Error(error?.message || 'Goal not found');
            }
            currentAmount = await DataProtection.decryptAmount(goal.current);
            goalName = goal.name || goalName;
            goalUserId = goal.user_id || '';
            sourceWalletId = String(goal.source_wallet_id || '');

            if (!sourceWalletId) {
                sourceWalletId = await this.resolveOperatingWalletId(sb, goalUserId);
                await sb.from('goals').update({ source_wallet_id: sourceWalletId }).eq('id', goalId);
            }

            if (destinationWalletId && String(destinationWalletId) !== String(sourceWalletId)) {
                throw new Error('SOURCE_WALLET_LOCKED: Withdrawals must return to the original source wallet.');
            }

            const wallet = await this.resolveOwnedWalletRecord(sb, goalUserId, sourceWalletId);
            if (!wallet) {
                throw new Error('Source wallet not found');
            }
            if (goalUserId && wallet.user_id && String(wallet.user_id) !== String(goalUserId)) {
                throw new Error('Unauthorized destination wallet for goal withdrawal');
            }
            currency = wallet.currency || currency;
        } else {
            const goals = await this.getFromDBLocal();
            const goal = goals.find(g => String(g.id) === String(goalId));
            if (!goal) {
                throw new Error('Goal not found');
            }
            currentAmount = goal.current;
            goalName = goal.name || goalName;
            goalUserId = goal.user_id || '';
            if (!destinationWalletId) {
                throw new Error('VALIDATION_ERROR: Destination wallet is required.');
            }
        }

        if (amount <= 0) {
            throw new Error('VALIDATION_ERROR: Withdrawal amount must be greater than zero.');
        }
        if (amount > currentAmount) {
            throw new Error('INSUFFICIENT_GOAL_FUNDS: Requested withdrawal exceeds saved goal funds.');
        }

        const newAmount = currentAmount - amount;
        const encryptedCurrent = await DataProtection.encryptAmount(newAmount);

        if (sb) {
            const referenceId = `GOAL-WITHDRAW-${UUID.generateShortCode(12)}`;
            await this.ledger.postTransactionWithLedger(
                {
                    user_id: goalUserId || 'system',
                    walletId: goalId,
                    toWalletId: sourceWalletId,
                    amount,
                    currency,
                    description: `Goal withdrawal: ${goalName}`,
                    type: 'withdrawal',
                    status: 'completed',
                    date: new Date().toISOString().split('T')[0],
                    metadata: {
                        goal_id: goalId,
                        destination_wallet_id: sourceWalletId,
                        movement: 'withdraw_from_goal',
                        security_verification: verification ? {
                            verified_via: verification.verifiedVia || 'otp',
                            pin_verified: verification.pinVerified === true,
                            otp_request_id: verification.otpRequestId || null,
                            otp_verified_at: verification.otpVerifiedAt || null,
                            delivery_type: verification.deliveryType || null,
                            verified_by_user_id: verification.verifiedByUserId || null
                        } : null
                    },
                    referenceId
                },
                [
                    {
                        transactionId: referenceId,
                        walletId: goalId,
                        type: 'DEBIT',
                        amount,
                        currency,
                        description: `Goal withdrawal debit: ${goalName}`,
                        timestamp: new Date().toISOString()
                    },
                    {
                        transactionId: referenceId,
                        walletId: sourceWalletId,
                        type: 'CREDIT',
                        amount,
                        currency,
                        description: `Goal withdrawal credit: ${goalName}`,
                        timestamp: new Date().toISOString()
                    }
                ]
            );

        }

        let items = Storage.getFromDB<any>(STORAGE_KEYS.GOALS);
        const index = items.findIndex(i => String(i.id) === String(goalId));
        if (index !== -1) {
            items[index].current = encryptedCurrent;
            Storage.saveToDB(STORAGE_KEYS.GOALS, items);
        }

        return { success: true, newAmount, destinationWalletId };
    }

    async deleteGoal(id: string, token?: string) { 
        const sb = this.getDb(token);
        if (sb) await sb.from('goals').delete().eq('id', id);
        let items = Storage.getFromDB<Goal>(STORAGE_KEYS.GOALS); 
        items = items.filter(i => String(i.id) !== String(id)); 
        Storage.saveToDB(STORAGE_KEYS.GOALS, items); 
        return { error: null }; 
    }
}
