
import { Goal } from '../types.js';
import { Storage, STORAGE_KEYS } from '../backend/storage.js';
import { getSupabase, createAuthenticatedClient } from '../services/supabaseClient.js';
import { DataVault } from '../backend/security/encryption.js';
import { TransactionService } from '../ledger/transactionService.js';

import { UUID } from '../services/utils.js';

export class GoalService {
    private ledger = new TransactionService();
    private getDb(token?: string) {
        if (token) {
            const client = createAuthenticatedClient(token);
            if (client) return client;
        }
        return getSupabase();
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
            target: typeof g.target === 'string' ? Number(await DataVault.decrypt(g.target)) : g.target,
            current: typeof g.current === 'string' ? Number(await DataVault.decrypt(g.current)) : g.current,
            fundingStrategy: g.funding_strategy || 'manual',
            autoAllocationEnabled: g.auto_allocation_enabled || false
        })));
    }

    async postGoal(g: Goal, token?: string) { 
        let encryptedTarget: any = g.target;
        let encryptedCurrent: any = g.current;
        try {
            encryptedTarget = await DataVault.encrypt(g.target);
            encryptedCurrent = await DataVault.encrypt(g.current);
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
                    target: await DataVault.encrypt(localGoal.target),
                    current: await DataVault.encrypt(localGoal.current)
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
                updated.target = await DataVault.encrypt(g.target);
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

    async allocateFunds(goalId: string, amount: number, sourceWalletId: string, token?: string) {
        if (amount <= 0) {
            throw new Error('VALIDATION_ERROR: Allocation amount must be greater than zero.');
        }
        if (!sourceWalletId) {
            throw new Error('VALIDATION_ERROR: Source wallet is required.');
        }

        const sb = this.getDb(token);
        let goalName = 'Goal';
        let goalUserId = '';
        let currentAmount = 0;
        let currency = 'TZS';
        
        if (sb) {
            const { data: goal, error } = await sb
                .from('goals')
                .select('id, name, user_id, current')
                .eq('id', goalId)
                .single();
            if (error || !goal) {
                throw new Error(error?.message || 'Goal not found');
            }
            goalName = goal.name || goalName;
            goalUserId = goal.user_id || '';
            currentAmount = Number(await DataVault.decrypt(goal.current));

            const { data: wallet } = await sb
                .from('wallets')
                .select('id, user_id, currency')
                .eq('id', sourceWalletId)
                .maybeSingle();
            if (!wallet) {
                throw new Error('Source wallet not found');
            }
            if (goalUserId && wallet.user_id && String(wallet.user_id) !== String(goalUserId)) {
                throw new Error('Unauthorized source wallet for goal allocation');
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
        }

        const newAmount = currentAmount + amount;
        const encryptedCurrent = await DataVault.encrypt(newAmount);

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

            const { error } = await sb.from('goals').update({ current: newAmount }).eq('id', goalId);
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

    async withdrawFunds(goalId: string, amount: number, destinationWalletId: string, verification?: any, token?: string) {
        if (!destinationWalletId) {
            throw new Error('VALIDATION_ERROR: Destination wallet is required.');
        }
        const sb = this.getDb(token);

        let currentAmount = 0;
        let goalName = 'Goal';
        let goalUserId = '';
        let currency = 'TZS';
        if (sb) {
            const { data: goal, error } = await sb
                .from('goals')
                .select('id, name, user_id, current')
                .eq('id', goalId)
                .single();
            if (error || !goal) {
                throw new Error(error?.message || 'Goal not found');
            }
            currentAmount = Number(await DataVault.decrypt(goal.current));
            goalName = goal.name || goalName;
            goalUserId = goal.user_id || '';

            const { data: wallet } = await sb
                .from('wallets')
                .select('id, user_id, currency')
                .eq('id', destinationWalletId)
                .maybeSingle();
            if (!wallet) {
                throw new Error('Destination wallet not found');
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
        }

        if (amount <= 0) {
            throw new Error('VALIDATION_ERROR: Withdrawal amount must be greater than zero.');
        }
        if (amount > currentAmount) {
            throw new Error('INSUFFICIENT_GOAL_FUNDS: Requested withdrawal exceeds saved goal funds.');
        }

        const newAmount = currentAmount - amount;
        const encryptedCurrent = await DataVault.encrypt(newAmount);

        if (sb) {
            const referenceId = `GOAL-WITHDRAW-${UUID.generateShortCode(12)}`;
            await this.ledger.postTransactionWithLedger(
                {
                    user_id: goalUserId || 'system',
                    walletId: goalId,
                    toWalletId: destinationWalletId,
                    amount,
                    currency,
                    description: `Goal withdrawal: ${goalName}`,
                    type: 'withdrawal',
                    status: 'completed',
                    date: new Date().toISOString().split('T')[0],
                    metadata: {
                        goal_id: goalId,
                        destination_wallet_id: destinationWalletId,
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
                        walletId: destinationWalletId,
                        type: 'CREDIT',
                        amount,
                        currency,
                        description: `Goal withdrawal credit: ${goalName}`,
                        timestamp: new Date().toISOString()
                    }
                ]
            );

            const { error } = await sb.from('goals').update({ current: newAmount }).eq('id', goalId);
            if (error) throw new Error(error.message);
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
