import { type RequestHandler, type Router } from 'express';
import { z } from 'zod';
import { Messaging } from '../../../backend/features/MessagingService.js';

type Deps = {
  authenticate: RequestHandler;
  LogicCore: any;
  getSupabase: () => any;
  getAdminSupabase: () => any;
};

let logicCoreRef: any = null;

const BillReserveCreateSchema = z.object({
    provider_name: z.string().min(2),
    bill_type: z.string().min(2),
    source_wallet_id: z.string().uuid().optional(),
    currency: z.string().min(3).max(8).optional(),
    due_pattern: z.enum(['WEEKLY', 'MONTHLY', 'CUSTOM']).optional(),
    due_day: z.coerce.number().int().min(1).max(31).optional(),
    reserve_mode: z.enum(['FIXED', 'PERCENT']).optional(),
    reserve_amount: z.coerce.number().nonnegative(),
});

const SharedPotCreateSchema = z.object({
    name: z.string().min(2),
    purpose: z.string().optional(),
    currency: z.string().min(3).max(8).optional(),
    target_amount: z.coerce.number().nonnegative().optional(),
    access_model: z.enum(['INVITE', 'PRIVATE', 'ORG']).optional(),
});

const BillReserveUpdateSchema = BillReserveCreateSchema.partial().extend({
    is_active: z.boolean().optional(),
    status: z.enum(['ACTIVE', 'PAUSED', 'ARCHIVED']).optional(),
});

const BillReservePaymentSchema = z.object({
    bill_reserve_id: z.string().uuid().optional(),
    reserve_id: z.string().uuid().optional(),
    amount: z.coerce.number().positive(),
    currency: z.string().min(3).max(8).optional(),
    provider: z.string().min(2),
    billCategory: z.string().optional(),
    reference: z.string().optional(),
    description: z.string().max(255).optional(),
    metadata: z.record(z.string(), z.any()).optional(),
}).refine((data) => !!(data.bill_reserve_id || data.reserve_id), {
    message: 'bill_reserve_id is required',
});

const SharedPotUpdateSchema = SharedPotCreateSchema.partial().extend({
    status: z.enum(['ACTIVE', 'PAUSED', 'COMPLETED', 'ARCHIVED']).optional(),
});

const SharedPotContributionSchema = z.object({
    amount: z.coerce.number().positive(),
    source_wallet_id: z.string().uuid().optional(),
});

const SharedPotMemberAddSchema = z.object({
    identifier: z.string().min(3),
    role: z.enum(['MANAGER', 'CONTRIBUTOR', 'VIEWER']).optional(),
    message: z.string().max(240).optional(),
});

const SharedPotInviteResponseSchema = z.object({
    action: z.enum(['ACCEPT', 'REJECT']),
});

const SharedPotWithdrawSchema = z.object({
    amount: z.coerce.number().positive(),
    target_wallet_id: z.string().uuid().optional(),
});

const SharedBudgetCreateSchema = z.object({
    name: z.string().min(2),
    purpose: z.string().optional(),
    currency: z.string().min(3).max(8).optional(),
    budget_limit: z.coerce.number().positive(),
    period_type: z.enum(['WEEKLY', 'MONTHLY', 'CUSTOM']).optional(),
    approval_mode: z.enum(['AUTO', 'REVIEW']).optional(),
});

const SharedBudgetUpdateSchema = SharedBudgetCreateSchema.partial().extend({
    status: z.enum(['ACTIVE', 'PAUSED', 'ARCHIVED']).optional(),
});

const SharedBudgetMemberAddSchema = z.object({
    identifier: z.string().min(3),
    role: z.enum(['MANAGER', 'SPENDER', 'VIEWER']).optional(),
    member_limit: z.coerce.number().positive().optional(),
    message: z.string().max(240).optional(),
});

const SharedBudgetInviteResponseSchema = z.object({
    action: z.enum(['ACCEPT', 'REJECT']),
});

const SharedBudgetApprovalResponseSchema = z.object({
    action: z.enum(['APPROVE', 'REJECT']),
    note: z.string().max(255).optional(),
});

const SharedBudgetSpendSchema = z.object({
    source_wallet_id: z.string().uuid().optional(),
    amount: z.coerce.number().positive(),
    currency: z.string().min(3).max(8).optional(),
    provider: z.string().min(2).optional(),
    bill_category: z.string().min(2).optional(),
    reference: z.string().min(2).optional(),
    description: z.string().max(255).optional(),
    type: z.enum(['EXTERNAL_PAYMENT', 'BILL_PAYMENT', 'MERCHANT_PAYMENT']).optional(),
    metadata: z.record(z.string(), z.any()).optional(),
});

const AllocationRuleCreateSchema = z.object({
    name: z.string().min(2),
    trigger_type: z.enum(['DEPOSIT', 'SALARY', 'ROUNDUP', 'REMITTANCE', 'MANUAL']),
    source_wallet_id: z.string().uuid().optional(),
    target_type: z.enum(['GOAL', 'BUDGET', 'BILL_RESERVE', 'SHARED_POT', 'WEALTH_BUCKET']),
    target_id: z.string().uuid(),
    mode: z.enum(['FIXED', 'PERCENT']),
    fixed_amount: z.coerce.number().nonnegative().optional(),
    percentage: z.coerce.number().min(0).max(100).optional(),
    priority: z.coerce.number().int().min(1).optional(),
});

const AllocationRuleUpdateSchema = AllocationRuleCreateSchema.partial().extend({
    is_active: z.boolean().optional(),
});

const wealthNumber = (value: any) => {
    if (typeof value === 'number') return value;
    if (typeof value === 'string') return Number(value.replace(/,/g, '')) || 0;
    return 0;
};

const resolveWealthSourceWallet = async (
    sb: any,
    userId: string,
    sourceWalletId?: string,
) => {
    let sourceRecord: any = null;
    let sourceTable: 'platform_vaults' | 'wallets' = 'platform_vaults';

    if (sourceWalletId) {
        const { data: vaultMatch } = await sb
            .from('platform_vaults')
            .select('*')
            .eq('id', sourceWalletId)
            .eq('user_id', userId)
            .maybeSingle();
        if (vaultMatch) {
            sourceRecord = vaultMatch;
            sourceTable = 'platform_vaults';
        } else {
            const { data: walletMatch } = await sb
                .from('wallets')
                .select('*')
                .eq('id', sourceWalletId)
                .eq('user_id', userId)
                .maybeSingle();
            if (walletMatch) {
                sourceRecord = walletMatch;
                sourceTable = 'wallets';
            }
        }
    }

    if (!sourceRecord) {
        const { data: operatingVault } = await sb
            .from('platform_vaults')
            .select('*')
            .eq('user_id', userId)
            .eq('vault_role', 'OPERATING')
            .maybeSingle();
        if (operatingVault) {
            sourceRecord = operatingVault;
            sourceTable = 'platform_vaults';
        } else {
            const { data: fallbackWallet } = await sb
                .from('wallets')
                .select('*')
                .eq('user_id', userId)
                .order('created_at', { ascending: true })
                .limit(1)
                .maybeSingle();
            sourceRecord = fallbackWallet;
            sourceTable = 'wallets';
        }
    }

    if (!sourceRecord) throw new Error('NO_OPERATING_WALLET');
    return { sourceRecord, sourceTable };
};

const updateWealthSourceBalance = async (
    sb: any,
    sourceTable: 'platform_vaults' | 'wallets',
    sourceRecord: any,
    userId: string,
    nextBalance: number,
) => {
    const { error } = await sb
        .from(sourceTable)
        .update({
            balance: nextBalance,
            updated_at: new Date().toISOString(),
        })
        .eq('id', sourceRecord.id)
        .eq('user_id', userId);
    if (error) throw new Error(error.message);
};

const createWealthTransaction = async (
    sb: any,
    userId: string,
    sourceRecord: any,
    amount: number,
    currency: string,
    description: string,
    wealthImpactType: string,
    metadata: Record<string, any>,
    options?: {
        transactionType?: string;
        transactionStatus?: string;
    },
) => {
    const reference = `wealth_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
    const { data, error } = await sb
        .from('transactions')
        .insert({
            reference_id: reference,
            user_id: userId,
            wallet_id: sourceRecord.id,
            amount: String(amount),
            currency,
            description,
            type: options?.transactionType || 'internal_transfer',
            status: options?.transactionStatus || 'completed',
            wealth_impact_type: wealthImpactType,
            protection_state: 'OPEN',
            allocation_source: metadata.allocation_source || null,
            metadata,
        })
        .select('*')
        .single();
    if (error || !data) throw new Error(error?.message || 'TX_CREATE_FAILED');
    return data;
};

const insertBillReserveLedger = async (
    sb: any,
    {
        transactionId,
        userId,
        sourceRecord,
        reserveId,
        amount,
        sourceBalanceAfter,
        reserveBalanceAfter,
        action,
    }: {
        transactionId: string;
        userId: string;
        sourceRecord: any;
        reserveId: string;
        amount: number;
        sourceBalanceAfter: number;
        reserveBalanceAfter: number;
        action: 'LOCK' | 'RELEASE';
    },
) => {
    const isLock = action == 'LOCK';
    const rows = [
        {
            transaction_id: transactionId,
            user_id: userId,
            wallet_id: sourceRecord.id,
            bill_reserve_id: reserveId,
            bucket_type: 'OPERATING',
            entry_side: isLock ? 'DEBIT' : 'CREDIT',
            entry_type: isLock ? 'DEBIT' : 'CREDIT',
            amount: String(amount),
            balance_after: String(sourceBalanceAfter),
            description: isLock
                ? 'Bill reserve funding debit'
                : 'Bill reserve release credit',
        },
        {
            transaction_id: transactionId,
            user_id: userId,
            wallet_id: sourceRecord.id,
            bill_reserve_id: reserveId,
            bucket_type: 'PLANNED',
            entry_side: isLock ? 'CREDIT' : 'DEBIT',
            entry_type: isLock ? 'CREDIT' : 'DEBIT',
            amount: String(amount),
            balance_after: String(reserveBalanceAfter),
            description: isLock
                ? 'Bill reserve protected balance credit'
                : 'Bill reserve protected balance release',
        },
    ];
    const { error } = await sb.from('financial_ledger').insert(rows);
    if (error) throw new Error(error.message);
};

const wealthSourceMetadata = (sourceRecord: any): Record<string, any> => {
    const metadata = sourceRecord?.metadata;
    if (metadata && typeof metadata === 'object' && !Array.isArray(metadata)) {
        return metadata as Record<string, any>;
    }
    return {};
};

const isGoalBackedWealthSourceWallet = (sourceRecord: any) => {
    const metadata = wealthSourceMetadata(sourceRecord);
    const sourceKind = String(
        metadata.source_kind ??
        metadata.sourceKind ??
        sourceRecord?.vault_role ??
        sourceRecord?.type ??
        '',
    ).trim().toLowerCase();
    const linkedGoalId = metadata.goal_id ?? metadata.goalId ?? sourceRecord?.goal_id;
    return sourceKind.includes('goal') || Boolean(linkedGoalId);
};

const assertBillPaymentSourceAllowed = (sourceRecord: any) => {
    if (isGoalBackedWealthSourceWallet(sourceRecord)) {
        throw new Error('GOAL_FUNDS_BILL_PAYMENT_NOT_ALLOWED');
    }
};

const normalizeBillReserveValue = (value: string) =>
    value
        .trim()
        .toLowerCase()
        .replace(/&/g, 'and')
        .replace(/[^a-z0-9]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

const billReserveValuesMatch = (left?: string | null, right?: string | null) => {
    const leftKey = normalizeBillReserveValue(String(left || ''));
    const rightKey = normalizeBillReserveValue(String(right || ''));
    if (!leftKey || !rightKey) return false;
    return leftKey === rightKey || leftKey.includes(rightKey) || rightKey.includes(leftKey);
};

const resolveBillReserveReference = (reserve: any) =>
    String(
        reserve?.reference ??
        reserve?.bill_reference ??
        reserve?.account_number ??
        reserve?.meter_number ??
        reserve?.customer_number ??
        '',
    ).trim();

const normalizeWealthIdentifier = (value: string) => value.trim().toLowerCase();

const normalizeWealthPhone = (value: string) =>
    value
        .trim()
        .replace(/[^\d+]/g, '')
        .replace(/(?!^)\+/g, '');

const isEmailLikeIdentifier = (value: string) => value.includes('@');

const resolveSharedPotMembership = async (sb: any, potId: string, userId: string) => {
    const { data: pot, error: potError } = await sb
        .from('shared_pots')
        .select('*')
        .eq('id', potId)
        .maybeSingle();
    if (potError) throw new Error(potError.message);
    if (!pot) throw new Error('SHARED_POT_NOT_FOUND');

    const { data: membership, error: memberError } = await sb
        .from('shared_pot_members')
        .select('*')
        .eq('pot_id', potId)
        .eq('user_id', userId)
        .maybeSingle();
    if (memberError) throw new Error(memberError.message);

    const ownerMembership = pot.owner_user_id === userId
        ? { role: 'OWNER', user_id: userId, pot_id: potId }
        : null;

    const effectiveMembership = membership || ownerMembership;
    if (!effectiveMembership) throw new Error('SHARED_POT_ACCESS_DENIED');
    return { pot, membership: effectiveMembership };
};

const canManageSharedPot = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());
const canContributeToSharedPot = (role: string) =>
    ['OWNER', 'MANAGER', 'CONTRIBUTOR'].includes(role.toUpperCase());

const resolveUserBySharedPotIdentifier = async (sb: any, identifier: string) => {
    if (isEmailLikeIdentifier(identifier)) {
        const { data, error } = await sb
            .from('users')
            .select('id,email,phone,full_name')
            .eq('email', normalizeWealthIdentifier(identifier))
            .maybeSingle();
        if (error) throw new Error(error.message);
        return data;
    }

    const normalizedPhone = normalizeWealthPhone(identifier);
    const candidates = Array.from(new Set([identifier.trim(), normalizedPhone, normalizedPhone.replace(/\D/g, '')].filter(Boolean)));
    const { data, error } = await sb
        .from('users')
        .select('id,email,phone,full_name')
        .in('phone', candidates)
        .limit(1)
        .maybeSingle();
    if (error) throw new Error(error.message);
    return data;
};

const expireSharedPotInvitationIfNeeded = async (sb: any, invite: any) => {
    if (!invite?.expires_at) return invite;
    if (String(invite.status || '').toUpperCase() !== 'PENDING') return invite;
    if (new Date(invite.expires_at).getTime() > Date.now()) return invite;

    const { data, error } = await sb
        .from('shared_pot_invitations')
        .update({
            status: 'EXPIRED',
            updated_at: new Date().toISOString(),
        })
        .eq('id', invite.id)
        .select('*')
        .single();
    if (error) throw new Error(error.message);
    return data || invite;
};

const resolveSharedBudgetMembership = async (sb: any, budgetId: string, userId: string) => {
    const { data: budget, error: budgetError } = await sb
        .from('shared_budgets')
        .select('*')
        .eq('id', budgetId)
        .maybeSingle();
    if (budgetError) throw new Error(budgetError.message);
    if (!budget) throw new Error('SHARED_BUDGET_NOT_FOUND');

    const { data: membership, error: memberError } = await sb
        .from('shared_budget_members')
        .select('*')
        .eq('budget_id', budgetId)
        .eq('user_id', userId)
        .maybeSingle();
    if (memberError) throw new Error(memberError.message);

    const ownerMembership = budget.owner_user_id === userId
        ? { role: 'OWNER', user_id: userId, budget_id: budgetId }
        : null;

    const effectiveMembership = membership || ownerMembership;
    if (!effectiveMembership) throw new Error('SHARED_BUDGET_ACCESS_DENIED');
    return { budget, membership: effectiveMembership };
};

const canManageSharedBudget = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());
const canSpendFromSharedBudget = (role: string) => ['OWNER', 'MANAGER', 'SPENDER'].includes(role.toUpperCase());
const canReviewSharedBudgetSpend = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());

const resolveUserBySharedBudgetIdentifier = async (sb: any, identifier: string) => {
    return resolveUserBySharedPotIdentifier(sb, identifier);
};

const expireSharedBudgetInvitationIfNeeded = async (sb: any, invite: any) => {
    if (!invite?.expires_at) return invite;
    if (String(invite.status || '').toUpperCase() !== 'PENDING') return invite;
    if (new Date(invite.expires_at).getTime() > Date.now()) return invite;

    const { data, error } = await sb
        .from('shared_budget_invitations')
        .update({
            status: 'EXPIRED',
            updated_at: new Date().toISOString(),
        })
        .eq('id', invite.id)
        .select('*')
        .single();
    if (error) throw new Error(error.message);
    return data || invite;
};

const executeSharedBudgetSpend = async (
    sb: any,
    {
        budget,
        membership,
        actorUserId,
        actorUser,
        payload,
        approvalId,
    }: {
        budget: any;
        membership: any;
        actorUserId: string;
        actorUser: any;
        payload: any;
        approvalId?: string | null;
    },
) => {
    const currentSpent = wealthNumber(budget.spent_amount);
    const budgetLimit = wealthNumber(budget.budget_limit);
    if (currentSpent + payload.amount > budgetLimit) {
        throw new Error('SHARED_BUDGET_LIMIT_EXCEEDED');
    }

    const memberSpent = wealthNumber(membership.spent_amount || 0);
    if (membership.member_limit && memberSpent + payload.amount > wealthNumber(membership.member_limit)) {
        throw new Error('SHARED_BUDGET_MEMBER_LIMIT_EXCEEDED');
    }

    const enrichedMetadata = {
        ...(payload.metadata || {}),
        shared_budget_id: budget.id,
        shared_budget_name: budget.name,
        shared_budget_role: membership.role || 'SPENDER',
        bill_provider: payload.provider || null,
        bill_category: payload.bill_category || null,
        bill_reference: payload.reference || null,
        spend_origin: 'SHARED_BUDGET',
        spend_type: payload.type || 'EXTERNAL_PAYMENT',
        approval_id: approvalId || null,
        approval_mode: budget.approval_mode || 'AUTO',
        actor_user_id: actorUserId,
        member_user_id: actorUserId,
    };

    const result = await logicCoreRef.processSecurePayment({
        sourceWalletId: payload.source_wallet_id,
        recipientId: payload.provider,
        amount: payload.amount,
        currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
        description: payload.description || `${budget.name} spend`,
        type: payload.type || 'EXTERNAL_PAYMENT',
        metadata: enrichedMetadata,
    }, actorUser);
    if (!result.success) throw new Error(result.error || 'SHARED_BUDGET_SPEND_FAILED');

    const tx = result.transaction || {};
    const transactionId = tx.internalId || tx.id || null;
    const newBudgetSpent = currentSpent + payload.amount;
    const newMemberSpent = memberSpent + payload.amount;
    const nowIso = new Date().toISOString();

    if (transactionId) {
        const { error: txLinkError } = await sb
            .from('transactions')
            .update({
                shared_budget_id: budget.id,
                updated_at: nowIso,
                metadata: enrichedMetadata,
            })
            .eq('id', transactionId);
        if (txLinkError) throw new Error(txLinkError.message);

        const { error: ledgerLinkError } = await sb
            .from('financial_ledger')
            .update({ shared_budget_id: budget.id })
            .eq('transaction_id', transactionId);
        if (ledgerLinkError) throw new Error(ledgerLinkError.message);
    }

    const { error: budgetUpdateError } = await sb
        .from('shared_budgets')
        .update({
            spent_amount: newBudgetSpent,
            updated_at: nowIso,
        })
        .eq('id', budget.id);
    if (budgetUpdateError) throw new Error(budgetUpdateError.message);

    const { error: memberUpdateError } = await sb
        .from('shared_budget_members')
        .upsert({
            budget_id: budget.id,
            user_id: actorUserId,
            role: membership.role || 'SPENDER',
            status: membership.status || 'ACTIVE',
            member_limit: membership.member_limit || null,
            spent_amount: newMemberSpent,
            metadata: membership.metadata || {},
        }, {
            onConflict: 'budget_id,user_id',
        });
    if (memberUpdateError) throw new Error(memberUpdateError.message);

    const { data: budgetTx, error: budgetTxError } = await sb
        .from('shared_budget_transactions')
        .insert({
            shared_budget_id: budget.id,
            member_user_id: actorUserId,
            source_wallet_id: payload.source_wallet_id || tx.fromWalletId || null,
            transaction_id: transactionId,
            merchant_name: payload.provider || tx.toUserId || null,
            provider: payload.provider || null,
            category: payload.bill_category || payload.type || 'SPEND',
            amount: payload.amount,
            currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
            status: 'COMPLETED',
            note: payload.description || null,
            metadata: {
                ...enrichedMetadata,
                reference: payload.reference || null,
                approved_from_review: approvalId != null,
            },
        })
        .select('*')
        .single();
    if (budgetTxError) throw new Error(budgetTxError.message);

    return {
        transaction: result.transaction,
        budget_transaction: budgetTx,
        shared_budget: {
            ...budget,
            spent_amount: newBudgetSpent,
            remaining_amount: Math.max(0, budgetLimit - newBudgetSpent),
        },
        member: {
            ...membership,
            spent_amount: newMemberSpent,
        },
    };
};

export {
  BillReservePaymentSchema,
  wealthNumber,
  resolveWealthSourceWallet,
  assertBillPaymentSourceAllowed,
  billReserveValuesMatch,
  resolveBillReserveReference,
};

export const registerWealthRoutes = (v1: Router, deps: Deps) => {
  const { authenticate, LogicCore, getSupabase, getAdminSupabase } = deps;
  logicCoreRef = LogicCore;

  v1.get('/wealth/summary', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

          const userId = session.sub;
          const [
              platformVaultsResult,
              walletsResult,
              goalsResult,
              categoriesResult,
              billReservesResult,
              sharedPotsResult,
              userResult,
          ] = await Promise.all([
              sb.from('platform_vaults').select('vault_role,name,balance,currency,metadata').eq('user_id', userId),
              sb.from('wallets').select('name,balance,currency,type,management_tier,metadata').eq('user_id', userId),
              sb.from('goals').select('current').eq('user_id', userId),
              sb.from('categories').select('budget').eq('user_id', userId),
              sb.from('bill_reserves').select('reserve_amount,locked_balance,currency,is_active').eq('user_id', userId),
              sb.from('shared_pots').select('current_amount,target_amount,currency,status').eq('owner_user_id', userId),
              sb.from('users').select('currency').eq('id', userId).single(),
          ]);

          const firstError = [
              platformVaultsResult.error,
              walletsResult.error,
              goalsResult.error,
              categoriesResult.error,
              billReservesResult.error,
              sharedPotsResult.error,
              userResult.error,
          ].find(Boolean);
          if (firstError) {
              return res.status(400).json({ success: false, error: (firstError as any).message });
          }

          const preferredCurrency = String(userResult.data?.currency || 'TZS').toUpperCase();
          const asNumber = (value: any) => {
              if (typeof value === 'number') return value;
              if (typeof value === 'string') return Number(value.replace(/,/g, '')) || 0;
              return 0;
          };

          const platformVaults = platformVaultsResult.data || [];
          const wallets = walletsResult.data || [];
          const operatingVault = platformVaults.find((vault: any) => String(vault.vault_role || '').toUpperCase() === 'OPERATING');
          const fallbackOperatingWallet = wallets.find((wallet: any) => {
              const lowType = String(wallet.type || '').toLowerCase();
              const lowTier = String(wallet.management_tier || '').toLowerCase();
              const lowName = String(wallet.name || '').toLowerCase();
              return lowType.includes('internal') || lowTier.includes('sovereign') || lowName.includes('dilpesa');
          });

          const escrowBalance = [
              ...platformVaults.filter((vault: any) => String(vault.vault_role || '').toUpperCase() === 'INTERNAL_TRANSFER'),
              ...wallets.filter((wallet: any) => {
                  const lowName = String(wallet.name || '').toLowerCase();
                  const lowType = String(wallet.type || '').toLowerCase();
                  const escrowMeta = wallet.metadata?.is_secure_escrow === true;
                  return lowName.includes('paysafe') || lowName.includes('escrow') || lowType.includes('internal_transfer') || escrowMeta;
              }),
          ].reduce((sum: number, item: any) => sum + asNumber(item.balance), 0);

          const plannedBudget = (categoriesResult.data || []).reduce(
              (sum: number, category: any) => sum + asNumber(category.budget),
              0,
          );
          const reserveLocked = (billReservesResult.data || [])
              .filter((reserve: any) => reserve.is_active !== false)
              .reduce((sum: number, reserve: any) => sum + asNumber(reserve.locked_balance || reserve.reserve_amount), 0);
          const growingGoals = (goalsResult.data || []).reduce(
              (sum: number, goal: any) => sum + asNumber(goal.current),
              0,
          );
          const sharedPotBalance = (sharedPotsResult.data || [])
              .filter((pot: any) => String(pot.status || 'ACTIVE').toUpperCase() !== 'ARCHIVED')
              .reduce((sum: number, pot: any) => sum + asNumber(pot.current_amount), 0);

          const operatingBalance = asNumber(
              operatingVault?.balance ?? fallbackOperatingWallet?.balance ?? 0,
          );
          const plannedBalance = plannedBudget + reserveLocked;
          const protectedBalance = escrowBalance;
          const growingBalance = growingGoals + sharedPotBalance;

          const insights: Array<{ type: string; title: string; message: string; severity: string }> = [];
          if (plannedBalance > operatingBalance) {
              insights.push({
                  type: 'SPEND_PRESSURE',
                  title: 'Planned spending is ahead of available money',
                  message: 'Reduce planned spending or top up the operating wallet to stay in control.',
                  severity: 'WARNING',
              });
          }
          if ((goalsResult.data || []).length === 0) {
              insights.push({
                  type: 'GOAL_START',
                  title: 'Start a first growth goal',
                  message: 'Create one goal so ORBI can separate daily money from long-term money.',
                  severity: 'INFO',
              });
          }
          if ((billReservesResult.data || []).length === 0) {
              insights.push({
                  type: 'BILL_RESERVE_START',
                  title: 'Protect your next bill',
                  message: 'Create a bill reserve so important payments are set aside before spending.',
                  severity: 'INFO',
              });
          }

          res.json({
              success: true,
              data: {
                  currency: preferredCurrency,
                  operating_balance: operatingBalance,
                  planned_balance: plannedBalance,
                  protected_balance: protectedBalance,
                  growing_balance: growingBalance,
                  goal_count: (goalsResult.data || []).length,
                  budget_count: (categoriesResult.data || []).length,
                  linked_wallet_count: wallets.filter((wallet: any) => {
                      const lowType = String(wallet.type || '').toLowerCase();
                      const lowTier = String(wallet.management_tier || '').toLowerCase();
                      return lowType.includes('linked') || lowType.includes('external') || lowTier.includes('linked');
                  }).length,
                  insights,
              },
          });
      } catch (e: any) {
          res.status(500).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/bill-reserves', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { data, error } = await sb
              .from('bill_reserves')
              .select('*')
              .eq('user_id', session.sub)
              .order('created_at', { ascending: false });
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data: { reserves: data || [] } });
      } catch (e: any) {
          res.status(500).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/bill-reserves', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = BillReserveCreateSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const currency = payload.currency?.toUpperCase() || 'TZS';
          const isFixedReserve = (payload.reserve_mode || 'FIXED') === 'FIXED';
          const lockedBalance = isFixedReserve ? payload.reserve_amount : 0;

          let sourceRecord: any = null;
          let sourceTable: 'platform_vaults' | 'wallets' = 'platform_vaults';
          let sourceBalanceAfter: number | null = null;

          if (lockedBalance > 0) {
              const resolved = await resolveWealthSourceWallet(
                  sb,
                  session.sub,
                  payload.source_wallet_id,
              );
              sourceRecord = resolved.sourceRecord;
              sourceTable = resolved.sourceTable;
              assertBillPaymentSourceAllowed(sourceRecord);
              const currentBalance = wealthNumber(sourceRecord.balance);
              if (currentBalance < lockedBalance) {
                  return res.status(400).json({ success: false, error: 'INSUFFICIENT_FUNDS' });
              }
              sourceBalanceAfter = currentBalance - lockedBalance;
          }

          const insertPayload = {
              user_id: session.sub,
              provider_name: payload.provider_name,
              bill_type: payload.bill_type,
              source_wallet_id: sourceRecord?.id || payload.source_wallet_id,
              currency,
              due_pattern: payload.due_pattern || 'MONTHLY',
              due_day: payload.due_day,
              reserve_mode: payload.reserve_mode || 'FIXED',
              reserve_amount: payload.reserve_amount,
              locked_balance: lockedBalance,
              is_active: true,
              metadata: {
                  created_from: 'mobile_app',
                  source_table: sourceRecord ? sourceTable : null,
              },
          };
          const { data, error } = await sb
              .from('bill_reserves')
              .insert(insertPayload)
              .select('*')
              .single();
          if (error) return res.status(400).json({ success: false, error: error.message });

          let transaction: any = null;
          if (lockedBalance > 0 && sourceRecord && sourceBalanceAfter != null) {
              transaction = await createWealthTransaction(
                  sb,
                  session.sub,
                  sourceRecord,
                  lockedBalance,
                  currency,
                  `Bill reserve funding: ${payload.provider_name}`,
                  'PLANNED',
                  {
                      bill_reserve_id: data.id,
                      source_table: sourceTable,
                      source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
                      allocation_source: 'BILL_RESERVE_CREATE',
                  },
              );
              await updateWealthSourceBalance(
                  sb,
                  sourceTable,
                  sourceRecord,
                  session.sub,
                  sourceBalanceAfter,
              );
              await insertBillReserveLedger(sb, {
                  transactionId: transaction.id,
                  userId: session.sub,
                  sourceRecord,
                  reserveId: data.id,
                  amount: lockedBalance,
                  sourceBalanceAfter,
                  reserveBalanceAfter: lockedBalance,
                  action: 'LOCK',
              });
          }
          res.json({
              success: true,
              data: {
                  ...data,
                  source_balance: sourceBalanceAfter,
                  transaction,
              },
          });
      } catch (e: any) {
          res.status(400).json({ success: false, error: e.message });
      }
  });

  v1.patch('/wealth/bill-reserves/:id', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = BillReserveUpdateSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { data: existingReserve, error: reserveError } = await sb
              .from('bill_reserves')
              .select('*')
              .eq('id', req.params.id)
              .eq('user_id', session.sub)
              .single();
          if (reserveError || !existingReserve) {
              return res.status(404).json({ success: false, error: 'BILL_RESERVE_NOT_FOUND' });
          }

          const nextReserveMode = payload.reserve_mode ?? existingReserve.reserve_mode ?? 'FIXED';
          const nextReserveAmount = payload.reserve_amount ?? wealthNumber(existingReserve.reserve_amount);
          const nextStatus = payload.status ?? String(existingReserve.status || 'ACTIVE').toUpperCase();
          const nextIsActive = payload.is_active ?? (existingReserve.is_active !== false);
          const shouldLockFunds =
              nextIsActive &&
              String(nextStatus).toUpperCase() == 'ACTIVE' &&
              String(nextReserveMode).toUpperCase() == 'FIXED';

          const currentLockedBalance = wealthNumber(existingReserve.locked_balance || 0);
          const desiredLockedBalance = shouldLockFunds ? wealthNumber(nextReserveAmount) : 0;
          const delta = desiredLockedBalance - currentLockedBalance;

          const updatePayload: any = {
              updated_at: new Date().toISOString(),
          };
          if (payload.provider_name !== undefined) updatePayload.provider_name = payload.provider_name;
          if (payload.bill_type !== undefined) updatePayload.bill_type = payload.bill_type;
          if (payload.source_wallet_id !== undefined) updatePayload.source_wallet_id = payload.source_wallet_id;
          if (payload.currency !== undefined) updatePayload.currency = payload.currency.toUpperCase();
          if (payload.due_pattern !== undefined) updatePayload.due_pattern = payload.due_pattern;
          if (payload.due_day !== undefined) updatePayload.due_day = payload.due_day;
          if (payload.reserve_mode !== undefined) updatePayload.reserve_mode = payload.reserve_mode;
          if (payload.reserve_amount !== undefined) updatePayload.reserve_amount = payload.reserve_amount;
          if (payload.is_active !== undefined) updatePayload.is_active = payload.is_active;
          if (payload.status !== undefined) updatePayload.status = payload.status;
          updatePayload.locked_balance = desiredLockedBalance;

          let sourceRecord: any = null;
          let sourceTable: 'platform_vaults' | 'wallets' = 'platform_vaults';
          let sourceBalanceAfter: number | null = null;
          let adjustmentAction: 'LOCK' | 'RELEASE' | null = null;

          if (delta !== 0) {
              const resolved = await resolveWealthSourceWallet(
                  sb,
                  session.sub,
                  (payload.source_wallet_id ?? existingReserve.source_wallet_id ?? '').toString() || undefined,
              );
              sourceRecord = resolved.sourceRecord;
              sourceTable = resolved.sourceTable;
              assertBillPaymentSourceAllowed(sourceRecord);
              const currentBalance = wealthNumber(sourceRecord.balance);
              if (delta > 0) {
                  if (currentBalance < delta) {
                      return res.status(400).json({ success: false, error: 'INSUFFICIENT_FUNDS' });
                  }
                  sourceBalanceAfter = currentBalance - delta;
                  adjustmentAction = 'LOCK';
              } else {
                  sourceBalanceAfter = currentBalance + Math.abs(delta);
                  adjustmentAction = 'RELEASE';
              }
              updatePayload.source_wallet_id = sourceRecord.id;
          }

          const { data, error } = await sb
              .from('bill_reserves')
              .update(updatePayload)
              .eq('id', req.params.id)
              .eq('user_id', session.sub)
              .select('*')
              .single();
          if (error) return res.status(400).json({ success: false, error: error.message });

          let transaction: any = null;
          if (delta !== 0 && sourceRecord && sourceBalanceAfter != null && adjustmentAction) {
              const adjustmentAmount = Math.abs(delta);
              transaction = await createWealthTransaction(
                  sb,
                  session.sub,
                  sourceRecord,
                  adjustmentAmount,
                  String(data.currency || sourceRecord.currency || 'TZS').toUpperCase(),
                  adjustmentAction == 'LOCK'
                      ? `Bill reserve top-up: ${data.provider_name}`
                      : `Bill reserve release: ${data.provider_name}`,
                  'PLANNED',
                  {
                      bill_reserve_id: data.id,
                      source_table: sourceTable,
                      source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
                      allocation_source: adjustmentAction == 'LOCK'
                          ? 'BILL_RESERVE_TOP_UP'
                          : 'BILL_RESERVE_RELEASE',
                  },
              );
              await updateWealthSourceBalance(
                  sb,
                  sourceTable,
                  sourceRecord,
                  session.sub,
                  sourceBalanceAfter,
              );
              await insertBillReserveLedger(sb, {
                  transactionId: transaction.id,
                  userId: session.sub,
                  sourceRecord,
                  reserveId: data.id,
                  amount: adjustmentAmount,
                  sourceBalanceAfter,
                  reserveBalanceAfter: desiredLockedBalance,
                  action: adjustmentAction,
              });
          }
          res.json({
              success: true,
              data: {
                  ...data,
                  source_balance: sourceBalanceAfter,
                  transaction,
              },
          });
      } catch (e: any) {
          res.status(400).json({ success: false, error: e.message });
      }
  });

  v1.delete('/wealth/bill-reserves/:id', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

          const { data: reserve, error: reserveError } = await sb
              .from('bill_reserves')
              .select('*')
              .eq('id', req.params.id)
              .eq('user_id', session.sub)
              .single();
          if (reserveError || !reserve) {
              return res.status(404).json({ success: false, error: 'BILL_RESERVE_NOT_FOUND' });
          }

          const lockedBalance = wealthNumber(reserve.locked_balance || 0);
          let sourceBalanceAfter: number | null = null;
          let transaction: any = null;

          if (lockedBalance > 0) {
              const resolved = await resolveWealthSourceWallet(
                  sb,
                  session.sub,
                  String(reserve.source_wallet_id || '').trim() || undefined,
              );
              const sourceRecord = resolved.sourceRecord;
              const sourceTable = resolved.sourceTable;
              const currentBalance = wealthNumber(sourceRecord.balance);
              sourceBalanceAfter = currentBalance + lockedBalance;

              transaction = await createWealthTransaction(
                  sb,
                  session.sub,
                  sourceRecord,
                  lockedBalance,
                  String(reserve.currency || sourceRecord.currency || 'TZS').toUpperCase(),
                  `Bill reserve delete release: ${reserve.provider_name || reserve.bill_type || 'Reserve'}`,
                  'PLANNED',
                  {
                      bill_reserve_id: reserve.id,
                      source_table: sourceTable,
                      source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
                      allocation_source: 'BILL_RESERVE_DELETE_RELEASE',
                  },
              );

              await updateWealthSourceBalance(
                  sb,
                  sourceTable,
                  sourceRecord,
                  session.sub,
                  sourceBalanceAfter,
              );

              await insertBillReserveLedger(sb, {
                  transactionId: transaction.id,
                  userId: session.sub,
                  sourceRecord,
                  reserveId: reserve.id,
                  amount: lockedBalance,
                  sourceBalanceAfter,
                  reserveBalanceAfter: 0,
                  action: 'RELEASE',
              });
          }

          const { error: deleteError } = await sb
              .from('bill_reserves')
              .delete()
              .eq('id', reserve.id)
              .eq('user_id', session.sub);
          if (deleteError) {
              return res.status(400).json({ success: false, error: deleteError.message });
          }

          res.json({
              success: true,
              data: {
                  deleted: true,
                  released_amount: lockedBalance,
                  source_balance: sourceBalanceAfter,
                  transaction,
              },
          });
      } catch (e: any) {
          res.status(400).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/shared-pots', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { data: memberships, error: memberError } = await sb
              .from('shared_pot_members')
              .select('pot_id, role')
              .eq('user_id', session.sub);
          if (memberError) return res.status(400).json({ success: false, error: memberError.message });

          const memberPotIds = Array.from(new Set((memberships || []).map((item: any) => String(item.pot_id || '')).filter(Boolean)));
          let query = sb
              .from('shared_pots')
              .select('*')
              .eq('owner_user_id', session.sub);
          if (memberPotIds.length > 0) {
              query = sb
                  .from('shared_pots')
                  .select('*')
                  .or([
                      `owner_user_id.eq.${session.sub}`,
                      `id.in.(${memberPotIds.join(',')})`,
                  ].join(','));
          }
          const { data, error } = await query.order('created_at', { ascending: false });
          if (error) return res.status(400).json({ success: false, error: error.message });
          const membershipByPot = new Map(
              (memberships || []).map((item: any) => [String(item.pot_id), String(item.role || 'CONTRIBUTOR').toUpperCase()]),
          );
          const items = (data || []).map((pot: any) => ({
              ...pot,
              my_role: pot.owner_user_id === session.sub
                  ? 'OWNER'
                  : (membershipByPot.get(String(pot.id)) || 'CONTRIBUTOR'),
              is_owner: pot.owner_user_id === session.sub,
          }));
          res.json({ success: true, data: { pots: items } });
      } catch (e: any) {
          res.status(500).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/shared-pots', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedPotCreateSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { data, error } = await sb
              .from('shared_pots')
              .insert({
                  owner_user_id: session.sub,
                  name: payload.name,
                  purpose: payload.purpose,
                  currency: payload.currency?.toUpperCase() || 'TZS',
                  target_amount: payload.target_amount || 0,
                  current_amount: 0,
                  access_model: payload.access_model || 'INVITE',
                  status: 'ACTIVE',
                  metadata: { created_from: 'mobile_app' },
              })
              .select('*')
              .single();
          if (error) return res.status(400).json({ success: false, error: error.message });
          await sb.from('shared_pot_members').insert({
              pot_id: data.id,
              user_id: session.sub,
              role: 'OWNER',
              contributed_amount: 0,
          });
          res.json({ success: true, data });
      } catch (e: any) {
          res.status(400).json({ success: false, error: e.message });
      }
  });

  v1.patch('/wealth/shared-pots/:id', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedPotUpdateSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { membership } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
          if (!canManageSharedPot(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_POT_ACCESS_DENIED' });
          }
          const updatePayload: any = {
              updated_at: new Date().toISOString(),
          };
          if (payload.name !== undefined) updatePayload.name = payload.name;
          if (payload.purpose !== undefined) updatePayload.purpose = payload.purpose;
          if (payload.currency !== undefined) updatePayload.currency = payload.currency.toUpperCase();
          if (payload.target_amount !== undefined) updatePayload.target_amount = payload.target_amount;
          if (payload.access_model !== undefined) updatePayload.access_model = payload.access_model;
          if (payload.status !== undefined) updatePayload.status = payload.status;
          const { data, error } = await sb
              .from('shared_pots')
              .update(updatePayload)
              .eq('id', req.params.id)
              .eq('owner_user_id', session.sub)
              .select('*')
              .single();
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data });
      } catch (e: any) {
          res.status(e.message === 'SHARED_POT_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/shared-pots/:id/members', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { pot } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
          const { data, error } = await sb
              .from('shared_pot_members')
              .select('id,pot_id,user_id,role,contribution_target,contributed_amount,metadata,created_at, users!shared_pot_members_user_id_fkey(id, full_name, email, phone)')
              .eq('pot_id', pot.id)
              .order('created_at', { ascending: true });
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data: { members: data || [] } });
      } catch (e: any) {
          res.status(e.message === 'SHARED_POT_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/shared-pots/:id/invitations', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { pot, membership } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
          if (!canManageSharedPot(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_POT_ACCESS_DENIED' });
          }
          const { data, error } = await sb
              .from('shared_pot_invitations')
              .select('id,pot_id,inviter_user_id,invitee_user_id,invitee_identifier,role,status,message,responded_at,expires_at,metadata,created_at, users!shared_pot_invitations_invitee_user_id_fkey(id, full_name, email, phone)')
              .eq('pot_id', pot.id)
              .order('created_at', { ascending: false });
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data: { invitations: data || [] } });
      } catch (e: any) {
          res.status(e.message === 'SHARED_POT_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/shared-pot-invitations', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { data, error } = await sb
              .from('shared_pot_invitations')
              .select('id,pot_id,inviter_user_id,invitee_user_id,invitee_identifier,role,status,message,responded_at,expires_at,metadata,created_at, shared_pots!shared_pot_invitations_pot_id_fkey(id, name, purpose, currency, target_amount, current_amount, status), users!shared_pot_invitations_inviter_user_id_fkey(id, full_name, email, phone)')
              .eq('invitee_user_id', session.sub)
              .order('created_at', { ascending: false });
          if (error) return res.status(400).json({ success: false, error: error.message });

          const invitations = [];
          for (const invite of data || []) {
              invitations.push(await expireSharedPotInvitationIfNeeded(sb, invite));
          }
          res.json({ success: true, data: { invitations } });
      } catch (e: any) {
          res.status(400).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/shared-pots/:id/invitations', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedPotMemberAddSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { pot, membership } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
          if (!canManageSharedPot(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_POT_ACCESS_DENIED' });
          }
          const memberUser = await resolveUserBySharedPotIdentifier(sb, payload.identifier);
          if (!memberUser?.id) {
              return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
          }
          if (String(memberUser.id) === String(pot.owner_user_id)) {
              return res.status(400).json({ success: false, error: 'OWNER_ALREADY_MEMBER' });
          }
          const { data: existingMember, error: existingMemberError } = await sb
              .from('shared_pot_members')
              .select('id')
              .eq('pot_id', pot.id)
              .eq('user_id', memberUser.id)
              .maybeSingle();
          if (existingMemberError) {
              return res.status(400).json({ success: false, error: existingMemberError.message });
          }
          if (existingMember) {
              return res.status(400).json({ success: false, error: 'SHARED_POT_MEMBER_ALREADY_EXISTS' });
          }

          const { data: pendingInvite, error: pendingInviteError } = await sb
              .from('shared_pot_invitations')
              .select('*')
              .eq('pot_id', pot.id)
              .eq('invitee_user_id', memberUser.id)
              .eq('status', 'PENDING')
              .order('created_at', { ascending: false })
              .limit(1)
              .single();
          if (pendingInviteError && pendingInviteError.code !== 'PGRST116') {
              return res.status(400).json({ success: false, error: pendingInviteError.message });
          }
          if (pendingInvite) {
              return res.status(400).json({ success: false, error: 'SHARED_POT_INVITE_ALREADY_PENDING' });
          }

          const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
          const { data, error } = await sb
              .from('shared_pot_invitations')
              .insert({
                  pot_id: pot.id,
                  inviter_user_id: session.sub,
                  invitee_user_id: memberUser.id,
                  invitee_identifier: payload.identifier,
                  role: payload.role || 'CONTRIBUTOR',
                  message: payload.message || null,
                  expires_at: expiresAt,
                  metadata: {
                      invited_by: session.sub,
                      invite_source: 'shared_pot_member_sheet',
                      identifier: payload.identifier,
                  },
              })
              .select('id,pot_id,inviter_user_id,invitee_user_id,invitee_identifier,role,status,message,responded_at,expires_at,metadata,created_at')
              .single();
          if (error) return res.status(400).json({ success: false, error: error.message });

          await Messaging.dispatch(
              String(memberUser.id),
              'info',
              'Shared pot invitation',
              `${session.user?.user_metadata?.full_name || 'A member'} invited you to join "${pot.name}" as ${String(payload.role || 'CONTRIBUTOR').toLowerCase()}.`,
              {
                  push: true,
                  sms: false,
                  email: true,
                  eventCode: 'SHARED_POT_INVITATION',
                  variables: {
                      pot_name: pot.name,
                      role: payload.role || 'CONTRIBUTOR',
                      invite_id: data.id,
                  },
              },
          );

          res.json({
              success: true,
              data: {
                  invitation: {
                      ...data,
                      invitee: {
                          id: memberUser.id,
                          full_name: memberUser.full_name,
                          email: memberUser.email,
                          phone: memberUser.phone,
                      },
                  },
              },
          });
      } catch (e: any) {
          res.status(e.message === 'SHARED_POT_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/shared-pot-invitations/:id/respond', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedPotInviteResponseSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

          const { data: inviteRaw, error: inviteError } = await sb
              .from('shared_pot_invitations')
              .select('*')
              .eq('id', req.params.id)
              .maybeSingle();
          if (inviteError) return res.status(400).json({ success: false, error: inviteError.message });
          if (!inviteRaw) return res.status(404).json({ success: false, error: 'SHARED_POT_INVITE_NOT_FOUND' });
          const invite = await expireSharedPotInvitationIfNeeded(sb, inviteRaw);

          if (String(invite.invitee_user_id || '') !== String(session.sub)) {
              return res.status(403).json({ success: false, error: 'SHARED_POT_INVITE_ACCESS_DENIED' });
          }
          if (String(invite.status || '').toUpperCase() !== 'PENDING') {
              return res.status(400).json({ success: false, error: 'SHARED_POT_INVITE_NOT_PENDING' });
          }

          if (payload.action === 'REJECT') {
              const { data, error } = await sb
                  .from('shared_pot_invitations')
                  .update({
                      status: 'REJECTED',
                      responded_at: new Date().toISOString(),
                      updated_at: new Date().toISOString(),
                  })
                  .eq('id', invite.id)
                  .select('*')
                  .single();
              if (error) return res.status(400).json({ success: false, error: error.message });
              return res.json({ success: true, data: { invitation: data } });
          }

          const { data: existingMember, error: existingMemberError } = await sb
              .from('shared_pot_members')
              .select('id')
              .eq('pot_id', invite.pot_id)
              .eq('user_id', session.sub)
              .maybeSingle();
          if (existingMemberError) return res.status(400).json({ success: false, error: existingMemberError.message });
          if (existingMember) {
              return res.status(400).json({ success: false, error: 'SHARED_POT_MEMBER_ALREADY_EXISTS' });
          }

          const { data: member, error: memberError } = await sb
              .from('shared_pot_members')
              .insert({
                  pot_id: invite.pot_id,
                  user_id: session.sub,
                  role: invite.role || 'CONTRIBUTOR',
                  contributed_amount: 0,
                  metadata: {
                      joined_via_invitation: invite.id,
                      invited_by: invite.inviter_user_id,
                  },
              })
              .select('*')
              .single();
          if (memberError) return res.status(400).json({ success: false, error: memberError.message });

          const { data: updatedInvite, error: updateInviteError } = await sb
              .from('shared_pot_invitations')
              .update({
                  status: 'ACCEPTED',
                  responded_at: new Date().toISOString(),
                  updated_at: new Date().toISOString(),
              })
              .eq('id', invite.id)
              .select('*')
              .single();
          if (updateInviteError) return res.status(400).json({ success: false, error: updateInviteError.message });

          res.json({ success: true, data: { invitation: updatedInvite, member } });
      } catch (e: any) {
          const status = e.message === 'SHARED_POT_INVITE_ACCESS_DENIED' ? 403 : 400;
          res.status(status).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/shared-pots/:id/contribute', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedPotContributionSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { pot, membership } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
          if (!canContributeToSharedPot(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_POT_CONTRIBUTION_DENIED' });
          }

          const { sourceRecord, sourceTable } = await resolveWealthSourceWallet(
              sb,
              session.sub,
              payload.source_wallet_id,
          );
          const currentBalance = wealthNumber(sourceRecord.balance);
          if (currentBalance < payload.amount) {
              return res.status(400).json({ success: false, error: 'INSUFFICIENT_FUNDS' });
          }

          const newSourceBalance = currentBalance - payload.amount;
          const newPotBalance = wealthNumber(pot.current_amount) + payload.amount;
          const reference = `pot_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;

          const { data: tx, error: txError } = await sb
              .from('transactions')
              .insert({
                  reference_id: reference,
                  user_id: session.sub,
                  wallet_id: sourceRecord.id,
                  amount: String(payload.amount),
                  currency: String(pot.currency || sourceRecord.currency || 'TZS').toUpperCase(),
                  description: `Shared pot contribution: ${pot.name}`,
                  type: 'internal_transfer',
                  status: 'completed',
                  wealth_impact_type: 'GROWING',
                  protection_state: 'OPEN',
                  allocation_source: 'SHARED_POT_CONTRIBUTION',
                  metadata: {
                      shared_pot_id: pot.id,
                      member_role: membership.role,
                      source_table: sourceTable,
                      source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
                  },
              })
              .select('*')
              .single();
          if (txError || !tx) {
              return res.status(400).json({ success: false, error: txError?.message || 'TX_CREATE_FAILED' });
          }

          const { error: walletUpdateError } = await sb
              .from(sourceTable)
              .update({
                  balance: newSourceBalance,
                  updated_at: new Date().toISOString(),
              })
              .eq('id', sourceRecord.id)
              .eq('user_id', session.sub);
          if (walletUpdateError) {
              return res.status(400).json({ success: false, error: walletUpdateError.message });
          }

          const { error: potUpdateError } = await sb
              .from('shared_pots')
              .update({
                  current_amount: newPotBalance,
                  updated_at: new Date().toISOString(),
              })
              .eq('id', pot.id);
          if (potUpdateError) {
              return res.status(400).json({ success: false, error: potUpdateError.message });
          }

          const ledgerRows = [
              {
                  transaction_id: tx.id,
                  user_id: session.sub,
                  wallet_id: sourceRecord.id,
                  shared_pot_id: pot.id,
                  bucket_type: 'OPERATING',
                  entry_side: 'DEBIT',
                  entry_type: 'DEBIT',
                  amount: String(payload.amount),
                  balance_after: String(newSourceBalance),
                  description: `Shared pot contribution debit: ${pot.name}`,
              },
              {
                  transaction_id: tx.id,
                  user_id: session.sub,
                  wallet_id: sourceRecord.id,
                  shared_pot_id: pot.id,
                  bucket_type: 'GROWING',
                  entry_side: 'CREDIT',
                  entry_type: 'CREDIT',
                  amount: String(payload.amount),
                  balance_after: String(newPotBalance),
                  description: `Shared pot contribution credit: ${pot.name}`,
              },
          ];
          const { error: ledgerError } = await sb.from('financial_ledger').insert(ledgerRows);
          if (ledgerError) {
              return res.status(400).json({ success: false, error: ledgerError.message });
          }

          res.json({
              success: true,
              data: {
                  transaction: tx,
                  shared_pot: { ...pot, current_amount: newPotBalance },
                  source_balance: newSourceBalance,
              },
          });
      } catch (e: any) {
          res.status(
              ['SHARED_POT_ACCESS_DENIED', 'SHARED_POT_CONTRIBUTION_DENIED'].includes(e.message) ? 403 : 400,
          ).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/shared-pots/:id/withdraw', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedPotWithdrawSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { pot, membership } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
          if (!canManageSharedPot(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_POT_WITHDRAW_DENIED' });
          }
          const currentPotBalance = wealthNumber(pot.current_amount);
          if (currentPotBalance < payload.amount) {
              return res.status(400).json({ success: false, error: 'INSUFFICIENT_POT_FUNDS' });
          }

          const { sourceRecord: targetRecord, sourceTable: targetTable } = await resolveWealthSourceWallet(
              sb,
              session.sub,
              payload.target_wallet_id,
          );
          const targetBalance = wealthNumber(targetRecord.balance);
          const newTargetBalance = targetBalance + payload.amount;
          const newPotBalance = currentPotBalance - payload.amount;
          const reference = `pot_w_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;

          const { data: tx, error: txError } = await sb
              .from('transactions')
              .insert({
                  reference_id: reference,
                  user_id: session.sub,
                  wallet_id: targetRecord.id,
                  amount: String(payload.amount),
                  currency: String(pot.currency || targetRecord.currency || 'TZS').toUpperCase(),
                  description: `Shared pot withdrawal: ${pot.name}`,
                  type: 'internal_transfer',
                  status: 'completed',
                  wealth_impact_type: 'GROWING',
                  protection_state: 'OPEN',
                  allocation_source: 'SHARED_POT_WITHDRAWAL',
                  metadata: {
                      shared_pot_id: pot.id,
                      actor_role: membership.role,
                      target_table: targetTable,
                      target_wallet_role: targetRecord.vault_role || targetRecord.type || null,
                  },
              })
              .select('*')
              .single();
          if (txError || !tx) {
              return res.status(400).json({ success: false, error: txError?.message || 'TX_CREATE_FAILED' });
          }

          const { error: walletUpdateError } = await sb
              .from(targetTable)
              .update({
                  balance: newTargetBalance,
                  updated_at: new Date().toISOString(),
              })
              .eq('id', targetRecord.id)
              .eq('user_id', session.sub);
          if (walletUpdateError) {
              return res.status(400).json({ success: false, error: walletUpdateError.message });
          }

          const { error: potUpdateError } = await sb
              .from('shared_pots')
              .update({
                  current_amount: newPotBalance,
                  updated_at: new Date().toISOString(),
              })
              .eq('id', pot.id);
          if (potUpdateError) {
              return res.status(400).json({ success: false, error: potUpdateError.message });
          }

          const existingMemberContribution = wealthNumber(
              membership.contributed_amount || 0,
          );
          const { error: memberUpdateError } = await sb
              .from('shared_pot_members')
              .upsert({
                  pot_id: pot.id,
                  user_id: session.sub,
                  role: membership.role || 'CONTRIBUTOR',
                  contributed_amount: existingMemberContribution + payload.amount,
                  metadata: membership.metadata || {},
              }, {
                  onConflict: 'pot_id,user_id',
              });
          if (memberUpdateError) {
              return res.status(400).json({ success: false, error: memberUpdateError.message });
          }

          const ledgerRows = [
              {
                  transaction_id: tx.id,
                  user_id: session.sub,
                  wallet_id: targetRecord.id,
                  shared_pot_id: pot.id,
                  bucket_type: 'GROWING',
                  entry_side: 'DEBIT',
                  entry_type: 'DEBIT',
                  amount: String(payload.amount),
                  balance_after: String(newPotBalance),
                  description: `Shared pot withdrawal debit: ${pot.name}`,
              },
              {
                  transaction_id: tx.id,
                  user_id: session.sub,
                  wallet_id: targetRecord.id,
                  shared_pot_id: pot.id,
                  bucket_type: 'OPERATING',
                  entry_side: 'CREDIT',
                  entry_type: 'CREDIT',
                  amount: String(payload.amount),
                  balance_after: String(newTargetBalance),
                  description: `Shared pot withdrawal credit: ${pot.name}`,
              },
          ];
          const { error: ledgerError } = await sb.from('financial_ledger').insert(ledgerRows);
          if (ledgerError) {
              return res.status(400).json({ success: false, error: ledgerError.message });
          }

          res.json({
              success: true,
              data: {
                  transaction: tx,
                  shared_pot: { ...pot, current_amount: newPotBalance },
                  target_balance: newTargetBalance,
              },
          });
      } catch (e: any) {
          res.status(e.message === 'SHARED_POT_WITHDRAW_DENIED' ? 403 : 400).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/shared-budgets', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { data: memberships, error: memberError } = await sb
              .from('shared_budget_members')
              .select('budget_id, role')
              .eq('user_id', session.sub);
          if (memberError) return res.status(400).json({ success: false, error: memberError.message });

          const memberBudgetIds = Array.from(new Set((memberships || []).map((item: any) => String(item.budget_id || '')).filter(Boolean)));
          let query = sb
              .from('shared_budgets')
              .select('*')
              .eq('owner_user_id', session.sub);
          if (memberBudgetIds.length > 0) {
              query = sb
                  .from('shared_budgets')
                  .select('*')
                  .or([
                      `owner_user_id.eq.${session.sub}`,
                      `id.in.(${memberBudgetIds.join(',')})`,
                  ].join(','));
          }
          const { data, error } = await query.order('created_at', { ascending: false });
          if (error) return res.status(400).json({ success: false, error: error.message });
          const membershipByBudget = new Map(
              (memberships || []).map((item: any) => [String(item.budget_id), String(item.role || 'SPENDER').toUpperCase()]),
          );
          const items = (data || []).map((budget: any) => ({
              ...budget,
              my_role: budget.owner_user_id === session.sub
                  ? 'OWNER'
                  : (membershipByBudget.get(String(budget.id)) || 'SPENDER'),
              is_owner: budget.owner_user_id === session.sub,
              remaining_amount: Math.max(0, wealthNumber(budget.budget_limit) - wealthNumber(budget.spent_amount)),
          }));
          res.json({ success: true, data: { budgets: items } });
      } catch (e: any) {
          res.status(500).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/shared-budgets', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedBudgetCreateSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { data, error } = await sb
              .from('shared_budgets')
              .insert({
                  owner_user_id: session.sub,
                  name: payload.name,
                  purpose: payload.purpose,
                  currency: payload.currency?.toUpperCase() || 'TZS',
                  budget_limit: payload.budget_limit,
                  spent_amount: 0,
                  period_type: payload.period_type || 'MONTHLY',
                  approval_mode: payload.approval_mode || 'AUTO',
                  status: 'ACTIVE',
                  metadata: { created_from: 'mobile_app' },
              })
              .select('*')
              .single();
          if (error) return res.status(400).json({ success: false, error: error.message });
          await sb.from('shared_budget_members').insert({
              budget_id: data.id,
              user_id: session.sub,
              role: 'OWNER',
              spent_amount: 0,
          });
          res.json({ success: true, data });
      } catch (e: any) {
          res.status(400).json({ success: false, error: e.message });
      }
  });

  v1.patch('/wealth/shared-budgets/:id', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedBudgetUpdateSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
          if (!canManageSharedBudget(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
          }
          const updatePayload: any = { updated_at: new Date().toISOString() };
          if (payload.name !== undefined) updatePayload.name = payload.name;
          if (payload.purpose !== undefined) updatePayload.purpose = payload.purpose;
          if (payload.currency !== undefined) updatePayload.currency = payload.currency.toUpperCase();
          if (payload.budget_limit !== undefined) updatePayload.budget_limit = payload.budget_limit;
          if (payload.period_type !== undefined) updatePayload.period_type = payload.period_type;
          if (payload.approval_mode !== undefined) updatePayload.approval_mode = payload.approval_mode;
          if (payload.status !== undefined) updatePayload.status = payload.status;
          const { data, error } = await sb
              .from('shared_budgets')
              .update(updatePayload)
              .eq('id', req.params.id)
              .select('*')
              .single();
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data });
      } catch (e: any) {
          res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/shared-budgets/:id/members', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { budget } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
          const { data, error } = await sb
              .from('shared_budget_members')
              .select('id,budget_id,user_id,role,status,member_limit,spent_amount,metadata,created_at, users!shared_budget_members_user_id_fkey(id, full_name, email, phone)')
              .eq('budget_id', budget.id)
              .order('created_at', { ascending: true });
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data: { members: data || [] } });
      } catch (e: any) {
          res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/shared-budgets/:id/transactions', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { budget } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
          const { data, error } = await sb
              .from('shared_budget_transactions')
              .select('*, users!shared_budget_transactions_member_user_id_fkey(id, full_name, email, phone)')
              .eq('shared_budget_id', budget.id)
              .order('created_at', { ascending: false });
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data: { transactions: data || [] } });
      } catch (e: any) {
          res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/shared-budgets/:id/invitations', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
          if (!canManageSharedBudget(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
          }
          const { data, error } = await sb
              .from('shared_budget_invitations')
              .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at, users!shared_budget_invitations_invitee_user_id_fkey(id, full_name, email, phone)')
              .eq('budget_id', budget.id)
              .order('created_at', { ascending: false });
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data: { invitations: data || [] } });
      } catch (e: any) {
          res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/shared-budget-invitations', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { data, error } = await sb
              .from('shared_budget_invitations')
              .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at, shared_budgets!shared_budget_invitations_budget_id_fkey(id, name, purpose, currency, budget_limit, spent_amount, period_type, approval_mode, status), users!shared_budget_invitations_inviter_user_id_fkey(id, full_name, email, phone)')
              .eq('invitee_user_id', session.sub)
              .order('created_at', { ascending: false });
          if (error) return res.status(400).json({ success: false, error: error.message });
          const invitations = [];
          for (const invite of data || []) {
              invitations.push(await expireSharedBudgetInvitationIfNeeded(sb, invite));
          }
          res.json({ success: true, data: { invitations } });
      } catch (e: any) {
          res.status(400).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/shared-budgets/:id/invitations', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedBudgetMemberAddSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
          if (!canManageSharedBudget(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
          }
          const memberUser = await resolveUserBySharedBudgetIdentifier(sb, payload.identifier);
          if (!memberUser?.id) {
              return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
          }
          if (String(memberUser.id) === String(budget.owner_user_id)) {
              return res.status(400).json({ success: false, error: 'OWNER_ALREADY_MEMBER' });
          }
          const { data: existingMember, error: existingMemberError } = await sb
              .from('shared_budget_members')
              .select('id')
              .eq('budget_id', budget.id)
              .eq('user_id', memberUser.id)
              .maybeSingle();
          if (existingMemberError) return res.status(400).json({ success: false, error: existingMemberError.message });
          if (existingMember) {
              return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_ALREADY_EXISTS' });
          }
          const { data: pendingInvite, error: pendingInviteError } = await sb
              .from('shared_budget_invitations')
              .select('*')
              .eq('budget_id', budget.id)
              .eq('invitee_user_id', memberUser.id)
              .eq('status', 'PENDING')
              .order('created_at', { ascending: false })
              .limit(1)
              .single();
          if (pendingInviteError && pendingInviteError.code !== 'PGRST116') {
              return res.status(400).json({ success: false, error: pendingInviteError.message });
          }
          if (pendingInvite) {
              return res.status(400).json({ success: false, error: 'SHARED_BUDGET_INVITE_ALREADY_PENDING' });
          }

          const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
          const { data, error } = await sb
              .from('shared_budget_invitations')
              .insert({
                  budget_id: budget.id,
                  inviter_user_id: session.sub,
                  invitee_user_id: memberUser.id,
                  invitee_identifier: payload.identifier,
                  role: payload.role || 'SPENDER',
                  member_limit: payload.member_limit || null,
                  message: payload.message || null,
                  expires_at: expiresAt,
                  metadata: {
                      invited_by: session.sub,
                      invite_source: 'shared_budget_member_sheet',
                      identifier: payload.identifier,
                  },
              })
              .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at')
              .single();
          if (error) return res.status(400).json({ success: false, error: error.message });

          await Messaging.dispatch(
              String(memberUser.id),
              'info',
              'Shared budget invitation',
              `${session.user?.user_metadata?.full_name || 'A member'} invited you to join "${budget.name}" as ${String(payload.role || 'SPENDER').toLowerCase()}.`,
              {
                  push: true,
                  sms: false,
                  email: true,
                  eventCode: 'SHARED_BUDGET_INVITATION',
                  variables: {
                      budget_name: budget.name,
                      role: payload.role || 'SPENDER',
                      invite_id: data.id,
                  },
              },
          );

          res.json({ success: true, data: { invitation: data } });
      } catch (e: any) {
          res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/shared-budget-invitations/:id/respond', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedBudgetInviteResponseSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

          const { data: inviteRaw, error: inviteError } = await sb
              .from('shared_budget_invitations')
              .select('*')
              .eq('id', req.params.id)
              .maybeSingle();
          if (inviteError) return res.status(400).json({ success: false, error: inviteError.message });
          if (!inviteRaw) return res.status(404).json({ success: false, error: 'SHARED_BUDGET_INVITE_NOT_FOUND' });
          const invite = await expireSharedBudgetInvitationIfNeeded(sb, inviteRaw);

          if (String(invite.invitee_user_id || '') !== String(session.sub)) {
              return res.status(403).json({ success: false, error: 'SHARED_BUDGET_INVITE_ACCESS_DENIED' });
          }
          if (String(invite.status || '').toUpperCase() !== 'PENDING') {
              return res.status(400).json({ success: false, error: 'SHARED_BUDGET_INVITE_NOT_PENDING' });
          }

          if (payload.action === 'REJECT') {
              const { data, error } = await sb
                  .from('shared_budget_invitations')
                  .update({
                      status: 'REJECTED',
                      responded_at: new Date().toISOString(),
                      updated_at: new Date().toISOString(),
                  })
                  .eq('id', invite.id)
                  .select('*')
                  .single();
              if (error) return res.status(400).json({ success: false, error: error.message });
              return res.json({ success: true, data: { invitation: data } });
          }

          const { data: existingMember, error: existingMemberError } = await sb
              .from('shared_budget_members')
              .select('id')
              .eq('budget_id', invite.budget_id)
              .eq('user_id', session.sub)
              .maybeSingle();
          if (existingMemberError) return res.status(400).json({ success: false, error: existingMemberError.message });
          if (existingMember) {
              return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_ALREADY_EXISTS' });
          }

          const { data: member, error: memberError } = await sb
              .from('shared_budget_members')
              .insert({
                  budget_id: invite.budget_id,
                  user_id: session.sub,
                  role: invite.role || 'SPENDER',
                  status: 'ACTIVE',
                  member_limit: invite.member_limit || null,
                  spent_amount: 0,
                  metadata: {
                      joined_via_invitation: invite.id,
                      invited_by: invite.inviter_user_id,
                  },
              })
              .select('*')
              .single();
          if (memberError) return res.status(400).json({ success: false, error: memberError.message });

          const { data: updatedInvite, error: updateInviteError } = await sb
              .from('shared_budget_invitations')
              .update({
                  status: 'ACCEPTED',
                  responded_at: new Date().toISOString(),
                  updated_at: new Date().toISOString(),
              })
              .eq('id', invite.id)
              .select('*')
              .single();
          if (updateInviteError) return res.status(400).json({ success: false, error: updateInviteError.message });

          res.json({ success: true, data: { invitation: updatedInvite, member } });
      } catch (e: any) {
          const status = e.message === 'SHARED_BUDGET_INVITE_ACCESS_DENIED' ? 403 : 400;
          res.status(status).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/shared-budgets/:id/approvals', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
          if (!canReviewSharedBudgetSpend(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
          }
          const { data, error } = await sb
              .from('shared_budget_approvals')
              .select('*, users!shared_budget_approvals_requester_user_id_fkey(id, full_name, email, phone), reviewer:users!shared_budget_approvals_reviewer_user_id_fkey(id, full_name, email, phone)')
              .eq('shared_budget_id', budget.id)
              .order('created_at', { ascending: false });
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data: { approvals: data || [] } });
      } catch (e: any) {
          const status = e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400;
          res.status(status).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/shared-budget-approvals/:id/respond', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedBudgetApprovalResponseSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

          const { data: approval, error: approvalError } = await sb
              .from('shared_budget_approvals')
              .select('*')
              .eq('id', req.params.id)
              .maybeSingle();
          if (approvalError) return res.status(400).json({ success: false, error: approvalError.message });
          if (!approval) return res.status(404).json({ success: false, error: 'SHARED_BUDGET_APPROVAL_NOT_FOUND' });
          if (String(approval.status || '').toUpperCase() !== 'PENDING') {
              return res.status(400).json({ success: false, error: 'SHARED_BUDGET_APPROVAL_NOT_PENDING' });
          }

          const { budget, membership } = await resolveSharedBudgetMembership(sb, approval.shared_budget_id, session.sub);
          if (!canReviewSharedBudgetSpend(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
          }

          if (payload.action === 'REJECT') {
              const { data, error } = await sb
                  .from('shared_budget_approvals')
                  .update({
                      status: 'REJECTED',
                      reviewer_user_id: session.sub,
                      responded_at: new Date().toISOString(),
                      updated_at: new Date().toISOString(),
                      note: payload.note ?? approval.note ?? null,
                  })
                  .eq('id', approval.id)
                  .select('*')
                  .single();
              if (error) return res.status(400).json({ success: false, error: error.message });
              return res.json({ success: true, data: { approval: data } });
          }

          const requesterMembershipResult = await resolveSharedBudgetMembership(
              sb,
              approval.shared_budget_id,
              String(approval.requester_user_id),
          );

          const approvalMetadata = approval.metadata && typeof approval.metadata === 'object'
              ? approval.metadata
              : {};

          const spendPayload = {
              source_wallet_id: approvalMetadata.source_wallet_id || null,
              amount: wealthNumber(approval.amount),
              currency: approval.currency || budget.currency || 'TZS',
              provider: approval.provider || null,
              bill_category: approval.bill_category || null,
              reference: approval.reference || null,
              description: approval.note || null,
              type: approvalMetadata.type || 'EXTERNAL_PAYMENT',
              metadata: {
                  ...approvalMetadata,
                  approval_reviewer_user_id: session.sub,
                  approval_reviewer_role: membership.role || 'MANAGER',
                  approval_response_note: payload.note || null,
              },
          };

          const spendData = await executeSharedBudgetSpend(sb, {
              budget,
              membership: requesterMembershipResult.membership,
              actorUserId: String(approval.requester_user_id),
              actorUser: {
                  ...(session.user || {}),
                  id: String(approval.requester_user_id),
              },
              payload: spendPayload,
              approvalId: approval.id,
          });

          const transactionId = (spendData as any)?.transaction?.internalId || (spendData as any)?.transaction?.id || null;
          const { data: updatedApproval, error: approvalUpdateError } = await sb
              .from('shared_budget_approvals')
              .update({
                  status: 'APPROVED',
                  reviewer_user_id: session.sub,
                  responded_at: new Date().toISOString(),
                  updated_at: new Date().toISOString(),
                  metadata: {
                      ...approvalMetadata,
                      approved_transaction_id: transactionId,
                      approval_response_note: payload.note || null,
                  },
              })
              .eq('id', approval.id)
              .select('*')
              .single();
          if (approvalUpdateError) return res.status(400).json({ success: false, error: approvalUpdateError.message });

          res.json({ success: true, data: { approval: updatedApproval, ...spendData } });
      } catch (e: any) {
          const status = e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400;
          res.status(status).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/shared-budgets/:id/spend/preview', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedBudgetSpendSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
          if (!canSpendFromSharedBudget(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_BUDGET_SPEND_DENIED' });
          }
          const currentSpent = wealthNumber(budget.spent_amount);
          const budgetLimit = wealthNumber(budget.budget_limit);
          if (currentSpent + payload.amount > budgetLimit) {
              return res.status(400).json({ success: false, error: 'SHARED_BUDGET_LIMIT_EXCEEDED' });
          }
          const memberSpent = wealthNumber(membership.spent_amount || 0);
          const memberLimit = payload.amount + memberSpent;
          if (membership.member_limit && memberLimit > wealthNumber(membership.member_limit)) {
              return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_LIMIT_EXCEEDED' });
          }

          const result = await LogicCore.getTransactionPreview(session.sub, {
              sourceWalletId: payload.source_wallet_id,
              recipientId: payload.provider,
              amount: payload.amount,
              currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
              description: payload.description || `${budget.name} spend`,
              type: payload.type || 'EXTERNAL_PAYMENT',
              metadata: {
                  ...(payload.metadata || {}),
                  shared_budget_id: budget.id,
                  shared_budget_name: budget.name,
                  shared_budget_role: membership.role || 'SPENDER',
                  bill_provider: payload.provider || null,
                  bill_category: payload.bill_category || null,
                  bill_reference: payload.reference || null,
                  shared_budget_preview: true,
                  spend_origin: 'SHARED_BUDGET',
                  spend_type: payload.type || 'EXTERNAL_PAYMENT',
              },
              dryRun: true,
          });
          if (!result.success) return res.status(400).json(result);
          res.json({
              success: true,
              data: {
                  preview: result,
                  budget: {
                      ...budget,
                      remaining_amount: Math.max(0, budgetLimit - currentSpent - payload.amount),
                  },
                  member: {
                      ...membership,
                      remaining_member_limit: membership.member_limit
                          ? Math.max(0, wealthNumber(membership.member_limit) - memberSpent - payload.amount)
                          : null,
                  },
              },
          });
      } catch (e: any) {
          const status = e.message === 'SHARED_BUDGET_SPEND_DENIED' ? 403 : 400;
          res.status(status).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/shared-budgets/:id/spend/settle', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = SharedBudgetSpendSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
          if (!canSpendFromSharedBudget(String(membership.role || ''))) {
              return res.status(403).json({ success: false, error: 'SHARED_BUDGET_SPEND_DENIED' });
          }
          const currentSpent = wealthNumber(budget.spent_amount);
          const budgetLimit = wealthNumber(budget.budget_limit);
          if (currentSpent + payload.amount > budgetLimit) {
              return res.status(400).json({ success: false, error: 'SHARED_BUDGET_LIMIT_EXCEEDED' });
          }
          const memberSpent = wealthNumber(membership.spent_amount || 0);
          if (membership.member_limit && memberSpent + payload.amount > wealthNumber(membership.member_limit)) {
              return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_LIMIT_EXCEEDED' });
          }
          if (String(budget.approval_mode || 'AUTO').toUpperCase() === 'REVIEW') {
              const { data, error } = await sb
                  .from('shared_budget_approvals')
                  .insert({
                      shared_budget_id: budget.id,
                      requester_user_id: session.sub,
                      amount: payload.amount,
                      currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
                      provider: payload.provider || null,
                      bill_category: payload.bill_category || null,
                      reference: payload.reference || null,
                      note: payload.description || null,
                      status: 'PENDING',
                      metadata: {
                          ...(payload.metadata || {}),
                          source_wallet_id: payload.source_wallet_id || null,
                          type: payload.type || 'EXTERNAL_PAYMENT',
                          shared_budget_name: budget.name,
                          requester_role: membership.role || 'SPENDER',
                          spend_origin: 'SHARED_BUDGET',
                          bill_provider: payload.provider || null,
                          bill_category: payload.bill_category || null,
                          bill_reference: payload.reference || null,
                          preview_required: true,
                      },
                  })
                  .select('*')
                  .single();
              if (error) return res.status(400).json({ success: false, error: error.message });
              return res.json({ success: true, data: { approval: data, requires_approval: true } });
          }

          const data = await executeSharedBudgetSpend(sb, {
              budget,
              membership,
              actorUserId: session.sub,
              actorUser: session.user,
              payload,
          });
          res.json({ success: true, data });
      } catch (e: any) {
          const status = e.message === 'SHARED_BUDGET_SPEND_DENIED' ? 403 : 400;
          res.status(status).json({ success: false, error: e.message });
      }
  });

  v1.get('/wealth/allocation-rules', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { data, error } = await sb
              .from('allocation_rules')
              .select('*')
              .eq('user_id', session.sub)
              .order('priority', { ascending: true })
              .order('created_at', { ascending: false });
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data: { rules: data || [] } });
      } catch (e: any) {
          res.status(500).json({ success: false, error: e.message });
      }
  });

  v1.post('/wealth/allocation-rules', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = AllocationRuleCreateSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const { data, error } = await sb
              .from('allocation_rules')
              .insert({
                  user_id: session.sub,
                  name: payload.name,
                  trigger_type: payload.trigger_type,
                  source_wallet_id: payload.source_wallet_id,
                  target_type: payload.target_type,
                  target_id: payload.target_id,
                  mode: payload.mode,
                  fixed_amount: payload.fixed_amount,
                  percentage: payload.percentage,
                  priority: payload.priority || 1,
                  is_active: true,
                  metadata: { created_from: 'mobile_app' },
              })
              .select('*')
              .single();
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data });
      } catch (e: any) {
          res.status(400).json({ success: false, error: e.message });
      }
  });

  v1.patch('/wealth/allocation-rules/:id', authenticate as any, async (req, res) => {
      const session = (req as any).session;
      try {
          const payload = AllocationRuleUpdateSchema.parse(req.body);
          const sb = getAdminSupabase() || getSupabase();
          if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
          const updatePayload: any = {
              updated_at: new Date().toISOString(),
          };
          if (payload.name !== undefined) updatePayload.name = payload.name;
          if (payload.trigger_type !== undefined) updatePayload.trigger_type = payload.trigger_type;
          if (payload.source_wallet_id !== undefined) updatePayload.source_wallet_id = payload.source_wallet_id;
          if (payload.target_type !== undefined) updatePayload.target_type = payload.target_type;
          if (payload.target_id !== undefined) updatePayload.target_id = payload.target_id;
          if (payload.mode !== undefined) updatePayload.mode = payload.mode;
          if (payload.fixed_amount !== undefined) updatePayload.fixed_amount = payload.fixed_amount;
          if (payload.percentage !== undefined) updatePayload.percentage = payload.percentage;
          if (payload.priority !== undefined) updatePayload.priority = payload.priority;
          if (payload.is_active !== undefined) updatePayload.is_active = payload.is_active;
          const { data, error } = await sb
              .from('allocation_rules')
              .update(updatePayload)
              .eq('id', req.params.id)
              .eq('user_id', session.sub)
              .select('*')
              .single();
          if (error) return res.status(400).json({ success: false, error: error.message });
          res.json({ success: true, data });
      } catch (e: any) {
          res.status(400).json({ success: false, error: e.message });
      }
  });
};
