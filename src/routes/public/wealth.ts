import { type RequestHandler, type Router } from 'express';
import { z } from 'zod';
import {
  wealthNumber,
  resolveWealthSourceWallet,
  assertBillPaymentSourceAllowed,
} from './wealthShared.js';
import {
  resolveSharedPotMembership,
  canManageSharedPot,
  canContributeToSharedPot,
  resolveUserBySharedPotIdentifier,
  expireSharedPotInvitationIfNeeded,
  resolveSharedBudgetMembership,
  canManageSharedBudget,
  canSpendFromSharedBudget,
  canReviewSharedBudgetSpend,
  resolveUserBySharedBudgetIdentifier,
  expireSharedBudgetInvitationIfNeeded,
  createSharedBudgetSpendExecutor,
} from './wealthCollab.js';
import {
  updateWealthSourceBalance,
  createWealthTransaction,
  insertBillReserveLedger,
} from './wealthBillReserve.js';
import { registerBillReserveRoutes } from './wealthBillReserveRoutes.js';
import { registerSharedPotRoutes } from './wealthSharedPotRoutes.js';
import { registerSharedBudgetRoutes } from './wealthSharedBudgetRoutes.js';
import { registerAllocationRoutes } from './wealthAllocationRoutes.js';

type Deps = {
  authenticate: RequestHandler;
  LogicCore: any;
  getSupabase: () => any;
  getAdminSupabase: () => any;
};

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

export const registerWealthRoutes = (v1: Router, deps: Deps) => {
  const { authenticate, LogicCore, getSupabase, getAdminSupabase } = deps;
  const executeSharedBudgetSpend = createSharedBudgetSpendExecutor(LogicCore);

  registerBillReserveRoutes(v1, {
    authenticate,
    getSupabase,
    getAdminSupabase,
    BillReserveCreateSchema,
    BillReserveUpdateSchema,
    wealthNumber,
    resolveWealthSourceWallet,
    assertBillPaymentSourceAllowed,
    createWealthTransaction,
    updateWealthSourceBalance,
    insertBillReserveLedger,
  });

  registerSharedPotRoutes(v1, {
    authenticate,
    getSupabase,
    getAdminSupabase,
    SharedPotCreateSchema,
    SharedPotUpdateSchema,
    SharedPotMemberAddSchema,
    SharedPotInviteResponseSchema,
    SharedPotContributionSchema,
    SharedPotWithdrawSchema,
    wealthNumber,
    resolveWealthSourceWallet,
    resolveSharedPotMembership,
    canManageSharedPot,
    canContributeToSharedPot,
    resolveUserBySharedPotIdentifier,
    expireSharedPotInvitationIfNeeded,
  });

  registerSharedBudgetRoutes(v1, {
    authenticate,
    LogicCore,
    getSupabase,
    getAdminSupabase,
    SharedBudgetCreateSchema,
    SharedBudgetUpdateSchema,
    SharedBudgetMemberAddSchema,
    SharedBudgetInviteResponseSchema,
    SharedBudgetApprovalResponseSchema,
    SharedBudgetSpendSchema,
    wealthNumber,
    resolveSharedBudgetMembership,
    canManageSharedBudget,
    canSpendFromSharedBudget,
    canReviewSharedBudgetSpend,
    resolveUserBySharedBudgetIdentifier,
    expireSharedBudgetInvitationIfNeeded,
    executeSharedBudgetSpend,
  });

  registerAllocationRoutes(v1, {
    authenticate,
    getSupabase,
    getAdminSupabase,
    AllocationRuleCreateSchema,
    AllocationRuleUpdateSchema,
  });

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

};
