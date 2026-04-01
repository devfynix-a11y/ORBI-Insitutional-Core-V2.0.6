import { wealthNumber } from './wealthShared.js';

const normalizeWealthIdentifier = (value: string) => value.trim().toLowerCase();

const normalizeWealthPhone = (value: string) =>
  value
    .trim()
    .replace(/[^\d+]/g, '')
    .replace(/(?!^)\+/g, '');

const isEmailLikeIdentifier = (value: string) => value.includes('@');

export const resolveSharedPotMembership = async (sb: any, potId: string, userId: string) => {
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

export const canManageSharedPot = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());
export const canContributeToSharedPot = (role: string) =>
  ['OWNER', 'MANAGER', 'CONTRIBUTOR'].includes(role.toUpperCase());

export const resolveUserBySharedPotIdentifier = async (sb: any, identifier: string) => {
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

export const expireSharedPotInvitationIfNeeded = async (sb: any, invite: any) => {
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

export const resolveSharedBudgetMembership = async (sb: any, budgetId: string, userId: string) => {
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

export const canManageSharedBudget = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());
export const canSpendFromSharedBudget = (role: string) => ['OWNER', 'MANAGER', 'SPENDER'].includes(role.toUpperCase());
export const canReviewSharedBudgetSpend = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());

export const resolveUserBySharedBudgetIdentifier = async (sb: any, identifier: string) => {
  return resolveUserBySharedPotIdentifier(sb, identifier);
};

export const expireSharedBudgetInvitationIfNeeded = async (sb: any, invite: any) => {
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

export const createSharedBudgetSpendExecutor = (LogicCore: any) => async (
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

  const result = await LogicCore.processSecurePayment({
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
