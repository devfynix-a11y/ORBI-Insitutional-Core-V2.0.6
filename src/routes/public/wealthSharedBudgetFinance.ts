import { wealthNumber } from './wealthShared.js';

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
