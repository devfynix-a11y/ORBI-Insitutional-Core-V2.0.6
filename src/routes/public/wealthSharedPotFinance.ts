type ContributeInput = {
  sb: any;
  sessionUserId: string;
  pot: any;
  membership: any;
  payload: any;
  wealthNumber: (value: any) => number;
  resolveWealthSourceWallet: (sb: any, userId: string, sourceWalletId?: string) => Promise<any>;
};

type WithdrawInput = {
  sb: any;
  sessionUserId: string;
  pot: any;
  membership: any;
  payload: any;
  wealthNumber: (value: any) => number;
  resolveWealthSourceWallet: (sb: any, userId: string, sourceWalletId?: string) => Promise<any>;
};

const isMissingRpc = (error: any, fnName: string) => {
  const code = String(error?.code || '');
  const message = String(error?.message || '');
  return code === 'PGRST202' || code === '42883' || message.includes(fnName);
};

const logSharedPotFallback = (
  flow: 'contribute' | 'withdraw',
  sessionUserId: string,
  potId: string,
  error: any,
) => {
  console.warn('[Wealth][SharedPot] Atomic RPC fallback engaged', {
    flow,
    userId: sessionUserId,
    potId,
    code: String(error?.code || ''),
    message: String(error?.message || ''),
  });
};

const contributeViaLegacyPath = async ({
  sb,
  sessionUserId,
  pot,
  membership,
  payload,
  wealthNumber,
  resolveWealthSourceWallet,
}: ContributeInput) => {
  const { sourceRecord, sourceTable } = await resolveWealthSourceWallet(
    sb,
    sessionUserId,
    payload.source_wallet_id,
  );
  const currentBalance = wealthNumber(sourceRecord.balance);
  if (currentBalance < payload.amount) {
    throw new Error('INSUFFICIENT_FUNDS');
  }

  const newSourceBalance = currentBalance - payload.amount;
  const newPotBalance = wealthNumber(pot.current_amount) + payload.amount;
  const reference = `pot_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;

  const { data: tx, error: txError } = await sb
    .from('transactions')
    .insert({
      reference_id: reference,
      user_id: sessionUserId,
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
    throw new Error(txError?.message || 'TX_CREATE_FAILED');
  }

  const { error: walletUpdateError } = await sb
    .from(sourceTable)
    .update({
      balance: newSourceBalance,
      updated_at: new Date().toISOString(),
    })
    .eq('id', sourceRecord.id)
    .eq('user_id', sessionUserId);
  if (walletUpdateError) {
    throw new Error(walletUpdateError.message);
  }

  const { error: potUpdateError } = await sb
    .from('shared_pots')
    .update({
      current_amount: newPotBalance,
      updated_at: new Date().toISOString(),
    })
    .eq('id', pot.id);
  if (potUpdateError) {
    throw new Error(potUpdateError.message);
  }

  const ledgerRows = [
    {
      transaction_id: tx.id,
      user_id: sessionUserId,
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
      user_id: sessionUserId,
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
    throw new Error(ledgerError.message);
  }

  return {
    transaction: tx,
    shared_pot: { ...pot, current_amount: newPotBalance },
    source_balance: newSourceBalance,
  };
};

const withdrawViaLegacyPath = async ({
  sb,
  sessionUserId,
  pot,
  membership,
  payload,
  wealthNumber,
  resolveWealthSourceWallet,
}: WithdrawInput) => {
  const currentPotBalance = wealthNumber(pot.current_amount);
  if (currentPotBalance < payload.amount) {
    throw new Error('INSUFFICIENT_POT_FUNDS');
  }

  const { sourceRecord: targetRecord, sourceTable: targetTable } = await resolveWealthSourceWallet(
    sb,
    sessionUserId,
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
      user_id: sessionUserId,
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
    throw new Error(txError?.message || 'TX_CREATE_FAILED');
  }

  const { error: walletUpdateError } = await sb
    .from(targetTable)
    .update({
      balance: newTargetBalance,
      updated_at: new Date().toISOString(),
    })
    .eq('id', targetRecord.id)
    .eq('user_id', sessionUserId);
  if (walletUpdateError) {
    throw new Error(walletUpdateError.message);
  }

  const { error: potUpdateError } = await sb
    .from('shared_pots')
    .update({
      current_amount: newPotBalance,
      updated_at: new Date().toISOString(),
    })
    .eq('id', pot.id);
  if (potUpdateError) {
    throw new Error(potUpdateError.message);
  }

  const existingMemberContribution = wealthNumber(
    membership.contributed_amount || 0,
  );
  const { error: memberUpdateError } = await sb
    .from('shared_pot_members')
    .upsert({
      pot_id: pot.id,
      user_id: sessionUserId,
      role: membership.role || 'CONTRIBUTOR',
      contributed_amount: existingMemberContribution + payload.amount,
      metadata: membership.metadata || {},
    }, {
      onConflict: 'pot_id,user_id',
    });
  if (memberUpdateError) {
    throw new Error(memberUpdateError.message);
  }

  const ledgerRows = [
    {
      transaction_id: tx.id,
      user_id: sessionUserId,
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
      user_id: sessionUserId,
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
    throw new Error(ledgerError.message);
  }

  return {
    transaction: tx,
    shared_pot: { ...pot, current_amount: newPotBalance },
    target_balance: newTargetBalance,
  };
};

export const contributeToSharedPot = async (input: ContributeInput) => {
  const { sb, sessionUserId, pot, membership, payload, wealthNumber, resolveWealthSourceWallet } = input;
  const { sourceRecord, sourceTable } = await resolveWealthSourceWallet(
    sb,
    sessionUserId,
    payload.source_wallet_id,
  );
  const currentBalance = wealthNumber(sourceRecord.balance);
  if (currentBalance < payload.amount) {
    throw new Error('INSUFFICIENT_FUNDS');
  }

  const reference = `pot_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
  const metadata = {
    shared_pot_id: pot.id,
    member_role: membership.role,
    source_table: sourceTable,
    source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
  };

  const { data, error } = await sb.rpc('shared_pot_contribute_v1', {
    p_user_id: sessionUserId,
    p_pot_id: pot.id,
    p_source_wallet_id: sourceRecord.id,
    p_amount: payload.amount,
    p_currency: String(pot.currency || sourceRecord.currency || 'TZS').toUpperCase(),
    p_description: `Shared pot contribution: ${pot.name}`,
    p_reference_id: reference,
    p_metadata: metadata,
  });

  if (error) {
    if (!isMissingRpc(error, 'shared_pot_contribute_v1')) {
      throw new Error(error.message);
    }
    logSharedPotFallback('contribute', sessionUserId, String(pot.id), error);
    return contributeViaLegacyPath(input);
  }

  const txId = data?.transaction_id || null;
  let transaction = null;
  if (txId) {
    const { data: tx } = await sb
      .from('transactions')
      .select('*')
      .eq('id', txId)
      .maybeSingle();
    transaction = tx || null;
  }

  return {
    transaction,
    shared_pot: { ...pot, current_amount: Number(data?.pot_balance_after ?? pot.current_amount) },
    source_balance: Number(data?.source_balance_after ?? currentBalance),
    atomic_commit: true,
  };
};

export const withdrawFromSharedPot = async (input: WithdrawInput) => {
  const { sb, sessionUserId, pot, membership, payload, wealthNumber, resolveWealthSourceWallet } = input;
  const currentPotBalance = wealthNumber(pot.current_amount);
  if (currentPotBalance < payload.amount) {
    throw new Error('INSUFFICIENT_POT_FUNDS');
  }

  const { sourceRecord: targetRecord, sourceTable: targetTable } = await resolveWealthSourceWallet(
    sb,
    sessionUserId,
    payload.target_wallet_id,
  );
  const reference = `pot_w_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
  const metadata = {
    shared_pot_id: pot.id,
    actor_role: membership.role,
    target_table: targetTable,
    target_wallet_role: targetRecord.vault_role || targetRecord.type || null,
  };

  const { data, error } = await sb.rpc('shared_pot_withdraw_v1', {
    p_user_id: sessionUserId,
    p_pot_id: pot.id,
    p_target_wallet_id: targetRecord.id,
    p_amount: payload.amount,
    p_currency: String(pot.currency || targetRecord.currency || 'TZS').toUpperCase(),
    p_description: `Shared pot withdrawal: ${pot.name}`,
    p_reference_id: reference,
    p_metadata: metadata,
    p_member_role: membership.role || 'CONTRIBUTOR',
    p_member_metadata: membership.metadata || {},
  });

  if (error) {
    if (!isMissingRpc(error, 'shared_pot_withdraw_v1')) {
      throw new Error(error.message);
    }
    logSharedPotFallback('withdraw', sessionUserId, String(pot.id), error);
    return withdrawViaLegacyPath(input);
  }

  const txId = data?.transaction_id || null;
  let transaction = null;
  if (txId) {
    const { data: tx } = await sb
      .from('transactions')
      .select('*')
      .eq('id', txId)
      .maybeSingle();
    transaction = tx || null;
  }

  return {
    transaction,
    shared_pot: { ...pot, current_amount: Number(data?.pot_balance_after ?? pot.current_amount) },
    target_balance: Number(data?.target_balance_after ?? targetRecord.balance),
    atomic_commit: true,
  };
};
