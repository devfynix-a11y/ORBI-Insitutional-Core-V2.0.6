const isMissingRpc = (error: any, functionName: string): boolean => {
  const code = String(error?.code || '');
  const message = String(error?.message || '');
  return code === 'PGRST202' || code === '42883' || message.includes(functionName);
};

const logBillReserveFallback = (
  userId: string,
  reserveId: string,
  action: 'LOCK' | 'RELEASE',
  error: any,
) => {
  console.warn('[Wealth][BillReserve] Atomic RPC fallback engaged', {
    userId,
    reserveId,
    action,
    code: String(error?.code || ''),
    message: String(error?.message || ''),
  });
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
  const isLock = action === 'LOCK';
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

type ApplyBillReserveAdjustmentInput = {
  sb: any;
  userId: string;
  reserveId: string;
  sourceRecord: any;
  sourceTable: 'platform_vaults' | 'wallets';
  amount: number;
  currency: string;
  description: string;
  metadata: Record<string, any>;
  action: 'LOCK' | 'RELEASE';
  reserveBalanceAfter: number;
  transactionType?: string;
  transactionStatus?: string;
};

export const applyBillReserveAdjustment = async (input: ApplyBillReserveAdjustmentInput) => {
  const {
    sb,
    userId,
    reserveId,
    sourceRecord,
    sourceTable,
    amount,
    currency,
    description,
    metadata,
    action,
    reserveBalanceAfter,
    transactionType,
    transactionStatus,
  } = input;

  const sourceBalanceBefore = Number(sourceRecord.balance || 0);
  const sourceBalanceAfter = action === 'LOCK'
    ? sourceBalanceBefore - amount
    : sourceBalanceBefore + amount;

  const { data, error } = await sb.rpc('bill_reserve_adjust_v1', {
    p_user_id: userId,
    p_reserve_id: reserveId,
    p_source_wallet_id: sourceRecord.id,
    p_amount: amount,
    p_action: action,
    p_currency: currency,
    p_description: description,
    p_metadata: {
      ...metadata,
      source_table: sourceTable,
      source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
      wealth_impact_type: 'PLANNED',
      transaction_type: transactionType || 'internal_transfer',
      transaction_status: transactionStatus || 'completed',
    },
    p_desired_locked_balance: reserveBalanceAfter,
  });

  if (!error) {
    const txId = data?.transaction_id || null;
    const reserve = data?.reserve || null;
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
      sourceBalanceAfter: Number(data?.source_balance_after ?? sourceBalanceAfter),
      reserve,
      atomic_commit: true,
    };
  }

  if (!isMissingRpc(error, 'bill_reserve_adjust_v1')) {
    throw new Error(error.message);
  }

  logBillReserveFallback(userId, reserveId, action, error);

  const transaction = await createWealthTransaction(
    sb,
    userId,
    sourceRecord,
    amount,
    currency,
    description,
    'PLANNED',
    metadata,
    { transactionType, transactionStatus },
  );

  await updateWealthSourceBalance(
    sb,
    sourceTable,
    sourceRecord,
    userId,
    sourceBalanceAfter,
  );

  await insertBillReserveLedger(sb, {
    transactionId: transaction.id,
    userId,
    sourceRecord,
    reserveId,
    amount,
    sourceBalanceAfter,
    reserveBalanceAfter,
    action,
  });

  return {
    transaction,
    sourceBalanceAfter,
    reserve: null,
    atomic_commit: false,
  };
};
