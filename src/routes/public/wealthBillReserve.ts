export const updateWealthSourceBalance = async (
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

export const createWealthTransaction = async (
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

export const insertBillReserveLedger = async (
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
