import { z } from 'zod';

export const BillReservePaymentSchema = z.object({
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

export const wealthNumber = (value: any) => {
  if (typeof value === 'number') return value;
  if (typeof value === 'string') return Number(value.replace(/,/g, '')) || 0;
  return 0;
};

export const resolveWealthSourceWallet = async (
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

export const assertBillPaymentSourceAllowed = (sourceRecord: any) => {
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

export const billReserveValuesMatch = (left?: string | null, right?: string | null) => {
  const leftKey = normalizeBillReserveValue(String(left || ''));
  const rightKey = normalizeBillReserveValue(String(right || ''));
  if (!leftKey || !rightKey) return false;
  return leftKey === rightKey || leftKey.includes(rightKey) || rightKey.includes(leftKey);
};

export const resolveBillReserveReference = (reserve: any) =>
  String(
    reserve?.reference ??
    reserve?.bill_reference ??
    reserve?.account_number ??
    reserve?.meter_number ??
    reserve?.customer_number ??
    '',
  ).trim();
