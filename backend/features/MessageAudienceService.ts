import { getAdminSupabase } from '../../services/supabaseClient.js';

export type MessageAudienceFilters = {
  search?: string;
  country?: string;
  registryType?: string;
  kycStatus?: string;
  accountStatus?: string;
  appOrigin?: string;
  hasPhone?: boolean;
  hasEmail?: boolean;
  createdAfter?: string;
  createdBefore?: string;
  newCustomersWithinDays?: number;
  minTransactionCount?: number;
  minTransactionAmount?: number;
  maxTransactionAmount?: number;
  minTotalTransactionAmount?: number;
  currency?: string;
  limit?: number;
};

export type AudienceUser = {
  id: string;
  full_name?: string | null;
  email?: string | null;
  phone?: string | null;
  nationality?: string | null;
  language?: string | null;
  registry_type?: string | null;
  kyc_status?: string | null;
  account_status?: string | null;
  app_origin?: string | null;
  customer_id?: string | null;
  created_at?: string | null;
  transaction_count: number;
  total_transaction_amount: number;
  last_transaction_at?: string | null;
};

class MessageAudienceService {
  async resolve(filters: MessageAudienceFilters = {}): Promise<AudienceUser[]> {
    const sb = getAdminSupabase();
    if (!sb) throw new Error('DB_OFFLINE');

    const limit = Math.min(Math.max(Number(filters.limit || 200), 1), 5000);
    let query = sb
      .from('users')
      .select('id, full_name, email, phone, nationality, language, registry_type, kyc_status, account_status, app_origin, customer_id, created_at')
      .limit(limit);

    if (filters.search?.trim()) {
      const q = filters.search.trim();
      query = query.or(`full_name.ilike.%${q}%,email.ilike.%${q}%,phone.ilike.%${q}%,customer_id.ilike.%${q}%`);
    }
    if (filters.country?.trim()) query = query.ilike('nationality', `%${filters.country.trim()}%`);
    if (filters.registryType?.trim()) query = query.eq('registry_type', filters.registryType.trim().toUpperCase());
    if (filters.kycStatus?.trim()) query = query.eq('kyc_status', filters.kycStatus.trim().toLowerCase());
    if (filters.accountStatus?.trim()) query = query.eq('account_status', filters.accountStatus.trim().toLowerCase());
    if (filters.appOrigin?.trim()) query = query.eq('app_origin', filters.appOrigin.trim());
    if (filters.hasPhone === true) query = query.not('phone', 'is', null);
    if (filters.hasEmail === true) query = query.not('email', 'is', null);
    if (filters.createdAfter?.trim()) query = query.gte('created_at', filters.createdAfter.trim());
    if (filters.createdBefore?.trim()) query = query.lte('created_at', filters.createdBefore.trim());

    if (filters.newCustomersWithinDays && Number(filters.newCustomersWithinDays) > 0) {
      const createdAfter = new Date(Date.now() - Number(filters.newCustomersWithinDays) * 24 * 60 * 60 * 1000).toISOString();
      query = query.gte('created_at', createdAfter);
    }

    const { data: users, error } = await query;
    if (error) throw new Error(error.message);
    if (!users?.length) return [];

    const userIds = users.map((user: any) => user.id).filter(Boolean);
    const { data: transactions, error: txError } = await sb
      .from('transactions')
      .select('user_id, amount, currency, created_at, status')
      .in('user_id', userIds)
      .in('status', ['settled', 'completed']);

    if (txError) throw new Error(txError.message);

    const aggregates = new Map<string, { count: number; total: number; max: number; lastAt: string | null }>();
    for (const tx of transactions || []) {
      const key = String((tx as any).user_id || '');
      if (!key) continue;
      const amount = Number((tx as any).amount || 0);
      const current = aggregates.get(key) || { count: 0, total: 0, max: 0, lastAt: null };
      current.count += 1;
      current.total += Number.isFinite(amount) ? amount : 0;
      current.max = Math.max(current.max, Number.isFinite(amount) ? amount : 0);
      const createdAt = typeof (tx as any).created_at === 'string' ? (tx as any).created_at : null;
      if (createdAt && (!current.lastAt || createdAt > current.lastAt)) current.lastAt = createdAt;
      aggregates.set(key, current);
    }

    return users
      .map((user: any) => {
        const aggregate = aggregates.get(String(user.id)) || { count: 0, total: 0, max: 0, lastAt: null };
        return {
          ...user,
          transaction_count: aggregate.count,
          total_transaction_amount: aggregate.total,
          last_transaction_at: aggregate.lastAt,
          _max_transaction_amount: aggregate.max,
        } as any;
      })
      .filter((user: any) => {
        if (filters.minTransactionCount != null && user.transaction_count < Number(filters.minTransactionCount)) return false;
        if (filters.minTotalTransactionAmount != null && user.total_transaction_amount < Number(filters.minTotalTransactionAmount)) return false;
        if (filters.minTransactionAmount != null && user._max_transaction_amount < Number(filters.minTransactionAmount)) return false;
        if (filters.maxTransactionAmount != null && user._max_transaction_amount > Number(filters.maxTransactionAmount)) return false;
        return true;
      })
      .map(({ _max_transaction_amount, ...user }: any) => user)
      .slice(0, limit);
  }
}

export const messageAudienceService = new MessageAudienceService();
