
import { Wallet, Transaction, User, LedgerEntry } from '../types.js';
import { Storage, STORAGE_KEYS } from '../backend/storage.js';
import { getSupabase, getAdminSupabase } from '../services/supabaseClient.js';
import { DataVault } from '../backend/security/encryption.js';
import { DataProtection } from '../backend/security/DataProtection.js';
import { TransactionService } from '../ledger/transactionService.js';
import { UUID } from '../services/utils.js';

export class WalletService {
    private txService = new TransactionService();

    /**
     * PROVISION SOVEREIGN DILPESA VAULT
     * Triggered during identity genesis. Persists to the separate 'platform_vaults' table.
     */
    public async provisionGenesisVault(userId: string): Promise<void> {
        const sb = getAdminSupabase();
        if (!sb) return;

        const encryptedBalance = await DataProtection.encryptAmount(0);

        const { error: opError } = await sb.from('platform_vaults').insert({
            id: UUID.generate(),
            user_id: userId,
            vault_role: 'OPERATING',
            name: "Orbi",
            balance: 0,
            encrypted_balance: encryptedBalance,
            currency: 'USD',
            color: '#06D6A0',
            icon: 'vault'
        });
        
        if (opError) console.error("[Wallet] Sovereign OPERATING provision failed:", opError.message);

        const { error: intError } = await sb.from('platform_vaults').insert({
            id: UUID.generate(),
            user_id: userId,
            vault_role: 'INTERNAL_TRANSFER',
            name: "PaySafe",
            balance: 0,
            encrypted_balance: encryptedBalance,
            currency: 'USD',
            color: '#118AB2',
            icon: 'shield-check',
            metadata: {
                is_secure_escrow: true,
                slogan: "Secure Internal Transfers",
                display_mode: "mask"
            }
        });

        if (intError) console.error("[Wallet] Sovereign INTERNAL_TRANSFER provision failed:", intError.message);
    }

    /**
     * UNIFIED FETCH
     * Fetches from both Platform Vaults and Linked Accounts.
     * Hides INTERNAL_TRANSFER vaults from the end user.
     */
    async fetchForUser(userId: string): Promise<Wallet[]> {
        const sb = getAdminSupabase();
        if (!sb) return [];

        try {
            const [vaultsRes, linkedRes] = await Promise.all([
                sb.from('platform_vaults').select('*').eq('user_id', userId),
                sb.from('wallets').select('*').eq('user_id', userId)
            ]);

            const vaults = (vaultsRes.data || [])
                .filter(v => v.vault_role !== 'INTERNAL_TRANSFER')
                .map(v => ({
                ...v,
                management_tier: 'sovereign' as const,
                type: 'operating' as const,
                actualBalance: Number(v.balance),
                availableBalance: Number(v.balance),
                balance: Number(v.balance),
                initialBalance: 0,
                metadata: v.metadata,
                accountNumber: v.metadata?.account_number || v.metadata?.linked_customer_id
            }));

            const linked = (linkedRes.data || []).map(l => ({
                ...l,
                management_tier: 'linked' as const,
                actualBalance: Number(l.balance),
                availableBalance: Number(l.balance),
                balance: Number(l.balance),
                initialBalance: 0,
                metadata: l.metadata,
                accountNumber: l.account_number || l.metadata?.account_number
            }));

            return [...vaults, ...linked];
        } catch (e) {
            console.error("[WalletService] Fetch failure:", e);
            return [];
        }
    }

    // Added getFromDBLocal to fix missing property error in paymentsProcessor
    async getFromDBLocal(): Promise<Wallet[]> {
        const raw = Storage.getFromDB(STORAGE_KEYS.WALLETS) as any[];
        return await Promise.all(raw.map(async w => ({
            ...w,
            balance: typeof w.balance === 'string' ? await DataProtection.decryptAmount(w.balance) : w.balance,
            actualBalance: typeof w.actualBalance === 'string' ? await DataProtection.decryptAmount(w.actualBalance) : w.actualBalance,
            availableBalance: typeof w.availableBalance === 'string' ? await DataProtection.decryptAmount(w.availableBalance) : w.availableBalance
        })));
    }

    async createLinkedWallet(userId: string, data: any): Promise<void> {
        const sb = getAdminSupabase();
        if (!sb) return;
        await sb.from('wallets').insert({
            user_id: userId,
            ...data,
            management_tier: undefined // SQL table doesn't have it, we infer it from the table name
        });
    }

    /* FIX: Added missing updateWallet method */
    async updateWallet(id: string, data: any): Promise<void> {
        const sb = getAdminSupabase();
        if (!sb) return;
        await sb.from('wallets').update(data).eq('id', id);
    }

    async deleteWallet(id: string, tier: 'sovereign' | 'linked', userId?: string): Promise<void> {
        const sb = getAdminSupabase();
        if (!sb) return;
        const table = tier === 'sovereign' ? 'platform_vaults' : 'wallets';
        let query = sb.from(table).delete().eq('id', id).select('id');
        if (userId && tier === 'linked') {
            query = query.eq('user_id', userId);
        }
        const { data, error } = await query;
        if (error) throw error;
        if (userId && tier === 'linked' && (!(data && data.length))) {
            throw new Error('WALLET_NOT_FOUND');
        }
    }
}
