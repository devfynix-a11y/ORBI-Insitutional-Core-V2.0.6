import { getSupabase, getAdminSupabase } from '../supabaseClient.js';
import { Identity } from '../../iam/identityService.js';
import { UserPublicProfile } from '../../types.js';
import { buildPostgrestOrFilter } from '../security/postgrest.js';

export interface ResolvedWallet {
    userId: string;
    walletId: string;
    walletName: string;
    profile: UserPublicProfile;
}

/**
 * ORBI WALLET RESOLVER (V1.0)
 * ----------------------------
 * Centralized service to resolve user identities and their
 * primary operating wallets from any identifier.
 */
export class WalletResolver {

    /**
     * Resolves a user and their primary operating wallet.
     * @param identifier Customer ID, Phone, Email, or User ID.
     * @param vaultRole The role of the vault to resolve (default: 'OPERATING').
     */
    public async resolveWallet(identifier: string, vaultRole: string = 'OPERATING'): Promise<ResolvedWallet | null> {
        // Use Admin client to bypass RLS for backend resolution
        const sb = getAdminSupabase();
        if (!sb) return null;

        // 1. Resolve Identity
        // If it's a UUID, try direct lookup or fallback to IdentityService
        let profile = await Identity.lookupUser(identifier);
        
        // If not found via IdentityService, check if it's a direct user_id or customer_id
        if (!profile) {
            let query = sb.from('users').select('id, full_name, avatar_url, customer_id, phone, email, registry_type');
            
            // Check if identifier is a valid UUID
            const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identifier);
            
            if (isUUID) {
                query = query.eq('id', identifier);
            } else {
                // If not UUID, try customer_id, phone, or email
                // Note: .or() syntax requires explicit column names
                query = query.or(buildPostgrestOrFilter([
                    { column: 'customer_id', operator: 'eq', value: identifier },
                    { column: 'phone', operator: 'eq', value: identifier },
                    { column: 'email', operator: 'eq', value: identifier },
                ]));
            }

            const { data: user } = await query.maybeSingle();
            
            if (user) {
                profile = {
                    id: user.id,
                    full_name: user.full_name,
                    avatar_url: user.avatar_url,
                    customer_id: user.customer_id,
                    phone: user.phone,
                    email: user.email,
                    registry_type: user.registry_type
                };
            }
        }

        if (!profile) {
            console.warn(`[WalletResolver] Identity not found for identifier: ${identifier}`);
            return null;
        }

        // 2. Resolve Wallet
        // Priority 1: If a specific vaultRole is requested (other than OPERATING), find it directly
        if (vaultRole !== 'OPERATING') {
            const { data: specificVault } = await sb
                .from('platform_vaults')
                .select('id, balance, name, vault_role')
                .eq('user_id', profile.id)
                .eq('vault_role', vaultRole)
                .maybeSingle();
            
            if (specificVault) {
                return { userId: profile.id, walletId: specificVault.id, walletName: specificVault.name || vaultRole, profile };
            }
        }

        // Priority 2: Check platform_vaults for the specific role AND balance > 0
        const { data: vaults, error: vaultError } = await sb
            .from('platform_vaults')
            .select('id, balance, name, vault_role')
            .eq('user_id', profile.id)
            .order('balance', { ascending: false });

        if (vaults && vaults.length > 0) {
            // Try to find the specific role with balance
            const roleMatchWithBalance = vaults.find(v => v.vault_role === vaultRole && Number(v.balance) > 0);
            if (roleMatchWithBalance) {
                return { userId: profile.id, walletId: roleMatchWithBalance.id, walletName: roleMatchWithBalance.name || 'Operating Vault', profile };
            }

            // If not found, try any vault with balance
            const anyWithBalance = vaults.find(v => Number(v.balance) > 0);
            if (anyWithBalance) {
                return { userId: profile.id, walletId: anyWithBalance.id, walletName: anyWithBalance.name || 'Operating Vault', profile };
            }
        }

        // Priority 2: Check wallets table for any wallet belonging to the user with balance
        const { data: wallets, error: walletError } = await sb
            .from('wallets')
            .select('id, balance, name')
            .eq('user_id', profile.id)
            .order('balance', { ascending: false });

        if (wallets && wallets.length > 0) {
            const withBalance = wallets.find(w => Number(w.balance) > 0);
            if (withBalance) {
                return { userId: profile.id, walletId: withBalance.id, walletName: withBalance.name, profile };
            }
        }

        // Priority 3: Fallback to the specific role even if balance is 0
        if (vaults && vaults.length > 0) {
            const roleMatch = vaults.find(v => v.vault_role === vaultRole);
            if (roleMatch) {
                return { userId: profile.id, walletId: roleMatch.id, walletName: roleMatch.name || 'Operating Vault', profile };
            }
        }

        // Priority 4: Fallback to any wallet/vault if nothing else found
        if (wallets && wallets.length > 0) {
            return { userId: profile.id, walletId: wallets[0].id, walletName: wallets[0].name, profile };
        }

        if (vaults && vaults.length > 0) {
            return { userId: profile.id, walletId: vaults[0].id, walletName: vaults[0].name || 'Operating Vault', profile };
        }

        console.warn(`[WalletResolver] No suitable wallet found for user ${profile.id}`);
        return null;
    }

    /**
     * Resolves a wallet and its owner by wallet ID.
     */
    public async resolveByWalletId(walletId: string): Promise<ResolvedWallet | null> {
        const sb = getAdminSupabase();
        if (!sb) return null;

        // 1. Find the wallet/vault
        let resolvedWallet: { id: string, user_id: string } | null = null;

        const { data: vault } = await sb
            .from('platform_vaults')
            .select('id, user_id')
            .eq('id', walletId)
            .maybeSingle();

        if (vault) {
            resolvedWallet = vault;
        } else {
            // Try 'wallets' table too
            const { data: wallet } = await sb
                .from('wallets')
                .select('id, user_id')
                .eq('id', walletId)
                .maybeSingle();
            
            if (wallet) resolvedWallet = wallet;
        }

        if (!resolvedWallet) return null;

        // 2. Resolve User Profile
        const { data: user } = await sb
            .from('users')
            .select('id, full_name, avatar_url, customer_id, phone, email, registry_type')
            .eq('id', resolvedWallet.user_id)
            .maybeSingle();

        if (!user) return null;

        return {
            userId: user.id,
            walletId: resolvedWallet.id,
            walletName: (resolvedWallet as any).name || 'Operating Vault',
            profile: user as UserPublicProfile
        };
    }
}

export const WalletResolverService = new WalletResolver();
