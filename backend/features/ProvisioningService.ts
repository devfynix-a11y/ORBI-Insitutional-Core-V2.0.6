
import { getAdminSupabase } from '../supabaseClient.js';
import { UUID } from '../../services/utils.js';
import { DataVault } from '../security/encryption.js';
import crypto from 'crypto';
import { DataProtection } from '../security/DataProtection.js';

export class ProvisioningService {
    /**
     * PROVISION USER INFRASTRUCTURE
     * Idempotent creation of default vaults and card metadata.
     */
    static async provisionUser(userId: string, fullName: string, customerId?: string) {
        const sb = getAdminSupabase();
        if (!sb) {
            console.error("[Provisioning] Admin Supabase client not available. Check SUPABASE_SERVICE_ROLE_KEY.");
            return { status: 'failed', error: 'DB_OFFLINE_MISSING_ADMIN_KEY' };
        }

        try {
            // 1. Check if already provisioned (idempotency)
            const { data: existingVaults, error: fetchError } = await sb.from('platform_vaults')
                .select('id')
                .eq('user_id', userId)
                .in('name', ['Orbi', 'PaySafe']);

            if (fetchError) {
                console.error(`[Provisioning] Failed to check existing vaults: ${fetchError.message}`);
                // Don't throw here, try to proceed or return error? 
                // If we can't read, we probably can't write.
                throw fetchError;
            }

            if (existingVaults && existingVaults.length >= 2) {
                console.info(`[Provisioning] User ${userId} already provisioned.`);
                return { status: 'ready' };
            }

            console.info(`[Provisioning] Starting genesis for user ${userId}...`);

            // 2. Create Vaults & Wallets
            const encryptedZero = await DataProtection.encryptAmount(0);
            
            // Fetch customer_id if not provided
            let finalCustomerId = customerId;
            let userFullName = fullName;

            if (!finalCustomerId) {
                const { data: userData } = await sb.from('users').select('customer_id, full_name').eq('id', userId).single();
                finalCustomerId = userData?.customer_id || 'OBI-PENDING';
                userFullName = userData?.full_name || fullName;
            }

            // Deterministic IDs matching the trigger
            const wallet1_id = crypto.createHash('md5').update(`${userId}Orbi`).digest('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
            const wallet2_id = crypto.createHash('md5').update(`${userId}PaySafe`).digest('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');

            const vaultsToCreate = [
                {
                    id: wallet1_id,
                    user_id: userId,
                    vault_role: 'OPERATING',
                    name: "Orbi",
                    balance: 0,
                    encrypted_balance: encryptedZero,
                    currency: 'TZS',
                    color: '#10B981', // Emerald
                    icon: 'credit-card',
                    metadata: {
                        linked_customer_id: finalCustomerId,
                        account_number: finalCustomerId, // Set Customer ID as Wallet Account ID
                        display_name: userFullName,
                        card_type: 'Virtual Master'
                    }
                },
                {
                    id: wallet2_id,
                    user_id: userId,
                    vault_role: 'INTERNAL_TRANSFER',
                    name: "PaySafe",
                    balance: 0,
                    encrypted_balance: encryptedZero,
                    currency: 'TZS',
                    color: '#6366F1', // Indigo
                    icon: 'shield-check',
                    metadata: {
                        is_secure_escrow: true,
                        slogan: "Secure Internal Transfers",
                        display_mode: "mask",
                        account_number: `ESC-${finalCustomerId}` // Distinct account number for PaySafe
                    }
                }
            ];

            const { error: vaultError } = await sb.from('platform_vaults').upsert(vaultsToCreate, { onConflict: 'id' });
            if (vaultError) {
                console.error(`[Provisioning] Vault insertion failed: ${vaultError.message}`);
                throw vaultError;
            }

            // 3. Create Transfer Card Metadata
            const transferCard = {
                holder_name: userFullName,
                card_number_masked: finalCustomerId, // Use Customer ID as the "Card Number" for internal transfers
                brand: 'mastercard_style',
                status: 'ready',
                provisioned_at: new Date().toISOString(),
                product_name: 'Orbi'
            };

            const { error: userUpdateError } = await sb.from('users')
                .update({ 
                    metadata: { transfer_card: transferCard } 
                })
                .eq('id', userId);

            if (userUpdateError) throw userUpdateError;

            console.info(`[Provisioning] Genesis complete for user ${userId}. Wallets created.`);
            return { status: 'ready' };
        } catch (e: any) {
            console.error(`[Provisioning] Genesis failed for ${userId}:`, e.message);
            return { status: 'failed', error: e.message };
        }
    }

    static async getProvisioningStatus(userId: string) {
        const sb = getAdminSupabase();
        if (!sb) return 'failed';

        const { data: vaults } = await sb.from('platform_vaults')
            .select('id')
            .eq('user_id', userId)
            .in('name', ['Orbi', 'PaySafe']);

        return (vaults && vaults.length >= 2) ? 'ready' : 'pending';
    }
}
