import { getAdminSupabase } from '../supabaseClient.js';
import { PolicyEngine } from '../ledger/PolicyEngine.js';
import { EntProcessor } from '../enterprise/wealth/EnterprisePaymentProcessor.js';
import { Audit } from '../security/audit.js';
import { buildPostgrestOrFilter } from '../security/postgrest.js';

export class OfflineOrbiBridge {
    async processConfirmedSession(session: any) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const user = await this.resolveUserFromSession(session);
        if (!user?.id) {
            throw new Error('OFFLINE_USER_NOT_FOUND');
        }

        const amount = Number(session.amount || 0);
        const currency = String(session.currency || 'TZS').trim().toUpperCase();
        const action = String(session.action || '').trim().toUpperCase();

        if (action !== 'SEND') {
            throw new Error(`OFFLINE_ACTION_NOT_SUPPORTED:${action}`);
        }

        const sourceWalletId = await this.resolveSourceWalletId(user.id, session.source_wallet_id);
        const policy = await PolicyEngine.evaluateTransaction(user.id, amount, currency, 'offline_settlement');
        if (!policy.allowed) {
            throw new Error(`POLICY_VIOLATION:${policy.reason}`);
        }

        const paymentPayload = {
            idempotencyKey: `offline-${session.request_id}`,
            referenceId: session.request_id,
            sourceWalletId,
            recipient_customer_id: session.recipient_ref || undefined,
            amount,
            currency,
            description: `Offline transfer ${session.request_id}`,
            type: 'INTERNAL_TRANSFER',
            metadata: {
                ...(session.metadata || {}),
                service_context: 'OFFLINE_GATEWAY',
                offline_request_id: session.request_id,
                offline_session_id: session.id,
                offline_phone_number: session.phone_number,
            },
        };

        const result = await EntProcessor.process(user as any, paymentPayload as any);
        if (!result?.success) {
            throw new Error(result?.error || 'OFFLINE_SETTLEMENT_FAILED');
        }

        await Audit.log('FINANCIAL', user.id, 'OFFLINE_SETTLEMENT_COMMITTED', {
            requestId: session.request_id,
            sessionId: session.id,
            transactionId: result?.transaction?.id || null,
            amount,
            currency,
        });

        return result;
    }

    private async resolveUserFromSession(session: any) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        if (session.user_id) {
            const { data: authUser } = await sb.auth.admin.getUserById(session.user_id);
            if (authUser?.user) {
                return {
                    id: authUser.user.id,
                    email: authUser.user.email,
                    phone: authUser.user.phone,
                    user_metadata: authUser.user.user_metadata || {},
                };
            }
        }

        const phone = String(session.phone_number || '').trim();
        if (!phone) return null;

        const { data: profile, error } = await sb
            .from('users')
            .select('id, full_name, email, phone, customer_id, account_status, kyc_status, registry_type, role')
            .eq('phone', phone)
            .maybeSingle();

        if (error) throw new Error(error.message);
        if (!profile) return null;

        return {
            id: profile.id,
            email: profile.email,
            phone: profile.phone,
            customer_id: profile.customer_id,
            role: profile.role,
            user_metadata: {
                full_name: profile.full_name,
                account_status: profile.account_status,
                kyc_status: profile.kyc_status,
                registry_type: profile.registry_type,
                role: profile.role,
            },
        };
    }

    private async resolveSourceWalletId(userId: string, walletIdentifier?: string | null) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const clean = String(walletIdentifier || '').trim();
        if (clean) {
            const { data: exactWallet, error: exactError } = await sb
                .from('wallets')
                .select('id, name, is_primary')
                .eq('user_id', userId)
                .or(buildPostgrestOrFilter([
                    { column: 'id', operator: 'eq', value: clean },
                    { column: 'name', operator: 'ilike', value: clean },
                ]))
                .maybeSingle();
            if (exactError) throw new Error(exactError.message);
            if (exactWallet?.id) return exactWallet.id;

            const { data: exactVault, error: exactVaultError } = await sb
                .from('platform_vaults')
                .select('id, name, vault_role')
                .eq('user_id', userId)
                .or(buildPostgrestOrFilter([
                    { column: 'id', operator: 'eq', value: clean },
                    { column: 'name', operator: 'ilike', value: clean },
                    { column: 'vault_role', operator: 'ilike', value: clean },
                ]))
                .maybeSingle();
            if (exactVaultError) throw new Error(exactVaultError.message);
            if (exactVault?.id) return exactVault.id;
        }

        const { data: primaryWallet, error: primaryWalletError } = await sb
            .from('wallets')
            .select('id')
            .eq('user_id', userId)
            .eq('is_primary', true)
            .maybeSingle();
        if (primaryWalletError) throw new Error(primaryWalletError.message);
        if (primaryWallet?.id) return primaryWallet.id;

        const { data: fallbackWallet, error: fallbackWalletError } = await sb
            .from('wallets')
            .select('id')
            .eq('user_id', userId)
            .limit(1)
            .maybeSingle();
        if (fallbackWalletError) throw new Error(fallbackWalletError.message);
        if (fallbackWallet?.id) return fallbackWallet.id;

        throw new Error('OFFLINE_SOURCE_WALLET_NOT_FOUND');
    }
}

export const offlineOrbiBridge = new OfflineOrbiBridge();
