import { FinancialPartner } from '../../../types.js';
import { MerchantFabric } from './MerchantFabric.js';
import { providerSecretVault } from './ProviderSecretVault.js';

export type ProviderTokenResult = {
    token: string;
    expiresAt?: number;
};

export class ProviderTokenService {
    async getCachedToken(partner: FinancialPartner): Promise<ProviderTokenResult | null> {
        if (!partner.token_cache || !partner.token_expiry) return null;
        if (partner.token_expiry <= Date.now()) return null;

        const cached = await providerSecretVault.unwrapSecret(partner.token_cache);

        if (!cached || !String(cached).trim()) return null;
        return {
            token: String(cached),
            expiresAt: Number(partner.token_expiry),
        };
    }

    async cacheToken(partnerId: string, token: string, expiresInSeconds: number): Promise<void> {
        if (!partnerId || !token) return;
        await MerchantFabric.updatePartnerToken(partnerId, token, expiresInSeconds);
    }

    async resolveStaticToken(partner: FinancialPartner): Promise<string> {
        const connectionSecret = await providerSecretVault.resolvePartnerSecret(
            partner,
            'connection_secret',
            'api_key',
        );
        if (connectionSecret) {
            return connectionSecret;
        }

        return providerSecretVault.resolvePartnerSecret(
            partner,
            'client_secret',
            'access_token',
        );
    }
}

export const providerTokenService = new ProviderTokenService();
