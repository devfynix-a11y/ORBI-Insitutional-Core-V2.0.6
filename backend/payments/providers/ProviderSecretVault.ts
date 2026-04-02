import { FinancialPartner } from '../../../types.js';
import { decryptEnvelope, encryptEnvelope, isEncryptedEnvelope } from '../../security/CryptoEnvelope.js';

type ProviderSecretField =
    | 'client_secret'
    | 'connection_secret'
    | 'webhook_secret'
    | 'token_cache'
    | 'access_token'
    | 'refresh_token'
    | 'api_key';

export class ProviderSecretVault {
    async wrapSecret(value: string, field: ProviderSecretField, context: Record<string, any> = {}): Promise<string> {
        if (!value) return '';
        return encryptEnvelope(value, field === 'token_cache' || field.endsWith('_token') ? 'PROVIDER_TOKEN' : 'PROVIDER_SECRET', {
            field,
            ...context,
        }, 'SECRET_WRAPPING');
    }

    async unwrapSecret(value: unknown): Promise<string> {
        if (!value) return '';
        if (typeof value !== 'string') return String(value);
        if (!isEncryptedEnvelope(value)) return value;
        return String(await decryptEnvelope(value, 'SECRET_WRAPPING'));
    }

    async resolvePartnerSecret(partner: FinancialPartner, ...candidates: Array<ProviderSecretField>): Promise<string> {
        const secrets = partner.provider_metadata?.secrets || {};
        for (const candidate of candidates) {
            const rawValue =
                (partner as Record<string, any>)[candidate] ??
                (secrets as Record<string, any>)[candidate];
            const unwrapped = await this.unwrapSecret(rawValue);
            if (unwrapped.trim().length > 0) {
                return unwrapped;
            }
        }
        return '';
    }
}

export const providerSecretVault = new ProviderSecretVault();
