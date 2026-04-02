import { providerSecretVault } from './ProviderSecretVault.js';

const SENSITIVE_EXACT_KEYS = new Set([
    'client_secret',
    'connection_secret',
    'webhook_secret',
    'secret',
    'password',
    'api_key',
    'apikey',
    'access_token',
    'refresh_token',
    'token_cache',
    'private_key',
    'authorization',
]);

const isSensitiveKey = (key: string) => {
    const normalized = key.trim().toLowerCase();
    if (SENSITIVE_EXACT_KEYS.has(normalized)) return true;
    if (normalized.startsWith('x-api-key')) return true;
    if (normalized.endsWith('_secret')) return true;
    if (normalized.endsWith('_token')) return true;
    if (normalized.endsWith('_password')) return true;
    if (normalized.endsWith('_key')) return true;
    return false;
};

export async function secureProviderRegistryPayload(input: any): Promise<any> {
    if (input === null || input === undefined) return input;

    if (Array.isArray(input)) {
        const result = [];
        for (const item of input) {
            result.push(await secureProviderRegistryPayload(item));
        }
        return result;
    }

    if (typeof input !== 'object') {
        return input;
    }

    const clone: Record<string, any> = {};
    for (const [key, value] of Object.entries(input)) {
        if (value === null || value === undefined) {
            clone[key] = value;
            continue;
        }

        if (typeof value === 'string' && isSensitiveKey(key)) {
            clone[key] = await providerSecretVault.wrapSecret(value, key as any, {
                domain: 'PROVIDER_REGISTRY',
            });
            continue;
        }

        clone[key] = await secureProviderRegistryPayload(value);
    }

    return clone;
}
