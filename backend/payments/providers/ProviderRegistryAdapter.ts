import {
    FinancialPartner,
    MoneyOperation,
    ProviderCallbackConfig,
    ProviderRegistryConfig,
    RestEndpointConfig,
} from '../../../types.js';

export type NormalizedProviderRegistry = ProviderRegistryConfig & {
    operations: Record<string, RestEndpointConfig>;
};

export const normalizeProviderRegistry = (partner: FinancialPartner): NormalizedProviderRegistry => {
    const registry = (partner.mapping_config || {}) as ProviderRegistryConfig;
    const operations = (registry.operations || {}) as Record<string, RestEndpointConfig>;

    return {
        ...registry,
        operations,
    };
};

export const assertProviderRegistry = (partner: FinancialPartner): NormalizedProviderRegistry => {
    if (!partner.mapping_config) {
        throw new Error(`PROVIDER_REGISTRY_CONFIG_MISSING: ${partner.name}`);
    }

    return normalizeProviderRegistry(partner);
};

export const resolveOperationConfig = (
    registry: NormalizedProviderRegistry,
    operation: MoneyOperation | string,
): RestEndpointConfig | undefined => {
    if (!operation) return undefined;
    const opKey = String(operation).trim().toUpperCase();
    return registry.operations[opKey] || registry.operations[operation] || undefined;
};

export const resolveOperationServiceKey = (operation: MoneyOperation | string): string => {
    const normalized = String(operation || '').trim().toUpperCase();
    if (normalized === 'COLLECTION_REQUEST') return 'stk_push';
    if (normalized === 'DISBURSEMENT_REQUEST') return 'disbursement';
    if (normalized === 'BALANCE_INQUIRY') return 'balance';
    if (normalized === 'AUTH') return 'auth';
    return normalized.toLowerCase();
};

export const assertOperationConfig = (
    partner: FinancialPartner,
    operation: MoneyOperation | string,
): RestEndpointConfig => {
    const registry = assertProviderRegistry(partner);
    const config = resolveOperationConfig(registry, operation);
    if (config) return config;

    const fallbackAllowed =
        (operation === 'COLLECTION_REQUEST' && registry.stk_push) ||
        (operation === 'DISBURSEMENT_REQUEST' && registry.disbursement) ||
        (operation === 'BALANCE_INQUIRY' && registry.balance);

    if (fallbackAllowed) {
        return (
            registry.stk_push ||
            registry.disbursement ||
            registry.balance ||
            registry.operations[String(operation)]!
        );
    }

    throw new Error(`PROVIDER_OPERATION_NOT_CONFIGURED: ${partner.name}:${operation}`);
};

export const resolveProviderBaseUrl = (
    partner: FinancialPartner,
    registry: NormalizedProviderRegistry,
    operation?: MoneyOperation | string,
): string => {
    const opKey = operation ? resolveOperationServiceKey(operation) : '';
    const operationRoot = opKey ? registry.service_roots?.[opKey] : undefined;
    const baseUrl = operationRoot || registry.service_root || partner.api_base_url;
    if (!baseUrl) {
        throw new Error(`PROVIDER_BASE_URL_MISSING: ${partner.name}`);
    }
    return baseUrl;
};

export const assertCallbackConfig = (
    partner: FinancialPartner,
): ProviderCallbackConfig => {
    const registry = assertProviderRegistry(partner);
    const callback = registry.callback;
    if (!callback) {
        throw new Error(`PROVIDER_CALLBACK_CONFIG_MISSING: ${partner.name}`);
    }
    if (!callback.reference_field) {
        throw new Error(`PROVIDER_CALLBACK_REFERENCE_FIELD_MISSING: ${partner.name}`);
    }
    if (!callback.status_field) {
        throw new Error(`PROVIDER_CALLBACK_STATUS_FIELD_MISSING: ${partner.name}`);
    }
    return callback;
};

export const assertAuthConfig = (
    partner: FinancialPartner,
): NonNullable<ProviderRegistryConfig['auth']> => {
    const registry = assertProviderRegistry(partner);
    if (!registry.auth) {
        throw new Error(`PROVIDER_AUTH_CONFIG_MISSING: ${partner.name}`);
    }
    return registry.auth;
};
