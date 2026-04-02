import {
    FinancialPartner,
    FinancialPartnerMetadata,
    ProviderAuthConfig,
    ProviderCallbackConfig,
    ProviderRegistryConfig,
    RestEndpointConfig,
} from '../../../types.js';

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const PARTNER_TYPES = new Set(['mobile_money', 'bank', 'card', 'crypto']);
const LOGIC_TYPES = new Set(['REGISTRY', 'GENERIC_REST', 'SPECIALIZED']);
const PROVIDER_GROUPS = new Set(['mobile', 'bank', 'gateways', 'crypto']);
const RAIL_TYPES = new Set(['mobile_money', 'bank', 'card_gateway', 'crypto', 'wallet']);
const CHECKOUT_MODES = new Set([
    'redirect',
    'embedded',
    'tokenized',
    'server_to_server',
    'ussd',
    'stk_push',
    'manual',
]);
const CHANNELS = new Set([
    'bank_transfer',
    'bank_account',
    'mobile_money',
    'card',
    'paypal',
    'crypto',
    'ussd',
    'qr',
    'checkout_link',
]);
const MONEY_OPERATIONS = new Set([
    'AUTH',
    'ACCOUNT_LOOKUP',
    'COLLECTION_REQUEST',
    'COLLECTION_STATUS',
    'DISBURSEMENT_REQUEST',
    'DISBURSEMENT_STATUS',
    'PAYOUT_REQUEST',
    'PAYOUT_STATUS',
    'REVERSAL_REQUEST',
    'REVERSAL_STATUS',
    'BALANCE_INQUIRY',
    'TRANSACTION_LOOKUP',
    'WEBHOOK_VERIFY',
    'BENEFICIARY_VALIDATE',
]);

function assertObject(value: any, label: string): Record<string, any> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error(`${label}_INVALID`);
    }
    return value as Record<string, any>;
}

function normalizeMethod(method: unknown, label: string): RestEndpointConfig['method'] {
    const normalized = String(method || '').trim().toUpperCase();
    if (!HTTP_METHODS.has(normalized)) {
        throw new Error(`${label}_METHOD_INVALID`);
    }
    return normalized as RestEndpointConfig['method'];
}

function validatePathLike(url: unknown, label: string): string {
    const value = String(url || '').trim();
    if (!value) {
        throw new Error(`${label}_URL_MISSING`);
    }
    if (!/^https?:\/\//i.test(value) && !value.startsWith('/')) {
        throw new Error(`${label}_URL_INVALID`);
    }
    return value;
}

function normalizeServiceRoots(value: unknown): Record<string, string> | undefined {
    if (value === undefined || value === null) return undefined;
    const raw = assertObject(value, 'PROVIDER_SERVICE_ROOTS');
    const normalized: Record<string, string> = {};
    for (const [key, root] of Object.entries(raw)) {
        const label = `PROVIDER_SERVICE_ROOTS_${String(key).toUpperCase()}`;
        normalized[String(key)] = validatePathLike(root, label);
    }
    return normalized;
}

function normalizeHeaders(headers: unknown, label: string): Record<string, string> | undefined {
    if (headers === undefined || headers === null) return undefined;
    const raw = assertObject(headers, `${label}_HEADERS`);
    const normalized: Record<string, string> = {};
    for (const [key, value] of Object.entries(raw)) {
        normalized[String(key)] = String(value);
    }
    return normalized;
}

function normalizePayloadTemplate(payload: unknown, label: string): Record<string, any> | undefined {
    if (payload === undefined || payload === null) return undefined;
    return assertObject(payload, `${label}_PAYLOAD_TEMPLATE`);
}

function normalizeResponseMapping(mapping: unknown, label: string): RestEndpointConfig['response_mapping'] | undefined {
    if (mapping === undefined || mapping === null) return undefined;
    const raw = assertObject(mapping, `${label}_RESPONSE_MAPPING`);
    const normalized: NonNullable<RestEndpointConfig['response_mapping']> = {};
    for (const [key, value] of Object.entries(raw)) {
        if (value !== undefined && value !== null && String(value).trim().length > 0) {
            normalized[key as keyof typeof normalized] = String(value);
        }
    }
    return normalized;
}

function normalizeEndpointConfig(
    config: unknown,
    label: string,
): RestEndpointConfig | undefined {
    if (config === undefined || config === null) return undefined;
    const raw = assertObject(config, label);
    return {
        url: validatePathLike(raw.url, label),
        method: normalizeMethod(raw.method || 'POST', label),
        headers: normalizeHeaders(raw.headers, label),
        payload_template: normalizePayloadTemplate(raw.payload_template, label),
        response_mapping: normalizeResponseMapping(raw.response_mapping, label),
    };
}

function normalizeAuthConfig(config: unknown): ProviderAuthConfig | undefined {
    if (config === undefined || config === null) return undefined;
    const raw = assertObject(config, 'PROVIDER_AUTH');
    const type = String(raw.type || 'api_key').trim().toLowerCase();
    if (!['oauth2_client_credentials', 'api_key', 'static_token', 'none'].includes(type)) {
        throw new Error('PROVIDER_AUTH_TYPE_INVALID');
    }
    const endpoint = normalizeEndpointConfig({
        url: raw.url || '/oauth/token',
        method: raw.method || 'POST',
        headers: raw.headers,
        payload_template: raw.payload_template,
        response_mapping: raw.response_mapping,
    }, 'PROVIDER_AUTH');
    if (!endpoint) {
        throw new Error('PROVIDER_AUTH_INVALID');
    }
    return {
        ...endpoint,
        type: type as ProviderAuthConfig['type'],
        cache_ttl_seconds:
            raw.cache_ttl_seconds === undefined || raw.cache_ttl_seconds === null
                ? undefined
                : Number(raw.cache_ttl_seconds),
    };
}

function normalizeValues(values: unknown): Array<string | number> | undefined {
    if (!Array.isArray(values)) return undefined;
    return values
        .filter((value) => value !== undefined && value !== null && String(value).trim().length > 0)
        .map((value) => typeof value === 'number' ? value : String(value));
}

function normalizeCallbackConfig(config: unknown): ProviderCallbackConfig | undefined {
    if (config === undefined || config === null) return undefined;
    const raw = assertObject(config, 'PROVIDER_CALLBACK');
    return {
        reference_field: raw.reference_field ? String(raw.reference_field) : undefined,
        status_field: raw.status_field ? String(raw.status_field) : undefined,
        message_field: raw.message_field ? String(raw.message_field) : undefined,
        event_id_field: raw.event_id_field ? String(raw.event_id_field) : undefined,
        success_values: normalizeValues(raw.success_values),
        pending_values: normalizeValues(raw.pending_values),
        failed_values: normalizeValues(raw.failed_values),
        completed_values: normalizeValues(raw.completed_values),
    };
}

function normalizeStringArray(values: unknown, label: string): string[] | undefined {
    if (values === undefined || values === null) return undefined;
    if (!Array.isArray(values)) {
        throw new Error(`${label}_INVALID`);
    }
    return values
        .map((value) => String(value || '').trim())
        .filter((value) => value.length > 0);
}

function normalizeProviderMetadata(metadata: unknown): FinancialPartnerMetadata | undefined {
    if (metadata === undefined || metadata === null) return undefined;
    const raw = assertObject(metadata, 'PROVIDER_METADATA');
    const normalized: FinancialPartnerMetadata = { ...raw };

    const groupRaw = String(
        raw.group ?? raw.provider_group ?? '',
    ).trim().toLowerCase();
    if (groupRaw) {
        const normalizedGroup =
            groupRaw === 'gateway' || groupRaw === 'processor' || groupRaw === 'payment_gateway'
                ? 'gateways'
                : groupRaw === 'mobile_money'
                    ? 'mobile'
                    : groupRaw;
        if (!PROVIDER_GROUPS.has(normalizedGroup)) {
            throw new Error('PROVIDER_METADATA_GROUP_INVALID');
        }
        normalized.group = normalizedGroup[0].toUpperCase() + normalizedGroup.slice(1);
        delete normalized.provider_group;
    }

    const brandName = String(raw.brand_name ?? raw.display_name ?? '').trim();
    if (brandName) {
        normalized.brand_name = brandName;
    }

    const displayName = String(raw.display_name ?? '').trim();
    if (displayName) {
        normalized.display_name = displayName;
    }

    const displayIcon = String(raw.display_icon ?? raw.icon ?? '').trim();
    if (displayIcon) {
        normalized.display_icon = displayIcon;
    }

    const checkoutMode = String(raw.checkout_mode ?? '').trim().toLowerCase();
    if (checkoutMode) {
        if (!CHECKOUT_MODES.has(checkoutMode)) {
            throw new Error('PROVIDER_METADATA_CHECKOUT_MODE_INVALID');
        }
        normalized.checkout_mode = checkoutMode;
    }

    const channels = normalizeStringArray(raw.channels, 'PROVIDER_METADATA_CHANNELS');
    if (channels) {
        const normalizedChannels = channels.map((channel) => channel.toLowerCase());
        for (const channel of normalizedChannels) {
            if (!CHANNELS.has(channel)) {
                throw new Error('PROVIDER_METADATA_CHANNEL_INVALID');
            }
        }
        normalized.channels = normalizedChannels;
    }

    const countries = normalizeStringArray(raw.countries, 'PROVIDER_METADATA_COUNTRIES');
    if (countries) {
        normalized.countries = countries.map((country) => country.toUpperCase());
    }

    const capabilities = normalizeStringArray(raw.capabilities, 'PROVIDER_METADATA_CAPABILITIES');
    if (capabilities) {
        normalized.capabilities = capabilities;
    }

    const rail = String(raw.rail ?? '').trim().toLowerCase();
    if (rail) {
        if (!RAIL_TYPES.has(rail)) {
            throw new Error('PROVIDER_METADATA_RAIL_INVALID');
        }
        normalized.rail = rail.toUpperCase();
    }

    const operations = normalizeStringArray(raw.operations, 'PROVIDER_METADATA_OPERATIONS');
    if (operations) {
        const normalizedOperations = operations.map((operation) => operation.trim().toUpperCase());
        for (const operation of normalizedOperations) {
            if (!MONEY_OPERATIONS.has(operation)) {
                throw new Error('PROVIDER_METADATA_OPERATION_INVALID');
            }
        }
        normalized.operations = normalizedOperations;
    }

    if (raw.sort_order !== undefined && raw.sort_order !== null) {
        const sortOrder = Number(raw.sort_order);
        if (!Number.isFinite(sortOrder)) {
            throw new Error('PROVIDER_METADATA_SORT_ORDER_INVALID');
        }
        normalized.sort_order = sortOrder;
    }

    return normalized;
}

function normalizeOperationMap(config: unknown): Partial<Record<string, RestEndpointConfig>> | undefined {
    if (config === undefined || config === null) return undefined;
    const raw = assertObject(config, 'PROVIDER_OPERATION_MAP');
    const normalized: Partial<Record<string, RestEndpointConfig>> = {};
    for (const [operation, endpointConfig] of Object.entries(raw)) {
        const normalizedOperation = String(operation || '').trim().toUpperCase();
        if (!MONEY_OPERATIONS.has(normalizedOperation)) {
            throw new Error('PROVIDER_OPERATION_MAP_KEY_INVALID');
        }
        const endpoint = normalizeEndpointConfig(endpointConfig, `PROVIDER_OPERATION_${normalizedOperation}`);
        if (!endpoint) {
            throw new Error('PROVIDER_OPERATION_MAP_INVALID');
        }
        normalized[normalizedOperation] = endpoint;
    }
    return normalized;
}

export function normalizeProviderRegistryConfig(config: unknown): ProviderRegistryConfig {
    const raw = assertObject(config || {}, 'PROVIDER_REGISTRY');
    const normalized: ProviderRegistryConfig = {
        service_root: raw.service_root ? validatePathLike(raw.service_root, 'PROVIDER_SERVICE_ROOT') : undefined,
        service_roots: normalizeServiceRoots(raw.service_roots),
        operations: normalizeOperationMap(raw.operations),
        auth: normalizeAuthConfig(raw.auth),
        endpoint: raw.endpoint ? String(raw.endpoint) : undefined,
        method: raw.method ? normalizeMethod(raw.method, 'PROVIDER_REGISTRY') : undefined,
        headers: normalizeHeaders(raw.headers, 'PROVIDER_REGISTRY'),
        payload_template: normalizePayloadTemplate(raw.payload_template, 'PROVIDER_REGISTRY'),
        response_mapping: normalizeResponseMapping(raw.response_mapping, 'PROVIDER_REGISTRY'),
        stk_push: normalizeEndpointConfig(raw.stk_push, 'PROVIDER_STK_PUSH'),
        disbursement: normalizeEndpointConfig(raw.disbursement, 'PROVIDER_DISBURSEMENT'),
        check_status: normalizeEndpointConfig(raw.check_status, 'PROVIDER_CHECK_STATUS'),
        balance: normalizeEndpointConfig(raw.balance, 'PROVIDER_BALANCE'),
        callback: normalizeCallbackConfig(raw.callback),
    };

    const hasOperations = Boolean(
        normalized.operations && Object.keys(normalized.operations).length > 0,
    ) || Boolean(
        normalized.stk_push ||
            normalized.disbursement ||
            normalized.balance ||
            normalized.check_status ||
            normalized.callback,
    );
    if (!hasOperations) {
        throw new Error('PROVIDER_REGISTRY_OPERATION_MISSING');
    }
    return normalized;
}

export function normalizePartnerType(type: unknown): FinancialPartner['type'] {
    const normalized = String(type || '').trim().toLowerCase();
    if (!PARTNER_TYPES.has(normalized)) {
        throw new Error('PROVIDER_TYPE_INVALID');
    }
    return normalized as FinancialPartner['type'];
}

export function normalizeLogicType(logicType: unknown): FinancialPartner['logic_type'] {
    const normalized = String(logicType || 'REGISTRY').trim().toUpperCase();
    if (!LOGIC_TYPES.has(normalized)) {
        throw new Error('PROVIDER_LOGIC_TYPE_INVALID');
    }
    return normalized as FinancialPartner['logic_type'];
}

export function normalizeFinancialPartnerInput(
    payload: Partial<FinancialPartner>,
    mode: 'create' | 'update' = 'create',
): Partial<FinancialPartner> {
    const normalized: Partial<FinancialPartner> = { ...payload };

    if (payload.type !== undefined || mode === 'create') {
        normalized.type = normalizePartnerType(payload.type);
    }

    if (payload.logic_type !== undefined || mode === 'create') {
        normalized.logic_type = normalizeLogicType(payload.logic_type);
    }

    if (payload.name !== undefined || mode === 'create') {
        const name = String(payload.name || '').trim();
        if (!name) throw new Error('PROVIDER_NAME_MISSING');
        normalized.name = name;
    }

    if (payload.api_base_url !== undefined) {
        normalized.api_base_url = String(payload.api_base_url || '').trim() || undefined;
    }

    if (payload.provider_metadata !== undefined) {
        normalized.provider_metadata = normalizeProviderMetadata(payload.provider_metadata);
    }

    if (payload.status !== undefined) {
        normalized.status = String(payload.status).trim().toUpperCase() as FinancialPartner['status'];
    }

    if (payload.mapping_config !== undefined || mode === 'create') {
        normalized.mapping_config = normalizeProviderRegistryConfig(payload.mapping_config || {});
    }

    return normalized;
}

export function assertPartnerActivationReady(payload: Partial<FinancialPartner>): void {
    const status = String(payload.status || '').trim().toUpperCase();
    if (status !== 'ACTIVE') {
        return;
    }

    const partnerName = String(payload.name || 'UNKNOWN_PROVIDER').trim();
    const metadata = (payload.provider_metadata || {}) as FinancialPartnerMetadata;
    const registry = payload.mapping_config as ProviderRegistryConfig | undefined;

    if (!registry) {
        throw new Error(`PROVIDER_ACTIVATION_MAPPING_CONFIG_REQUIRED:${partnerName}`);
    }

    const hasOperationEndpoint = Boolean(
        registry.operations && Object.keys(registry.operations).length > 0,
    ) || Boolean(
        registry.stk_push ||
        registry.disbursement ||
        registry.balance ||
        registry.check_status,
    );

    if (!hasOperationEndpoint) {
        throw new Error(`PROVIDER_ACTIVATION_OPERATION_REQUIRED:${partnerName}`);
    }

    if (!registry.service_root && (!registry.service_roots || Object.keys(registry.service_roots).length === 0)) {
        throw new Error(`PROVIDER_ACTIVATION_SERVICE_ROOT_REQUIRED:${partnerName}`);
    }

    if (!metadata.provider_code || !String(metadata.provider_code).trim()) {
        throw new Error(`PROVIDER_ACTIVATION_PROVIDER_CODE_REQUIRED:${partnerName}`);
    }

    if (!metadata.rail || !String(metadata.rail).trim()) {
        throw new Error(`PROVIDER_ACTIVATION_RAIL_REQUIRED:${partnerName}`);
    }

    const operations = Array.isArray(metadata.operations) ? metadata.operations : [];
    if (operations.length === 0) {
        throw new Error(`PROVIDER_ACTIVATION_OPERATIONS_METADATA_REQUIRED:${partnerName}`);
    }

    const supportsWebhook =
        metadata.supports_webhooks === true ||
        operations.map((operation) => String(operation).trim().toUpperCase()).includes('WEBHOOK_VERIFY') ||
        Boolean(registry.callback);

    if (supportsWebhook) {
        if (!registry.callback) {
            throw new Error(`PROVIDER_ACTIVATION_CALLBACK_REQUIRED:${partnerName}`);
        }
        if (!registry.callback.reference_field) {
            throw new Error(`PROVIDER_ACTIVATION_CALLBACK_REFERENCE_REQUIRED:${partnerName}`);
        }
        if (!registry.callback.status_field) {
            throw new Error(`PROVIDER_ACTIVATION_CALLBACK_STATUS_REQUIRED:${partnerName}`);
        }
    }
}
