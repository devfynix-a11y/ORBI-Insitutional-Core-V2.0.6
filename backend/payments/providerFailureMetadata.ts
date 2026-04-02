import { FinancialPartner } from '../../types.js';
import { normalizeProviderError } from './providers/ProviderErrorNormalizer.js';

export function buildProviderFailureMetadata(
    error: unknown,
    partner?: FinancialPartner,
    extra: Record<string, any> = {},
): Record<string, any> {
    const normalized = normalizeProviderError(error, partner);
    return {
        provider_failure: {
            code: 'PROVIDER_ERROR',
            category: normalized.category,
            retryable: normalized.retryable,
            provider_code: normalized.providerCode || null,
            message: normalized.message,
            ...extra,
        },
    };
}

export function buildLifecycleFailureMetadata(
    reason: string,
    message: string,
    extra: Record<string, any> = {},
): Record<string, any> {
    return {
        failure_reason: reason,
        failure_details: {
            reason,
            message,
            ...extra,
        },
    };
}
