import { NormalizedProviderError, ProviderErrorCategory } from './types.js';
import { FinancialPartner } from '../../../types.js';
import { resolveProviderCode } from '../financialPartnerMetadata.js';

const normalizeCategory = (message: string, statusCode?: number): ProviderErrorCategory => {
    const upper = message.toUpperCase();
    if (statusCode === 429 || upper.includes('RATE LIMIT')) return 'RATE_LIMIT';
    if (statusCode === 503 || statusCode === 502 || upper.includes('UNAVAILABLE')) return 'UNAVAILABLE';
    if (upper.includes('AUTH') || upper.includes('TOKEN') || upper.includes('CREDENTIAL')) return 'AUTH';
    if (upper.includes('CONFIG') || upper.includes('MISSING')) return 'CONFIG';
    if (upper.includes('TIMEOUT') || upper.includes('ABORTED')) return 'TIMEOUT';
    if (upper.includes('ECONN') || upper.includes('ENOTFOUND') || upper.includes('NETWORK')) return 'NETWORK';
    if (upper.includes('REJECT') || upper.includes('DECLIN') || upper.includes('FAILED')) return 'REJECTED';
    if (upper.includes('INVALID') || upper.includes('UNEXPECTED')) return 'INVALID_RESPONSE';
    return 'UNKNOWN';
};

const isRetryable = (category: ProviderErrorCategory): boolean => {
    return ['NETWORK', 'TIMEOUT', 'RATE_LIMIT', 'UNAVAILABLE'].includes(category);
};

export class ProviderDomainError extends Error {
    public readonly code = 'PROVIDER_ERROR';
    public readonly category: ProviderErrorCategory;
    public readonly retryable: boolean;
    public readonly providerCode?: string;
    public readonly raw?: any;
    public readonly statusCode?: number;

    constructor(normalized: NormalizedProviderError) {
        super(normalized.message);
        this.name = 'ProviderDomainError';
        this.category = normalized.category;
        this.retryable = normalized.retryable;
        this.providerCode = normalized.providerCode;
        this.raw = normalized.raw;
        this.statusCode = normalized.statusCode;
    }
}

export const normalizeProviderError = (
    error: any,
    partner?: FinancialPartner,
): NormalizedProviderError => {
    const message = String(error?.message || error || 'PROVIDER_ERROR');
    const statusCode = Number(error?.statusCode || error?.status || error?.response?.status || 0) || undefined;
    const category = normalizeCategory(message, statusCode);
    return {
        category,
        providerCode: resolveProviderCode(partner),
        message,
        retryable: isRetryable(category),
        raw: error,
        statusCode,
    };
};

export const toProviderDomainError = (
    error: any,
    partner?: FinancialPartner,
): ProviderDomainError => {
    if (error instanceof ProviderDomainError) {
        return error;
    }
    return new ProviderDomainError(normalizeProviderError(error, partner));
};

export const isProviderRetryableError = (error: any): boolean => {
    if (error instanceof ProviderDomainError) {
        return error.retryable;
    }
    return false;
};
