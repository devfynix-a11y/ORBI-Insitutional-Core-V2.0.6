
import { FinancialPartner, MoneyOperation, RailType } from '../../../types.js';

export type ProviderAdapterCategory = 'mobile_money' | 'bank' | 'card' | 'crypto';

export interface ProviderCapabilityDescriptor {
    providerId: string;
    providerCode?: string;
    providerName: string;
    category: ProviderAdapterCategory;
    rail: RailType;
    supportsWebhooks: boolean;
    supportsPolling: boolean;
    supportedOperations: MoneyOperation[];
    supportedCurrencies: string[];
    supportedCountries: string[];
    retryableOperations: MoneyOperation[];
    preferredRoutingPriority?: number;
    extra?: Record<string, any>;
}

export interface ProviderExecutionRequest {
    operation: MoneyOperation;
    partner?: FinancialPartner;
    reference: string;
    amount?: number;
    currency?: string;
    phone?: string;
    accountNumber?: string;
    destinationTag?: string;
    externalReference?: string;
    metadata?: Record<string, any>;
    idempotencyKey?: string;
}

export interface ProviderExecutionResponse {
    success: boolean;
    providerRef: string;
    status: 'accepted' | 'processing' | 'completed' | 'failed' | 'pending';
    message: string;
    externalId?: string;
    rawPayload?: any;
    balance?: number;
    metadata?: Record<string, any>;
}

export type ProviderErrorCategory =
    | 'AUTH'
    | 'CONFIG'
    | 'NETWORK'
    | 'TIMEOUT'
    | 'REJECTED'
    | 'INVALID_RESPONSE'
    | 'RATE_LIMIT'
    | 'UNAVAILABLE'
    | 'UNKNOWN';

export interface NormalizedProviderError {
    category: ProviderErrorCategory;
    providerCode?: string;
    message: string;
    retryable: boolean;
    raw?: any;
    statusCode?: number;
}

export interface ProviderCallbackResult {
    reference: string;
    status: 'completed' | 'failed' | 'processing' | 'pending';
    message: string;
    providerEventId?: string;
    rawStatus?: string;
}

export type RetryOperation =
    | 'AUTHENTICATE'
    | 'COLLECTION_REQUEST'
    | 'DISBURSEMENT_REQUEST'
    | 'BALANCE_INQUIRY'
    | 'WEBHOOK_PARSE';

export type RetryHookContext = {
    partner: FinancialPartner;
    operation: RetryOperation;
    attempt: number;
    maxAttempts: number;
    error: NormalizedProviderError;
};

export type RetryHooks = {
    onRetry?: (context: RetryHookContext) => Promise<void> | void;
    onExhausted?: (context: RetryHookContext) => Promise<void> | void;
    onFailoverCandidate?: (context: RetryHookContext) => Promise<FinancialPartner | null | undefined> | FinancialPartner | null | undefined;
};

/**
 * Formal provider adapter contract.
 * All provider categories execute through this normalized request/response boundary.
 */
export interface IProviderAdapter {
    authenticate(partner: FinancialPartner): Promise<string>;
    getCapabilities(partner: FinancialPartner): ProviderCapabilityDescriptor;
    execute(partner: FinancialPartner, request: ProviderExecutionRequest): Promise<ProviderExecutionResponse>;
    parseCallback(
        payload: any,
        partner?: FinancialPartner,
        context?: { headers?: Record<string, string | undefined> },
    ): ProviderCallbackResult;
    getBalance(partner: FinancialPartner): Promise<number>;

    // Compatibility shims for legacy call sites while the rest of the codebase migrates.
    stkPush(partner: FinancialPartner, phone: string, amount: number, reference: string): Promise<ProviderExecutionResponse>;
    disburse(partner: FinancialPartner, phone: string, amount: number, reference: string): Promise<ProviderExecutionResponse>;
}

export type IPaymentProvider = IProviderAdapter;
export type ProviderResponse = ProviderExecutionResponse;
