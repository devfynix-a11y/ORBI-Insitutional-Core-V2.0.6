import { FinancialPartner } from '../../../types.js';
import { normalizeProviderError, toProviderDomainError } from './ProviderErrorNormalizer.js';
import { RetryHooks, RetryOperation } from './types.js';

type RetryOptions = {
    maxAttempts?: number;
    baseDelayMs?: number;
    hooks?: RetryHooks;
};

const sleep = async (ms: number): Promise<void> => {
    await new Promise((resolve) => setTimeout(resolve, ms));
};

export class ProviderRetryPolicy {
    private readonly defaultMaxAttempts = Number(process.env.ORBI_PROVIDER_MAX_ATTEMPTS || 3);
    private readonly defaultBaseDelayMs = Number(process.env.ORBI_PROVIDER_RETRY_DELAY_MS || 250);

    async execute<T>(
        partner: FinancialPartner,
        operation: RetryOperation,
        work: () => Promise<T>,
        options: RetryOptions = {},
    ): Promise<T> {
        const maxAttempts = Math.max(1, Number(options.maxAttempts || this.defaultMaxAttempts));
        const baseDelayMs = Math.max(0, Number(options.baseDelayMs || this.defaultBaseDelayMs));
        const hooks = options.hooks;

        let lastError: unknown;
        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
            try {
                return await work();
            } catch (error: any) {
                const normalized = normalizeProviderError(error, partner);
                lastError = toProviderDomainError(error, partner);
                const shouldRetry = normalized.retryable && attempt < maxAttempts;
                const hookContext = {
                    partner,
                    operation,
                    attempt,
                    maxAttempts,
                    error: normalized,
                };

                if (!shouldRetry) {
                    await hooks?.onExhausted?.(hookContext);
                    throw lastError;
                }

                await hooks?.onRetry?.(hookContext);
                await hooks?.onFailoverCandidate?.(hookContext);
                const delayMs = baseDelayMs * attempt;
                console.warn(
                    `[ProviderRetryPolicy] Retrying ${operation} for ${partner.name} after ${normalized.category} failure (attempt ${attempt}/${maxAttempts})`,
                );
                if (delayMs > 0) {
                    await sleep(delayMs);
                }
            }
        }

        throw toProviderDomainError(lastError, partner);
    }
}

export const providerRetryPolicy = new ProviderRetryPolicy();
