import assert from 'node:assert/strict';
import test from 'node:test';

import { providerRetryPolicy } from '../backend/payments/providers/ProviderRetryPolicy.js';
import { ProviderDomainError } from '../backend/payments/providers/ProviderErrorNormalizer.js';

const partner = {
    name: 'Retry Partner',
    provider_metadata: {
        provider_code: 'RETRYPAY',
    },
} as any;

test('provider retry policy retries retryable failures and succeeds', async () => {
    let attempts = 0;
    const result = await providerRetryPolicy.execute(
        partner,
        'COLLECTION_REQUEST',
        async () => {
            attempts += 1;
            if (attempts < 3) {
                throw new Error('ECONNRESET while reaching upstream');
            }
            return 'ok';
        },
        { maxAttempts: 3, baseDelayMs: 0 },
    );

    assert.equal(result, 'ok');
    assert.equal(attempts, 3);
});

test('provider retry policy does not retry non-retryable failures', async () => {
    let attempts = 0;
    await assert.rejects(
        () =>
            providerRetryPolicy.execute(
                partner,
                'DISBURSEMENT_REQUEST',
                async () => {
                    attempts += 1;
                    throw new Error('AUTH_TOKEN_MISSING');
                },
                { maxAttempts: 3, baseDelayMs: 0 },
            ),
        (error: any) => {
            assert.ok(error instanceof ProviderDomainError);
            assert.equal(error.category, 'AUTH');
            assert.equal(error.retryable, false);
            return true;
        },
    );

    assert.equal(attempts, 1);
});
