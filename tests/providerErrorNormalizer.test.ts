import assert from 'node:assert/strict';
import test from 'node:test';

import {
    ProviderDomainError,
    normalizeProviderError,
    toProviderDomainError,
} from '../backend/payments/providers/ProviderErrorNormalizer.js';

test('normalizeProviderError categorizes network failures as retryable', () => {
    const normalized = normalizeProviderError(new Error('ECONNRESET: socket hang up'));
    assert.equal(normalized.category, 'NETWORK');
    assert.equal(normalized.retryable, true);
});

test('normalizeProviderError categorizes auth failures as non-retryable', () => {
    const normalized = normalizeProviderError(new Error('AUTH_TOKEN_MISSING'));
    assert.equal(normalized.category, 'AUTH');
    assert.equal(normalized.retryable, false);
});

test('toProviderDomainError preserves normalized provider semantics', () => {
    const error = toProviderDomainError(
        new Error('ECONNRESET while contacting partner'),
        { name: 'Test Partner', provider_metadata: { provider_code: 'TESTPAY' } } as any,
    );

    assert.ok(error instanceof ProviderDomainError);
    assert.equal(error.code, 'PROVIDER_ERROR');
    assert.equal(error.category, 'NETWORK');
    assert.equal(error.retryable, true);
    assert.equal(error.providerCode, 'TESTPAY');
});
