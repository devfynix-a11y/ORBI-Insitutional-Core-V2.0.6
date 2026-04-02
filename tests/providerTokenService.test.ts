import assert from 'node:assert/strict';
import test from 'node:test';

import { providerTokenService } from '../backend/payments/providers/ProviderTokenService.js';

test('provider token service resolves static token from partner secrets', async () => {
    const token = await providerTokenService.resolveStaticToken({
        provider_metadata: {
            secrets: {
                api_key: 'secret-token',
            },
        },
    } as any);

    assert.equal(token, 'secret-token');
});

test('provider token service returns empty when no static token exists', async () => {
    const token = await providerTokenService.resolveStaticToken({} as any);
    assert.equal(token, '');
});
