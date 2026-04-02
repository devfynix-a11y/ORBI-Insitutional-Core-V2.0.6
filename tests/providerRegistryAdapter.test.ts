import assert from 'node:assert/strict';
import test from 'node:test';

import {
    assertCallbackConfig,
    assertOperationConfig,
    assertProviderRegistry,
    resolveProviderBaseUrl,
} from '../backend/payments/providers/ProviderRegistryAdapter.js';
import { ProviderFactory } from '../backend/payments/providers/ProviderFactory.js';
import { GenericRestProvider } from '../backend/payments/providers/GenericRestProvider.js';

test('provider registry adapter rejects missing registry config', () => {
    assert.throws(
        () => assertProviderRegistry({ name: 'MissingRegistry' } as any),
        /PROVIDER_REGISTRY_CONFIG_MISSING/,
    );
});

test('provider registry adapter resolves operation config or throws', () => {
    const partner = {
        name: 'RegistryPartner',
        mapping_config: {
            service_root: 'https://api.example.com',
            operations: {
                COLLECTION_REQUEST: {
                    method: 'POST',
                    url: '/collect',
                },
            },
        },
    } as any;

    const config = assertOperationConfig(partner, 'COLLECTION_REQUEST');
    assert.equal(config.method, 'POST');
    assert.equal(config.url, '/collect');

    assert.throws(
        () => assertOperationConfig(partner, 'DISBURSEMENT_REQUEST'),
        /PROVIDER_OPERATION_NOT_CONFIGURED/,
    );
});

test('provider registry adapter requires callback fields for webhook-driven providers', () => {
    const partner = {
        name: 'WebhookPartner',
        mapping_config: {
            service_root: 'https://api.example.com',
            stk_push: {
                method: 'POST',
                url: '/collect',
            },
            callback: {
                reference_field: 'data.reference',
                status_field: 'data.status',
            },
        },
    } as any;

    const callback = assertCallbackConfig(partner);
    assert.equal(callback.reference_field, 'data.reference');
    assert.equal(callback.status_field, 'data.status');

    assert.throws(
        () =>
            assertCallbackConfig({
                name: 'BrokenWebhookPartner',
                mapping_config: {
                    service_root: 'https://api.example.com',
                    stk_push: { method: 'POST', url: '/collect' },
                    callback: { reference_field: 'data.reference' },
                },
            } as any),
        /PROVIDER_CALLBACK_STATUS_FIELD_MISSING/,
    );
});

test('provider registry adapter resolves provider base url from service roots', () => {
    const partner = {
        name: 'ServiceRootPartner',
        api_base_url: 'https://fallback.example.com',
        mapping_config: {
            service_root: 'https://api.example.com',
            service_roots: {
                stk_push: 'https://collections.example.com',
            },
            stk_push: {
                method: 'POST',
                url: '/collect',
            },
        },
    } as any;

    const registry = assertProviderRegistry(partner);
    assert.equal(
        resolveProviderBaseUrl(partner, registry, 'COLLECTION_REQUEST'),
        'https://collections.example.com',
    );
    assert.equal(
        resolveProviderBaseUrl(partner, registry, 'DISBURSEMENT_REQUEST'),
        'https://api.example.com',
    );
});

test('provider factory remains registry-only', () => {
    const partner = {
        name: 'RegistryOnlyPartner',
        mapping_config: {
            service_root: 'https://api.example.com',
            operations: {
                COLLECTION_REQUEST: {
                    method: 'POST',
                    url: '/collect',
                },
            },
        },
    } as any;

    const provider = ProviderFactory.getProvider(partner);
    assert.ok(provider instanceof GenericRestProvider);
});
