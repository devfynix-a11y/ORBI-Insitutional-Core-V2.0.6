import assert from 'node:assert/strict';
import test from 'node:test';

import { providerRoutingService } from '../backend/payments/ProviderRoutingService.js';
import { InstitutionalFundsService } from '../backend/payments/InstitutionalFundsService.js';

test('routing decision metadata is exposed for movement context', async () => {
    const service = new InstitutionalFundsService();
    const originalResolve = providerRoutingService.resolveProvider.bind(providerRoutingService);

    providerRoutingService.resolveProvider = async () => ({
        providerId: 'provider-1',
        providerCode: 'PROV1',
        providerName: 'Provider One',
        rail: 'MOBILE_MONEY',
        operation: 'COLLECTION_REQUEST',
        routingDecision: {
            providerId: 'provider-1',
            providerCode: 'PROV1',
            rail: 'MOBILE_MONEY',
            operation: 'COLLECTION_REQUEST',
            source: 'routing_rule',
            ruleId: 'rule-1',
            priority: 5,
            resolvedAt: new Date().toISOString(),
        },
    } as any);

    try {
        const resolved = await (service as any).resolveProviderId({
            rail: 'MOBILE_MONEY',
            operation: 'COLLECTION_REQUEST',
            direction: 'EXTERNAL_TO_INTERNAL',
            currency: 'TZS',
            amount: 100,
            grossAmount: 100,
            netAmount: 100,
            feeAmount: 0,
            taxAmount: 0,
            description: 'Test',
            metadata: {},
        });

        assert.equal(resolved.providerId, 'provider-1');
        assert.equal(resolved.routingDecision?.source, 'routing_rule');
        assert.equal(resolved.routingDecision?.ruleId, 'rule-1');
    } finally {
        providerRoutingService.resolveProvider = originalResolve;
    }
});
