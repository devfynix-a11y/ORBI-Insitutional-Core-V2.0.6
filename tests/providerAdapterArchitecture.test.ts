import assert from 'node:assert/strict';
import test from 'node:test';

import { GenericRestProvider } from '../backend/payments/providers/GenericRestProvider.js';
import { providerCapabilityService } from '../backend/payments/ProviderCapabilityService.js';
import { providerSelectionService } from '../backend/payments/ProviderSelectionService.js';
import { providerRetryPolicy } from '../backend/payments/providers/ProviderRetryPolicy.js';
import { providerRoutingService } from '../backend/payments/ProviderRoutingService.js';

test('provider capability service classifies mobile money generically', () => {
  const capability = providerCapabilityService.describe({
    id: 'p1',
    name: 'Generic Mobile Provider',
    type: 'mobile_money',
    status: 'ACTIVE',
    supported_currencies: ['TZS'],
    provider_metadata: {
      operations: ['COLLECTION_REQUEST', 'DISBURSEMENT_REQUEST'],
      supports_webhooks: true,
      countries: ['TZ'],
      routing_priority: 10,
      provider_code: 'GENMOMO',
      rail: 'MOBILE_MONEY',
    },
    mapping_config: {
      service_root: 'https://api.example.com',
      operations: {
        COLLECTION_REQUEST: { method: 'POST', url: '/collect' },
        DISBURSEMENT_REQUEST: { method: 'POST', url: '/disburse' },
      },
      callback: { reference_field: 'ref', status_field: 'status' },
    },
  } as any);

  assert.equal(capability.category, 'mobile_money');
  assert.equal(capability.rail, 'MOBILE_MONEY');
  assert.deepEqual(capability.supportedOperations.sort(), ['COLLECTION_REQUEST', 'DISBURSEMENT_REQUEST'].sort());
});

test('generic rest provider exposes formal adapter capabilities', () => {
  const provider = new GenericRestProvider();
  const capability = provider.getCapabilities({
    id: 'p2',
    name: 'Bank Provider',
    type: 'bank',
    status: 'ACTIVE',
    provider_metadata: {
      operations: ['BALANCE_INQUIRY'],
      provider_code: 'BANK1',
      rail: 'BANK',
    },
    mapping_config: {
      service_root: 'https://api.example.com',
      operations: {
        BALANCE_INQUIRY: { method: 'GET', url: '/balance', response_mapping: { balance_field: 'data.balance' } },
      },
    },
  } as any);

  assert.equal(capability.category, 'bank');
  assert.equal(capability.providerCode, 'BANK1');
});

test('generic rest provider blocks localhost, metadata, and private-network urls', async () => {
  const provider = new GenericRestProvider();

  await assert.rejects(
    () => provider.execute({
      id: 'p-ssrf',
      name: 'Private Host Provider',
      type: 'bank',
      status: 'ACTIVE',
      mapping_config: {
        service_root: 'http://127.0.0.1',
        operations: {
          BALANCE_INQUIRY: { method: 'GET', url: '/balance' },
        },
      },
      provider_metadata: {
        operations: ['BALANCE_INQUIRY'],
        provider_code: 'SSRF1',
        rail: 'BANK',
      },
    } as any, {
      operation: 'BALANCE_INQUIRY',
      reference: 'test-balance',
    } as any),
    /PROVIDER_URL_INSECURE|PROVIDER_URL_BLOCKED_HOST/,
  );

  await assert.rejects(
    () => provider.execute({
      id: 'p-ssrf-2',
      name: 'Metadata Provider',
      type: 'bank',
      status: 'ACTIVE',
      mapping_config: {
        service_root: 'https://169.254.169.254',
        operations: {
          BALANCE_INQUIRY: { method: 'GET', url: '/latest/meta-data' },
        },
      },
      provider_metadata: {
        operations: ['BALANCE_INQUIRY'],
        provider_code: 'SSRF2',
        rail: 'BANK',
      },
    } as any, {
      operation: 'BALANCE_INQUIRY',
      reference: 'test-metadata',
    } as any),
    /PROVIDER_URL_BLOCKED_HOST/,
  );
});

test('provider selection service wraps routing selection', async () => {
  const original = providerRoutingService.resolveProvider;
  providerRoutingService.resolveProvider = async () => ({
    providerId: 'p3',
    providerCode: 'CARD1',
    providerName: 'Card Provider',
    rail: 'CARD_GATEWAY',
    operation: 'COLLECTION_REQUEST',
  } as any);

  try {
    const selected = await providerSelectionService.select({
      rail: 'CARD_GATEWAY',
      operation: 'COLLECTION_REQUEST',
    } as any);
    assert.equal(selected.resolved.providerCode, 'CARD1');
    assert.ok(selected.selectedAt);
  } finally {
    providerRoutingService.resolveProvider = original;
  }
});

test('provider retry policy invokes retry hooks', async () => {
  let retried = 0;
  let exhausted = 0;
  await assert.rejects(
    () => providerRetryPolicy.execute(
      { id: 'p4', name: 'Retry Hook Provider' } as any,
      'COLLECTION_REQUEST',
      async () => { throw new Error('NETWORK_FAIL'); },
      {
        maxAttempts: 2,
        baseDelayMs: 0,
        hooks: {
          onRetry: () => { retried += 1; },
          onExhausted: () => { exhausted += 1; },
        },
      },
    ),
  );
  assert.equal(retried, 1);
  assert.equal(exhausted, 1);
});
