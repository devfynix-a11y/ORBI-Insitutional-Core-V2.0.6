import assert from 'node:assert/strict';
import test from 'node:test';

import { providerWebhookEventLedger } from '../backend/payments/ProviderWebhookEventLedger.js';

test('provider webhook event ledger deduplicates local receipts and allows replay after failed application', async () => {
    const previousReplayMode = process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE;
    process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE = 'true';
    const ledgerAny = providerWebhookEventLedger as any;
    const previousAllowLocalStore = ledgerAny.allowLocalStore;
    const previousLocalStore = ledgerAny.localStore;
    ledgerAny.allowLocalStore = true;
    ledgerAny.localStore = new Map();

    try {
        const suffix = `itest-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
        const partnerId = `partner-${suffix}`;
        const dedupeKey = `dedupe-${suffix}`;
        const replayKey = `replay-${suffix}`;

        const first = await providerWebhookEventLedger.recordReceipt({
            partner_id: partnerId,
            dedupe_key: dedupeKey,
            replay_key: replayKey,
            provider_event_id: `evt-${suffix}`,
            reference: `REF-${suffix}`,
            normalized_status: 'processing',
            raw_status: 'PENDING',
            event_timestamp: new Date().toISOString(),
            timestamp_source: 'unit_test',
            signature_status: 'verified',
            freshness_status: 'fresh',
            verification_status: 'verified',
            payload_sha256: `sha256-${suffix}`,
            payload: { integration_test: true, phase: 'first' },
            raw_headers: { 'x-itest': suffix },
            source_ip: '127.0.0.1',
        });

        const duplicate = await providerWebhookEventLedger.recordReceipt({
            partner_id: partnerId,
            dedupe_key: dedupeKey,
            replay_key: replayKey,
            provider_event_id: `evt-${suffix}`,
            reference: `REF-${suffix}`,
            normalized_status: 'processing',
            raw_status: 'PENDING',
            event_timestamp: new Date().toISOString(),
            timestamp_source: 'unit_test',
            signature_status: 'verified',
            freshness_status: 'fresh',
            verification_status: 'verified',
            payload_sha256: `sha256-${suffix}`,
            payload: { integration_test: true, phase: 'duplicate' },
            raw_headers: { 'x-itest': suffix },
            source_ip: '127.0.0.1',
        });

        assert.equal(first.duplicate, false);
        assert.equal(duplicate.duplicate, true);
        assert.equal(duplicate.record.id, first.record.id);

        const firstClaim = await providerWebhookEventLedger.claimForApplication(first.record.id);
        const secondClaim = await providerWebhookEventLedger.claimForApplication(first.record.id);
        assert.equal(firstClaim, true);
        assert.equal(secondClaim, false);

        await providerWebhookEventLedger.markFailed(first.record.id, 'TRANSIENT_PROVIDER_ERROR', 'Temporary provider outage');
        const replayClaim = await providerWebhookEventLedger.claimForApplication(first.record.id);
        assert.equal(replayClaim, true);

        await providerWebhookEventLedger.markApplied(first.record.id);
        const postApplyClaim = await providerWebhookEventLedger.claimForApplication(first.record.id);
        assert.equal(postApplyClaim, false);
    } finally {
        ledgerAny.allowLocalStore = previousAllowLocalStore;
        ledgerAny.localStore = previousLocalStore;
        if (previousReplayMode === undefined) {
            delete process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE;
        } else {
            process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE = previousReplayMode;
        }
    }
});
