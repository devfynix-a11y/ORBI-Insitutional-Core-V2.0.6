import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';

import { webhookVerificationService } from '../backend/payments/WebhookVerificationService.js';

test('webhook verification rejects missing signature when secret is configured', async () => {
    await assert.rejects(
        () =>
            webhookVerificationService.verifyWebhook(
                {
                    id: 'partner-1',
                    webhook_secret: 'encrypted',
                } as any,
                { foo: 'bar' },
                undefined,
                JSON.stringify({ foo: 'bar' }),
                'evt-1',
            ),
        /MISSING_SIGNATURE|WEBHOOK_SECRET_NOT_CONFIGURED|INVALID_SIGNATURE/,
    );
});

test('webhook verification accepts valid signed payload with timestamp freshness', async () => {
    process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE = 'true';
    const timestamp = String(Math.floor(Date.now() / 1000));
    const rawPayload = JSON.stringify({ event_id: 'evt-2', status: 'SUCCESS' });
    const signature = crypto
        .createHmac('sha256', 'topsecret')
        .update(`${timestamp}.${rawPayload}`)
        .digest('hex');

    const result = await webhookVerificationService.verifyWebhook(
        {
            id: 'partner-2',
            webhook_secret: 'topsecret',
            mapping_config: {
                callback: {
                    event_id_field: 'event_id',
                    timestamp_header: 'x-timestamp',
                    signature_payload_mode: 'timestamp.raw',
                    max_age_seconds: 300,
                },
            },
        } as any,
        JSON.parse(rawPayload),
        signature,
        rawPayload,
        undefined,
        { 'x-timestamp': timestamp },
    );

    assert.equal(result.providerEventId, 'evt-2');
    assert.equal(result.freshnessStatus, 'fresh');
});

test('webhook verification rejects stale timestamps when provided', async () => {
    process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE = 'true';
    const staleTimestamp = String(Math.floor(Date.now() / 1000) - 3600);
    const rawPayload = JSON.stringify({ event_id: 'evt-3' });
    const signature = crypto
        .createHmac('sha256', 'topsecret')
        .update(`${staleTimestamp}.${rawPayload}`)
        .digest('hex');

    await assert.rejects(
        () =>
            webhookVerificationService.verifyWebhook(
                {
                    id: 'partner-3',
                    webhook_secret: 'topsecret',
                    mapping_config: {
                        callback: {
                            timestamp_header: 'x-timestamp',
                            signature_payload_mode: 'timestamp.raw',
                            max_age_seconds: 60,
                        },
                    },
                } as any,
                JSON.parse(rawPayload),
                signature,
                rawPayload,
                undefined,
                { 'x-timestamp': staleTimestamp },
            ),
        /STALE_TIMESTAMP/,
    );
});
