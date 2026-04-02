import { TransactionService } from '../../ledger/transactionService.js';
import { Audit } from '../security/audit.js';
import { getAdminSupabase, getSupabase } from '../../services/supabaseClient.js';
import { UUID } from '../../services/utils.js';
import { ProviderFactory } from './providers/ProviderFactory.js';
import { toProviderDomainError } from './providers/ProviderErrorNormalizer.js';
import { providerRetryPolicy } from './providers/ProviderRetryPolicy.js';
import {
    WebhookSecurityError,
    webhookVerificationService,
} from './WebhookVerificationService.js';
import { institutionalFundsService } from './InstitutionalFundsService.js';
import { providerWebhookEventLedger } from './ProviderWebhookEventLedger.js';
import { logger } from '../infrastructure/logger.js';

/**
 * SOVEREIGN WEBHOOK LISTENER (V4.0)
 * -------------------------
 */
const webhookLogger = logger.child({ component: 'webhook_handler' });

class WebhookHandler {
    private ledger = new TransactionService();

    /**
     * PROCESS PROVIDER CALLBACK
     */
    public async handleCallback(
        payload: any,
        partnerId: string,
        context: {
            signature?: string;
            rawPayload?: string;
            explicitEventId?: string;
            headers?: Record<string, string | undefined>;
            sourceIp?: string;
        } = {},
    ) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        const { data: partner } = await sb.from('financial_partners').select('*').eq('id', partnerId).single();
        if (!partner) {
            webhookLogger.error('webhook.partner_unknown', { partner_id: partnerId });
            return;
        }

        const inspection = webhookVerificationService.inspectWebhook(
            partner,
            payload,
            context.signature,
            context.rawPayload,
            context.explicitEventId,
            context.headers,
        );
        const receipt = await providerWebhookEventLedger.recordReceipt({
            partner_id: partner.id,
            provider_event_id: inspection.providerEventId || null,
            dedupe_key: inspection.dedupeKey,
            replay_key: inspection.replayKey,
            event_timestamp: inspection.eventTimestamp || null,
            timestamp_source: inspection.eventTimestampSource || null,
            signature_status: inspection.signatureStatus,
            freshness_status: inspection.freshnessStatus,
            verification_status: 'pending',
            payload_sha256: inspection.payloadSha256,
            payload,
            raw_headers: context.headers || {},
            source_ip: context.sourceIp || null,
        });

        if (receipt.duplicate && ['applied', 'processing', 'rejected'].includes(receipt.record.application_status)) {
            await Audit.log('FINANCIAL', 'SYSTEM', 'WEBHOOK_DUPLICATE_IGNORED', {
                partnerId,
                providerEventId: receipt.record.provider_event_id,
                dedupeKey: receipt.record.dedupe_key,
                applicationStatus: receipt.record.application_status,
            });
            return { duplicate: true, eventId: receipt.record.id };
        }

        try {
            await webhookVerificationService.verifyWebhook(
                partner,
                payload,
                context.signature,
                context.rawPayload,
                context.explicitEventId,
                context.headers,
            );
            await providerWebhookEventLedger.markVerified(receipt.record.id);
        } catch (verificationError: any) {
            const message = String(verificationError?.message || verificationError);
            const inspectionFromError =
                verificationError instanceof WebhookSecurityError
                    ? verificationError.inspection
                    : inspection;
            if (message === 'INVALID_SIGNATURE') {
                webhookLogger.error('webhook.invalid_signature', { partner_id: partnerId, partner_name: partner.name, payload_sha256: inspectionFromError.payloadSha256, provider_event_id: inspectionFromError.providerEventId });
                await Audit.log('SECURITY', 'SYSTEM', 'WEBHOOK_SIGNATURE_FAILED', {
                    partnerId,
                    payloadSha256: inspectionFromError.payloadSha256,
                    providerEventId: inspectionFromError.providerEventId,
                });
            } else if (message === 'MISSING_SIGNATURE') {
                webhookLogger.error('webhook.missing_signature', { partner_id: partnerId, partner_name: partner.name });
                await Audit.log('SECURITY', 'SYSTEM', 'WEBHOOK_SIGNATURE_MISSING', { partnerId });
            } else if (message === 'WEBHOOK_SECRET_NOT_CONFIGURED') {
                webhookLogger.error('webhook.secret_missing', { partner_id: partnerId, partner_name: partner.name });
                await Audit.log('SECURITY', 'SYSTEM', 'WEBHOOK_SECRET_MISSING', { partnerId });
            } else if (message === 'REPLAY_DETECTED') {
                webhookLogger.warn('webhook.replay_detected', { partner_id: partnerId, partner_name: partner.name, dedupe_key: inspectionFromError.dedupeKey });
                await Audit.log('SECURITY', 'SYSTEM', 'WEBHOOK_REPLAY_BLOCKED', {
                    partnerId,
                    dedupeKey: inspectionFromError.dedupeKey,
                });
            } else if (message === 'STALE_TIMESTAMP' || message === 'INVALID_TIMESTAMP') {
                await Audit.log('SECURITY', 'SYSTEM', 'WEBHOOK_TIMESTAMP_REJECTED', {
                    partnerId,
                    providerEventId: inspectionFromError.providerEventId,
                    eventTimestamp: inspectionFromError.eventTimestamp,
                    source: inspectionFromError.eventTimestampSource,
                    reason: message,
                });
            }
            await providerWebhookEventLedger.markRejected(receipt.record.id, message, message);
            throw verificationError;
        }

        const providerNode = ProviderFactory.getProvider(partner);
        let callback;
        try {
            callback = await providerRetryPolicy.execute(
                partner,
                'WEBHOOK_PARSE',
                async () => providerNode.parseCallback(payload, partner, { headers: context.headers }),
                { maxAttempts: 1 },
            );
        } catch (parseError: any) {
            const normalized = toProviderDomainError(parseError, partner);
            await providerWebhookEventLedger.markFailed(
                receipt.record.id,
                'WEBHOOK_PARSE_FAILED',
                normalized.message,
            );
            await Audit.log('SECURITY', 'SYSTEM', 'WEBHOOK_PARSE_FAILED', {
                partnerId,
                providerCode: normalized.providerCode,
                category: normalized.category,
                retryable: normalized.retryable,
                message: normalized.message,
            });
            throw normalized;
        }
        const { reference, status, message, providerEventId } = callback;
        await providerWebhookEventLedger.markParsed(receipt.record.id, {
            reference,
            normalized_status: status,
            raw_status: callback.rawStatus || null,
            provider_event_id: providerEventId || inspection.providerEventId || null,
        });

        const claimed = await providerWebhookEventLedger.claimForApplication(receipt.record.id);
        if (!claimed) {
            await Audit.log('FINANCIAL', 'SYSTEM', 'WEBHOOK_DUPLICATE_IGNORED', {
                partnerId,
                providerEventId: providerEventId || inspection.providerEventId,
                dedupeKey: inspection.dedupeKey,
                reference,
            });
            return { duplicate: true, eventId: receipt.record.id };
        }

        webhookLogger.info('webhook.signal_received', { partner_id: partner.id, partner_name: partner.name, reference_id: reference, provider_event_id: providerEventId || inspection.providerEventId, normalized_status: status, event_ledger_id: receipt.record.id });

        try {
            const result = await this.applyNormalizedCallback(
                sb,
                partner,
                {
                    reference,
                    status,
                    message,
                    providerEventId: providerEventId || inspection.providerEventId,
                },
                payload,
            );
            await providerWebhookEventLedger.markApplied(receipt.record.id);
            await Audit.log('FINANCIAL', 'SYSTEM', 'WEBHOOK_PROCESSED', {
                provider: partner.name,
                reference,
                status,
                providerEventId: providerEventId || inspection.providerEventId,
                traceId: UUID.generate(),
                eventLedgerId: receipt.record.id,
                route: result?.route || 'TRANSACTION',
                movementId: result?.movementId || null,
            });
            return result;
        } catch (applicationError: any) {
            await providerWebhookEventLedger.markFailed(
                receipt.record.id,
                applicationError?.message || 'WEBHOOK_APPLICATION_FAILED',
                String(applicationError?.message || applicationError),
            );
            await Audit.log('FINANCIAL', 'SYSTEM', 'WEBHOOK_APPLICATION_FAILED', {
                partner: partner.name,
                partnerId: partner.id,
                reference,
                status,
                providerEventId: providerEventId || inspection.providerEventId,
                eventLedgerId: receipt.record.id,
                message: String(applicationError?.message || applicationError),
            });
            throw applicationError;
        }
    }

    private async applyNormalizedCallback(
        sb: any,
        partner: any,
        callback: {
            reference: string;
            status: 'completed' | 'failed' | 'processing' | 'pending';
            message: string;
            providerEventId?: string;
        },
        rawPayload: any,
    ) {
        const { reference, status, message, providerEventId } = callback;

        const { data: tx } = await sb.from('transactions')
            .select('*')
            .or(`id.eq.${reference},reference_id.eq.${reference}`)
            .maybeSingle();

        if (!tx) {
            try {
                const depositResult = await institutionalFundsService.handleWebhookDepositIntent(
                    partner.id,
                    reference,
                    status,
                    message,
                    providerEventId,
                    rawPayload,
                );
                return {
                    route: 'EXTERNAL_DEPOSIT_INTENT',
                    movementId: depositResult?.movement?.id || null,
                    result: depositResult,
                };
            } catch {
                const movementResult = await institutionalFundsService.handleWebhookMovement(
                    partner.id,
                    reference,
                    status,
                    message,
                    providerEventId,
                    rawPayload,
                );
                return {
                    route: 'EXTERNAL_MOVEMENT',
                    movementId: movementResult?.movement?.id || null,
                    result: movementResult,
                };
            }
        }

        const txId = tx.id;
        if (status === 'completed') {
            await this.ledger.updateTransactionStatus(txId, 'completed', `Verified by ${partner.name}: ${message}`);
        } else if (status === 'processing' || status === 'pending') {
            await this.ledger.updateTransactionStatus(txId, 'processing', `Processor update from ${partner.name}: ${message}`);
        } else {
            await this.ledger.updateTransactionStatus(txId, 'failed', message || 'Provider rejection.');
        }

        return {
            route: 'TRANSACTION',
            txId,
        };
    }
}

export const Webhooks = new WebhookHandler();
