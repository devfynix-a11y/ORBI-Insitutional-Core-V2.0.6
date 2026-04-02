import crypto from 'crypto';
import { FinancialPartner } from '../../types.js';
import { RedisClusterFactory } from '../infrastructure/RedisClusterFactory.js';
import { assertCallbackConfig } from './providers/ProviderRegistryAdapter.js';
import { providerSecretVault } from './providers/ProviderSecretVault.js';

export type WebhookVerificationResult = {
    partnerId: string;
    replayKey: string;
    dedupeKey: string;
    providerEventId?: string;
    eventTimestamp?: string;
    eventTimestampSource?: string;
    freshnessStatus: 'fresh' | 'missing' | 'invalid';
    signatureStatus: 'verified' | 'not_configured';
    signatureHeader?: string;
};

export type WebhookVerificationInspection = WebhookVerificationResult & {
    payloadSha256: string;
};

export class WebhookSecurityError extends Error {
    public readonly code: string;
    public readonly inspection: WebhookVerificationInspection;

    constructor(code: string, inspection: WebhookVerificationInspection) {
        super(code);
        this.name = 'WebhookSecurityError';
        this.code = code;
        this.inspection = inspection;
    }
}

export class WebhookVerificationService {
    private readonly requireWebhookSignatures =
        process.env.ORBI_REQUIRE_WEBHOOK_SIGNATURES !== 'false';
    private readonly allowProcessLocalReplayStore =
        process.env.NODE_ENV !== 'production' &&
        process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE === 'true';
    private readonly replayWindowSeconds =
        Number(process.env.ORBI_WEBHOOK_REPLAY_WINDOW_SECONDS || 60 * 60);
    private readonly maxFreshnessSeconds =
        Number(process.env.ORBI_WEBHOOK_MAX_AGE_SECONDS || 5 * 60);
    private readonly replayStore = new Map<string, number>();

    async verifyWebhook(
        partner: FinancialPartner,
        payload: any,
        signature?: string,
        rawPayload?: string,
        explicitEventId?: string,
        headers?: Record<string, string | undefined>,
    ): Promise<WebhookVerificationResult> {
        const inspection = this.inspectWebhook(partner, payload, signature, rawPayload, explicitEventId, headers);
        const webhookSecret = await providerSecretVault.resolvePartnerSecret(partner, 'webhook_secret');

        if (inspection.eventTimestamp) {
            const timestampMs = Date.parse(inspection.eventTimestamp);
            if (Number.isNaN(timestampMs)) {
                throw new WebhookSecurityError('INVALID_TIMESTAMP', {
                    ...inspection,
                    freshnessStatus: 'invalid',
                });
            }
            const callbackConfig = this.getCallbackConfig(partner);
            const maxAgeSeconds = Number(callbackConfig.max_age_seconds || this.maxFreshnessSeconds);
            if (Math.abs(Date.now() - timestampMs) > maxAgeSeconds * 1000) {
                throw new WebhookSecurityError('STALE_TIMESTAMP', inspection);
            }
        }

        if (webhookSecret && inspection.signatureHeader) {
            const verificationPayload = rawPayload || JSON.stringify(payload || {});
            const isValid = this.verifySignature(
                verificationPayload,
                inspection.signatureHeader,
                webhookSecret,
                partner,
                inspection.eventTimestamp,
            );
            if (!isValid) {
                throw new WebhookSecurityError('INVALID_SIGNATURE', inspection);
            }
        } else if (webhookSecret && !inspection.signatureHeader) {
            throw new WebhookSecurityError('MISSING_SIGNATURE', inspection);
        } else if (this.requireWebhookSignatures && !partner.webhook_secret) {
            throw new WebhookSecurityError('WEBHOOK_SECRET_NOT_CONFIGURED', inspection);
        }

        const accepted = await this.registerReplayKey(inspection.replayKey);
        if (!accepted) {
            throw new WebhookSecurityError('REPLAY_DETECTED', inspection);
        }

        return {
            ...inspection,
        };
    }

    inspectWebhook(
        partner: FinancialPartner,
        payload: any,
        signature?: string,
        rawPayload?: string,
        explicitEventId?: string,
        headers?: Record<string, string | undefined>,
    ): WebhookVerificationInspection {
        const callbackConfig = this.getCallbackConfig(partner);
        const normalizedHeaders = this.normalizeHeaders(headers);
        const payloadString = rawPayload || JSON.stringify(payload || {});
        const payloadSha256 = crypto.createHash('sha256').update(payloadString).digest('hex');
        const signatureHeader = this.resolveSignature(signature, normalizedHeaders, callbackConfig.signature_header);
        const timestamp = this.resolveTimestamp(payload, normalizedHeaders, callbackConfig);
        const providerEventId =
            explicitEventId ||
            this.readValueByPath(payload, callbackConfig.event_id_field) ||
            this.readValueByPath(payload, callbackConfig.replay_key_field) ||
            payload?.event_id ||
            payload?.eventId ||
            undefined;
        const dedupeFingerprint = providerEventId || payloadSha256;
        const dedupeKey = `provider-webhook:${partner.id}:${dedupeFingerprint}`;
        return {
            partnerId: partner.id,
            replayKey: dedupeKey,
            dedupeKey,
            providerEventId: providerEventId ? String(providerEventId) : undefined,
            eventTimestamp: timestamp?.iso,
            eventTimestampSource: timestamp?.source,
            freshnessStatus: timestamp ? 'fresh' : 'missing',
            signatureStatus: signatureHeader ? 'verified' : 'not_configured',
            signatureHeader,
            payloadSha256,
        };
    }

    private verifySignature(
        payload: string,
        signature: string,
        secret: string,
        partner: FinancialPartner,
        timestamp?: string,
    ): boolean {
        if (!signature || !secret) return false;
        const callbackConfig = this.getCallbackConfig(partner);
        const encoding = callbackConfig.signature_encoding || 'hex';
        const mode = callbackConfig.signature_payload_mode || 'raw';
        const signaturePayload =
            mode === 'timestamp.raw' && timestamp
                ? `${this.normalizeTimestampForSignature(timestamp)}.${payload}`
                : payload;
        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(signaturePayload)
            .digest(encoding);
        const normalizedSignature = this.extractSignatureValue(signature, callbackConfig.signature_prefix);
        const expectedBuffer = Buffer.from(expectedSignature, 'utf8');
        const providedBuffer = Buffer.from(normalizedSignature, 'utf8');
        if (expectedBuffer.length !== providedBuffer.length) return false;
        return crypto.timingSafeEqual(expectedBuffer, providedBuffer);
    }

    private async registerReplayKey(key: string): Promise<boolean> {
        const redis = RedisClusterFactory.getClient('monitor');
        if (redis) {
            const result = await redis.set(key, '1', 'EX', this.replayWindowSeconds, 'NX');
            return result === 'OK';
        }

        if (!this.allowProcessLocalReplayStore) {
            return true;
        }

        const now = Date.now();
        for (const [storedKey, expiry] of this.replayStore.entries()) {
            if (expiry <= now) this.replayStore.delete(storedKey);
        }
        if (this.replayStore.has(key)) return false;
        this.replayStore.set(key, now + this.replayWindowSeconds * 1000);
        return true;
    }

    private getCallbackConfig(partner: FinancialPartner) {
        try {
            return assertCallbackConfig(partner);
        } catch {
            const mapping = (partner.mapping_config || {}) as Record<string, any>;
            return (mapping.callback || {}) as Record<string, any>;
        }
    }

    private normalizeHeaders(headers?: Record<string, string | undefined>): Record<string, string> {
        const normalized: Record<string, string> = {};
        for (const [key, value] of Object.entries(headers || {})) {
            if (typeof value === 'string') {
                normalized[key.toLowerCase()] = value;
            }
        }
        return normalized;
    }

    private resolveSignature(
        explicitSignature: string | undefined,
        headers: Record<string, string>,
        configuredHeader?: string,
    ): string | undefined {
        if (explicitSignature) return explicitSignature;
        const candidates = [
            configuredHeader,
            'x-signature',
            'x-webhook-signature',
            'x-hub-signature-256',
            'x-callback-signature',
            'authorization',
        ].filter(Boolean) as string[];
        for (const candidate of candidates) {
            const found = headers[candidate.toLowerCase()];
            if (found) return found;
        }
        return undefined;
    }

    private resolveTimestamp(
        payload: any,
        headers: Record<string, string>,
        callbackConfig: Record<string, any>,
    ): { iso: string; source: string } | undefined {
        const headerCandidates = [
            callbackConfig.timestamp_header,
            'x-timestamp',
            'x-webhook-timestamp',
            'x-event-timestamp',
        ].filter(Boolean) as string[];
        for (const candidate of headerCandidates) {
            const headerValue = headers[candidate.toLowerCase()];
            const iso = this.parseTimestamp(headerValue);
            if (iso) return { iso, source: `header:${candidate}` };
        }

        const fieldCandidates = [
            callbackConfig.timestamp_field,
            'timestamp',
            'event_timestamp',
            'occurred_at',
            'created_at',
        ].filter(Boolean) as string[];
        for (const candidate of fieldCandidates) {
            const fieldValue = this.readValueByPath(payload, candidate);
            const iso = this.parseTimestamp(fieldValue);
            if (iso) return { iso, source: `payload:${candidate}` };
        }
        return undefined;
    }

    private parseTimestamp(value: unknown): string | undefined {
        if (value === null || value === undefined || value === '') return undefined;
        if (typeof value === 'number') {
            const epochMs = value > 1e12 ? value : value * 1000;
            const date = new Date(epochMs);
            return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
        }
        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (!trimmed) return undefined;
            if (/^\d+$/.test(trimmed)) {
                return this.parseTimestamp(Number(trimmed));
            }
            const date = new Date(trimmed);
            return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
        }
        return undefined;
    }

    private normalizeTimestampForSignature(isoTimestamp: string): string {
        const date = new Date(isoTimestamp);
        return String(Math.floor(date.getTime() / 1000));
    }

    private extractSignatureValue(signature: string, configuredPrefix?: string): string {
        const trimmed = signature.trim();
        const prefixes = [configuredPrefix, 'sha256=', 'v1=', 'signature=', 'sig='].filter(Boolean) as string[];
        for (const prefix of prefixes) {
            if (trimmed.toLowerCase().startsWith(prefix.toLowerCase())) {
                return trimmed.slice(prefix.length).trim();
            }
        }
        if (trimmed.includes(',')) {
            for (const token of trimmed.split(',')) {
                const [key, value] = token.split('=');
                if (value && ['v1', 'sig', 'signature', 'sha256'].includes(key.trim().toLowerCase())) {
                    return value.trim();
                }
            }
        }
        if (/^bearer\s+/i.test(trimmed)) {
            return trimmed.replace(/^bearer\s+/i, '').trim();
        }
        return trimmed;
    }

    private readValueByPath(obj: any, path?: string): any {
        if (!path) return undefined;
        return String(path)
            .split('.')
            .reduce((acc: any, part: string) => {
                if (acc === null || acc === undefined) return undefined;
                return acc[part];
            }, obj);
    }
}

export const webhookVerificationService = new WebhookVerificationService();
