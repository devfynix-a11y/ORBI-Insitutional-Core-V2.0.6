import crypto from 'crypto';
import { getAdminSupabase, getSupabase } from '../../services/supabaseClient.js';

export type ProviderWebhookEventStatus =
    | 'received'
    | 'processing'
    | 'applied'
    | 'rejected'
    | 'failed';

export interface ProviderWebhookEventRecord {
    id: string;
    partner_id: string;
    dedupe_key: string;
    replay_key: string;
    provider_event_id?: string | null;
    reference?: string | null;
    normalized_status?: string | null;
    raw_status?: string | null;
    event_timestamp?: string | null;
    timestamp_source?: string | null;
    signature_status: string;
    freshness_status: string;
    verification_status: string;
    application_status: ProviderWebhookEventStatus;
    payload_sha256: string;
    payload?: any;
    raw_headers?: Record<string, any>;
    source_ip?: string | null;
    failure_code?: string | null;
    failure_message?: string | null;
    applied_at?: string | null;
}

class ProviderWebhookEventLedger {
    private readonly allowLocalStore =
        process.env.NODE_ENV !== 'production' &&
        process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE === 'true';
    private readonly localStore = new Map<string, ProviderWebhookEventRecord>();

    async recordReceipt(input: Omit<ProviderWebhookEventRecord, 'id' | 'application_status' | 'verification_status'> & {
        verification_status?: string;
        application_status?: ProviderWebhookEventStatus;
    }): Promise<{ record: ProviderWebhookEventRecord; duplicate: boolean }> {
        const sb = getAdminSupabase() || getSupabase();
        const baseRecord: ProviderWebhookEventRecord = {
            id: crypto.randomUUID(),
            application_status: input.application_status || 'received',
            verification_status: input.verification_status || 'pending',
            ...input,
        };

        if (!sb) {
            return this.recordLocalReceipt(baseRecord);
        }

        const { data, error } = await sb
            .from('provider_webhook_events')
            .insert(baseRecord)
            .select('*')
            .single();

        if (!error && data) {
            return { record: data as ProviderWebhookEventRecord, duplicate: false };
        }

        const { data: existing } = await sb
            .from('provider_webhook_events')
            .select('*')
            .eq('partner_id', input.partner_id)
            .eq('dedupe_key', input.dedupe_key)
            .maybeSingle();

        if (existing) {
            return { record: existing as ProviderWebhookEventRecord, duplicate: true };
        }

        throw error || new Error('WEBHOOK_EVENT_RECEIPT_FAILED');
    }

    async markRejected(id: string, failureCode: string, failureMessage: string, verificationStatus = 'rejected') {
        return this.updateRecord(id, {
            verification_status: verificationStatus,
            application_status: 'rejected',
            failure_code: failureCode,
            failure_message: failureMessage,
        });
    }

    async markVerified(id: string) {
        return this.updateRecord(id, {
            verification_status: 'verified',
        });
    }

    async markParsed(
        id: string,
        parsed: {
            reference?: string | null;
            normalized_status?: string | null;
            raw_status?: string | null;
            provider_event_id?: string | null;
        },
    ) {
        return this.updateRecord(id, {
            ...parsed,
            verification_status: 'verified',
        });
    }

    async claimForApplication(id: string): Promise<boolean> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) {
            const record = this.findLocalRecord(id);
            if (!record) return false;
            if (!['received', 'failed'].includes(record.application_status)) return false;
            record.application_status = 'processing';
            this.localStore.set(this.localKey(record.partner_id, record.dedupe_key), record);
            return true;
        }

        const { data } = await sb
            .from('provider_webhook_events')
            .update({
                application_status: 'processing',
                verification_status: 'verified',
            })
            .eq('id', id)
            .in('application_status', ['received', 'failed'])
            .select('id')
            .maybeSingle();

        return Boolean(data?.id);
    }

    async markApplied(id: string) {
        return this.updateRecord(id, {
            application_status: 'applied',
            applied_at: new Date().toISOString(),
            failure_code: null,
            failure_message: null,
        });
    }

    async markFailed(id: string, failureCode: string, failureMessage: string) {
        return this.updateRecord(id, {
            application_status: 'failed',
            failure_code: failureCode,
            failure_message: failureMessage,
        });
    }

    private async updateRecord(id: string, patch: Partial<ProviderWebhookEventRecord>) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) {
            const record = this.findLocalRecord(id);
            if (!record) return;
            const next = { ...record, ...patch };
            this.localStore.set(this.localKey(next.partner_id, next.dedupe_key), next);
            return;
        }

        await sb.from('provider_webhook_events').update(patch).eq('id', id);
    }

    private recordLocalReceipt(record: ProviderWebhookEventRecord) {
        if (!this.allowLocalStore) {
            return { record, duplicate: false };
        }
        const key = this.localKey(record.partner_id, record.dedupe_key);
        const existing = this.localStore.get(key);
        if (existing) {
            return { record: existing, duplicate: true };
        }
        this.localStore.set(key, record);
        return { record, duplicate: false };
    }

    private findLocalRecord(id: string): ProviderWebhookEventRecord | undefined {
        for (const record of this.localStore.values()) {
            if (record.id === id) return record;
        }
        return undefined;
    }

    private localKey(partnerId: string, dedupeKey: string): string {
        return `${partnerId}:${dedupeKey}`;
    }
}

export const providerWebhookEventLedger = new ProviderWebhookEventLedger();
