
import { TransactionService } from '../../ledger/transactionService.js';
import { Audit } from '../security/audit.js';
import { getAdminSupabase, getSupabase } from '../../services/supabaseClient.js';
import { RegulatoryService } from '../ledger/regulatoryService.js';
import { UUID } from '../../services/utils.js';
import { ProviderFactory } from './providers/ProviderFactory.js';
import crypto from 'crypto';
import { DataVault } from '../security/encryption.js';
import { RedisClusterFactory } from '../infrastructure/RedisClusterFactory.js';
import { institutionalFundsService } from './InstitutionalFundsService.js';

/**
 * SOVEREIGN WEBHOOK LISTENER (V4.0)
 * -------------------------
 */
class WebhookHandler {
    private ledger = new TransactionService();
    private readonly requireWebhookSignatures =
        process.env.ORBI_REQUIRE_WEBHOOK_SIGNATURES !== 'false';
    private readonly allowProcessLocalReplayStore =
        process.env.NODE_ENV !== 'production' &&
        process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE === 'true';
    private readonly replayWindowSeconds =
        Number(process.env.ORBI_WEBHOOK_REPLAY_WINDOW_SECONDS || 60 * 60);
    private readonly replayStore = new Map<string, number>();

    /**
     * VERIFY HMAC SIGNATURE
     */
    private verifySignature(payload: any, signature: string, secret: string): boolean {
        if (!signature || !secret) return false;
        const payloadString = typeof payload === 'string' ? payload : JSON.stringify(payload);
        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(payloadString)
            .digest('hex');
        // Use timingSafeEqual to prevent timing attacks
        const normalizedSignature = signature.replace(/^sha256=/i, '').trim();
        const expectedBuffer = Buffer.from(expectedSignature, 'utf8');
        const providedBuffer = Buffer.from(normalizedSignature, 'utf8');
        if (expectedBuffer.length !== providedBuffer.length) return false;
        return crypto.timingSafeEqual(expectedBuffer, providedBuffer);
    }

    private computeReplayKey(
        partnerId: string,
        payload: any,
        rawPayload?: string,
        explicitEventId?: string,
    ): string {
        const stablePayload = rawPayload || JSON.stringify(payload || {});
        const fingerprint = explicitEventId || crypto.createHash('sha256').update(stablePayload).digest('hex');
        return `webhook:${partnerId}:${fingerprint}`;
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

    /**
     * PROCESS PROVIDER CALLBACK
     */
    public async handleCallback(
        payload: any,
        partnerId: string,
        signature?: string,
        rawPayload?: string,
        explicitEventId?: string,
    ) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        // 1. Resolve Partner Metadata for Parsing Logic
        const { data: partner } = await sb.from('financial_partners').select('*').eq('id', partnerId).single();
        if (!partner) {
            console.error(`[Webhook] PARTNER_UNKNOWN: id ${partnerId}`);
            return;
        }

        // 2. Verify Signature (CRITICAL FOR BANKING)
        const webhookSecret =
            typeof partner.webhook_secret === 'string'
                ? await DataVault.decrypt(partner.webhook_secret)
                : '';

        if (webhookSecret && signature) {
            const verificationPayload = rawPayload || payload;
            const isValid = this.verifySignature(verificationPayload, signature, webhookSecret);
            if (!isValid) {
                console.error(`[Webhook] SECURITY_ALERT: Invalid signature for partner ${partner.name}`);
                await Audit.log('SECURITY', 'SYSTEM', 'WEBHOOK_SIGNATURE_FAILED', { partnerId, payload });
                throw new Error('INVALID_SIGNATURE');
            }
        } else if (webhookSecret && !signature) {
            console.error(`[Webhook] SECURITY_ALERT: Missing signature for partner ${partner.name}`);
            await Audit.log('SECURITY', 'SYSTEM', 'WEBHOOK_SIGNATURE_MISSING', { partnerId });
            throw new Error('MISSING_SIGNATURE');
        } else if (this.requireWebhookSignatures && !partner.webhook_secret) {
            console.error(`[Webhook] SECURITY_ALERT: No webhook secret configured for partner ${partner.name}`);
            await Audit.log('SECURITY', 'SYSTEM', 'WEBHOOK_SECRET_MISSING', { partnerId });
            throw new Error('WEBHOOK_SECRET_NOT_CONFIGURED');
        }

        const replayKey = this.computeReplayKey(partnerId, payload, rawPayload, explicitEventId);
        const accepted = await this.registerReplayKey(replayKey);
        if (!accepted) {
            console.warn(`[Webhook] REPLAY_DETECTED for partner ${partner.name}`);
            await Audit.log('SECURITY', 'SYSTEM', 'WEBHOOK_REPLAY_BLOCKED', { partnerId, replayKey });
            throw new Error('REPLAY_DETECTED');
        }

        const providerNode = ProviderFactory.getProvider(partner);
        const { reference, status, message, providerEventId } = providerNode.parseCallback(payload, partner);
        
        console.info(`[Webhook] Signal for ${reference} from ${partner.name}: ${status}`);

        // 2. Try the standard transaction trace first
        const { data: tx } = await sb.from('transactions')
            .select('*')
            .or(`id.eq.${reference},reference_id.eq.${reference}`)
            .maybeSingle();
        
        if (!tx) {
            try {
                const depositResult = await institutionalFundsService.handleWebhookDepositIntent(
                    partnerId,
                    reference,
                    status,
                    message,
                    providerEventId,
                    payload,
                );
                await Audit.log('FINANCIAL', 'SYSTEM', 'WEBHOOK_PROCESSED', {
                    provider: partner.name,
                    reference,
                    status,
                    providerEventId,
                    traceId: UUID.generate(),
                    route: 'EXTERNAL_DEPOSIT_INTENT',
                    movementId: (depositResult as any)?.movement?.id || null,
                });
                return depositResult;
            } catch (depositError: any) {
                console.error(`[Webhook] TRACE_LOST: Unknown tx ${reference}`);
                throw depositError;
            }
        }

        const txId = tx.id;

        // 3. Finalize Ledger Update
        if (status === 'completed') {
            await this.ledger.updateTransactionStatus(txId, 'completed', `Verified by ${partner.name}: ${message}`);
        } else if (status === 'processing' || status === 'pending') {
            await this.ledger.updateTransactionStatus(txId, 'processing', `Processor update from ${partner.name}: ${message}`);
        } else {
            await this.ledger.updateTransactionStatus(txId, 'failed', message || 'Provider rejection.');
        }

        await Audit.log('FINANCIAL', 'SYSTEM', 'WEBHOOK_PROCESSED', { 
            provider: partner.name, reference, status, providerEventId, traceId: UUID.generate() 
        });
    }
}

export const Webhooks = new WebhookHandler();
