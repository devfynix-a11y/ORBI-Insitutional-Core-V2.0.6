import { getAdminSupabase } from '../supabaseClient.js';
import { UUID } from '../../services/utils.js';
import { Audit } from '../security/audit.js';
import { OfflineMessageType, OfflineSessionStatus } from '../../types.js';
import { offlineOrbiBridge } from './OfflineOrbiBridge.js';

type GatewayPayload = {
    gatewayId: string;
    phoneNumber: string;
    messageBody: string;
    receivedAt?: string;
    carrierRef?: string;
    channel?: string;
};

type ParsedOfflineMessage = {
    raw: string;
    prefix: string;
    type: string;
    version: string;
    requestId: string;
    parts: string[];
};

export class OfflineGatewayService {
    async handleInboundRequest(payload: GatewayPayload) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const parsed = this.parseMessage(payload.messageBody);
        this.validateMessage(parsed);
        const messageType = this.classifyMessage(parsed);
        const now = payload.receivedAt || new Date().toISOString();

        await sb.from('inbound_sms_messages').insert({
            gateway_id: payload.gatewayId,
            phone_number: payload.phoneNumber,
            raw_message: payload.messageBody,
            normalized_message: payload.messageBody,
            message_type: messageType,
            request_id: parsed.requestId,
            carrier_ref: payload.carrierRef || null,
            received_at: now,
            parse_status: 'PARSED',
            signature_status: 'NOT_VERIFIED',
        });

        if (messageType === 'APP_OFFLINE_CONFIRM' || messageType === 'CHALLENGE_RESPONSE') {
            return this.handleConfirmation({
                requestId: parsed.requestId,
                confirmationCode: parsed.parts[0] || '',
                phoneNumber: payload.phoneNumber,
                receivedAt: now,
            });
        }

        const amount = Number(parsed.parts[1] || 0);
        const currency = String(parsed.parts[2] || 'TZS').trim().toUpperCase();
        const sourceWalletId = parsed.parts[3] || null;
        const budgetId = parsed.parts[4] || null;
        const recipientRef = parsed.parts[5] || null;
        const challengeCode = this.generateChallengeCode();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

        const { data: session, error } = await sb
            .from('offline_transaction_sessions')
            .insert({
                request_id: parsed.requestId,
                phone_number: payload.phoneNumber,
                action: parsed.parts[0] || 'UNKNOWN',
                amount: Number.isFinite(amount) ? amount : null,
                currency,
                source_wallet_id: sourceWalletId,
                budget_id: budgetId,
                recipient_ref: recipientRef,
                status: 'PENDING_CONFIRMATION',
                challenge_code: challengeCode,
                expires_at: expiresAt,
                correlation_id: UUID.generate(),
                metadata: {
                    gateway_id: payload.gatewayId,
                    channel: payload.channel || 'SMS',
                    parsed_parts: parsed.parts,
                    message_type: messageType,
                },
                created_at: now,
                updated_at: now,
            })
            .select('*')
            .single();

        if (error) {
            if (String(error.message || '').toLowerCase().includes('duplicate')) {
                throw new Error('OFFLINE_DUPLICATE_REQUEST');
            }
            throw new Error(error.message);
        }

        await sb.from('outbound_sms_messages').insert({
            request_id: parsed.requestId,
            phone_number: payload.phoneNumber,
            message_body: this.formatChallenge(parsed.requestId, challengeCode),
            message_type: 'CHALLENGE',
            send_status: 'QUEUED',
        });

        await Audit.log('FINANCIAL', 'SYSTEM', 'OFFLINE_REQUEST_RECEIVED', {
            requestId: parsed.requestId,
            phoneNumber: payload.phoneNumber,
            messageType,
            sessionId: session.id,
        });

        return {
            session,
            responseMessage: this.formatChallenge(parsed.requestId, challengeCode),
        };
    }

    async handleConfirmation(input: {
        requestId: string;
        confirmationCode: string;
        phoneNumber: string;
        receivedAt?: string;
    }) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const { data: session, error } = await sb
            .from('offline_transaction_sessions')
            .select('*')
            .eq('request_id', input.requestId)
            .maybeSingle();

        if (error) throw new Error(error.message);
        if (!session) throw new Error('OFFLINE_SESSION_NOT_FOUND');

        if (session.phone_number !== input.phoneNumber) {
            throw new Error('OFFLINE_PHONE_MISMATCH');
        }

        if (session.status === 'SUCCESS') {
            return {
                session,
                responseMessage: this.formatSuccess(input.requestId, session.correlation_id || session.id),
            };
        }

        if (session.challenge_code !== input.confirmationCode) {
            await this.updateSessionStatus(session.id, 'FAILED', {
                failure_reason: 'INVALID_CONFIRMATION_CODE',
            });
            throw new Error('INVALID_CONFIRMATION_CODE');
        }

        const confirmed = await this.updateSessionStatus(session.id, 'CONFIRMED', {
            confirmed_at: input.receivedAt || new Date().toISOString(),
            updated_at: input.receivedAt || new Date().toISOString(),
        });

        let bridgeResult: any;
        let finalSession: any = confirmed;
        try {
            const forwarded = await this.updateSessionStatus(session.id, 'FORWARDED_TO_ORBI');
            bridgeResult = await offlineOrbiBridge.processConfirmedSession(forwarded);
            finalSession = await this.updateSessionStatus(session.id, 'SUCCESS', {
                completed_at: input.receivedAt || new Date().toISOString(),
                metadata: {
                    ...(forwarded.metadata || {}),
                    bridge_transaction_id: bridgeResult?.transaction?.id || null,
                    bridge_result: bridgeResult || null,
                },
            });
            await sb.from('outbound_sms_messages').insert({
                request_id: input.requestId,
                phone_number: input.phoneNumber,
                message_body: this.formatSuccess(
                    input.requestId,
                    bridgeResult?.transaction?.referenceId || finalSession.correlation_id || finalSession.id,
                ),
                message_type: 'SUCCESS',
                send_status: 'QUEUED',
            });
        } catch (bridgeError: any) {
            finalSession = await this.updateSessionStatus(session.id, 'FAILED', {
                failure_reason: bridgeError.message,
                completed_at: input.receivedAt || new Date().toISOString(),
            });
            await sb.from('outbound_sms_messages').insert({
                request_id: input.requestId,
                phone_number: input.phoneNumber,
                message_body: this.formatFailure(input.requestId, bridgeError.message),
                message_type: 'FAILED',
                send_status: 'QUEUED',
            });
            throw bridgeError;
        }

        await Audit.log('FINANCIAL', 'SYSTEM', 'OFFLINE_REQUEST_CONFIRMED', {
            requestId: input.requestId,
            sessionId: session.id,
        });

        return {
            session: finalSession,
            bridgeResult,
            responseMessage: this.formatSuccess(
                input.requestId,
                bridgeResult?.transaction?.referenceId || finalSession.correlation_id || finalSession.id,
            ),
        };
    }

    private parseMessage(messageBody: string): ParsedOfflineMessage {
        const parts = String(messageBody || '').split('|');
        if (parts.length < 5) {
            throw new Error('OFFLINE_PROTOCOL_INSUFFICIENT_PARTS');
        }

        const [prefix, type, version, requestId, ...rest] = parts;
        return {
            raw: messageBody,
            prefix,
            type,
            version,
            requestId,
            parts: rest,
        };
    }

    private validateMessage(parsed: ParsedOfflineMessage): void {
        if (parsed.prefix !== 'ORBI') {
            throw new Error('OFFLINE_PROTOCOL_PREFIX_INVALID');
        }
        if (parsed.version !== 'v1') {
            throw new Error('OFFLINE_PROTOCOL_VERSION_INVALID');
        }
        if (!parsed.requestId || parsed.requestId.length < 4) {
            throw new Error('OFFLINE_PROTOCOL_REQUEST_ID_INVALID');
        }
    }

    private classifyMessage(parsed: ParsedOfflineMessage): OfflineMessageType {
        if (parsed.type === 'CONFIRM') return 'APP_OFFLINE_CONFIRM';
        if (parsed.type === 'REQ') {
            const action = String(parsed.parts[0] || '').trim().toUpperCase();
            if (action === 'SEND') return 'INTERNAL_TRANSFER';
            if (action === 'PAY') return 'MERCHANT_PAYMENT';
            if (action === 'WITHDRAW') return 'WITHDRAWAL_REQUEST';
            if (action === 'BALANCE') return 'BALANCE_CHECK';
            return 'APP_OFFLINE_REQUEST';
        }
        if (parsed.type === 'HELP') return 'HELP';
        return 'UNKNOWN';
    }

    private async updateSessionStatus(
        sessionId: string,
        status: OfflineSessionStatus,
        extra: Record<string, any> = {},
    ) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const { data, error } = await sb
            .from('offline_transaction_sessions')
            .update({
                status,
                updated_at: new Date().toISOString(),
                ...extra,
            })
            .eq('id', sessionId)
            .select('*')
            .single();

        if (error) throw new Error(error.message);
        return data;
    }

    private generateChallengeCode(): string {
        return String(Math.floor(100000 + Math.random() * 900000));
    }

    private formatChallenge(requestId: string, challengeCode: string): string {
        return `ORBI|CHALLENGE|v1|${requestId}|${challengeCode}|CONFIRM|EXP300|SIG_PLACEHOLDER`;
    }

    private formatSuccess(requestId: string, reference: string): string {
        return `ORBI|RESP|v1|${requestId}|SUCCESS|${reference}|SIG_PLACEHOLDER`;
    }

    private formatFailure(requestId: string, reason: string): string {
        return `ORBI|RESP|v1|${requestId}|FAILED|${reason}|SIG_PLACEHOLDER`;
    }
}

export const offlineGatewayService = new OfflineGatewayService();
