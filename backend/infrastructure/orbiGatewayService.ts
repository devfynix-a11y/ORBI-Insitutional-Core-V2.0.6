import { logger } from './logger.js';
import parsePhoneNumber from 'libphonenumber-js';
import { MessageType, TemplateChannel, TemplateLanguage, TemplateName, TemplatePayloads } from '../templates/template_types.js';

export const gatewayInfraLogger = logger.child({ component: 'orbi_gateway_service' });

class OrbiGatewayService {
    private apiKey: string | undefined;
    private baseUrl: string | undefined;

    constructor() {
        this.apiKey = process.env.ORBI_GATEWAY_API_KEY;
        this.baseUrl = this.normalizeBaseUrl(
            process.env.ORBI_GATEWAY_URL || process.env.ORBI_GATEWAY_BASE_URL
        );
        
        if (!this.apiKey) {
            gatewayInfraLogger.warn('gateway_service.api_key_missing');
        }
        if (!this.baseUrl) {
            gatewayInfraLogger.warn('gateway_service.url_missing');
        }
    }

    private normalizeBaseUrl(url?: string): string | undefined {
        const raw = url?.trim();
        if (!raw) return undefined;
        return raw.replace(/\/+$/, '').replace(/\/api$/, '');
    }

    private normalizePhone(phone: string): string {
        try {
            const parsed = parsePhoneNumber(phone, 'TZ');
            if (parsed && parsed.isValid()) {
                return parsed.format('E.164');
            }
            return phone.startsWith('+') ? phone : '+' + phone.replace(/\s/g, '');
        } catch (e) {
            return phone.startsWith('+') ? phone : '+' + phone.replace(/\s/g, '');
        }
    }

    async sendSms(recipient: string, body: string, language: string = 'en', ownerUid?: string, ownerEmail?: string, requestId?: string): Promise<boolean> {
        if (!this.apiKey || !this.baseUrl) {
            gatewayInfraLogger.error('gateway_service.sms_missing_configuration', { channel: 'sms' });
            return false;
        }

        const normalizedRecipient = this.normalizePhone(recipient);

        try {
            const endpoint = `${this.baseUrl}/api/send-sms`;
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.apiKey
                },
                body: JSON.stringify({
                    recipient: normalizedRecipient,
                    body,
                    channel: 'sms',
                    messageType: 'transactional',
                    language,
                    ownerUid: process.env.OBI_GATEWAY_USER_ID,
                    ownerEmail: process.env.OBI_GATEWAY_USER_EMAIL,
                    requestId
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                gatewayInfraLogger.error('gateway_service.sms_failed', { endpoint, status_code: response.status, channel: 'sms', recipient: normalizedRecipient, error_text: errorText });
                return false;
            }

            gatewayInfraLogger.info('gateway_service.sms_sent', { channel: 'sms', recipient: normalizedRecipient });
            return true;
        } catch (error) {
            gatewayInfraLogger.error('gateway_service.sms_exception', { channel: 'sms', recipient: normalizedRecipient }, error);
            return false;
        }
    }

    async sendEmail(recipient: string, subject: string, body: string, html?: string, language: string = 'en', ownerUid?: string, ownerEmail?: string, requestId?: string): Promise<boolean> {
        if (!this.apiKey || !this.baseUrl) {
            gatewayInfraLogger.error('gateway_service.email_missing_configuration', { channel: 'email', recipient });
            return false;
        }

        try {
            const endpoint = `${this.baseUrl}/api/send-email`;
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.apiKey
                },
                body: JSON.stringify({
                    recipient,
                    body,
                    subject,
                    html,
                    messageType: 'transactional',
                    language,
                    ownerUid: process.env.OBI_GATEWAY_USER_ID,
                    ownerEmail: process.env.OBI_GATEWAY_USER_EMAIL,
                    requestId
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                gatewayInfraLogger.error('gateway_service.email_failed', { endpoint, status_code: response.status, channel: 'email', recipient, error_text: errorText });
                return false;
            }

            gatewayInfraLogger.info('gateway_service.email_sent', { channel: 'email', recipient });
            return true;
        } catch (error) {
            gatewayInfraLogger.error('gateway_service.email_exception', { channel: 'email', recipient }, error);
            return false;
        }
    }

    async sendPush(fcmToken: string, title: string, body: string, data: Record<string, any> = {}, language: string = 'en', ownerUid?: string, ownerEmail?: string, requestId?: string): Promise<boolean> {
        if (!this.apiKey || !this.baseUrl) {
            gatewayInfraLogger.error('gateway_service.push_missing_configuration', { channel: 'push' });
            return false;
        }

        try {
            const payload = {
                token: fcmToken,
                title,
                body,
                data,
                language,
                ownerUid: process.env.OBI_GATEWAY_USER_ID,
                ownerEmail: process.env.OBI_GATEWAY_USER_EMAIL,
                requestId
            };

            gatewayInfraLogger.debug('gateway_service.push_payload_prepared', { channel: 'push', payload });

            const endpoint = `${this.baseUrl}/api/send-push`;
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.apiKey
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const errorText = await response.text();
                gatewayInfraLogger.error('gateway_service.push_failed', { endpoint, status_code: response.status, channel: 'push', error_text: errorText });
                return false;
            }

            gatewayInfraLogger.info('gateway_service.push_sent', { channel: 'push' });
            return true;
        } catch (error) {
            gatewayInfraLogger.error('gateway_service.push_exception', { channel: 'push' }, error);
            return false;
        }
    }

    async sendTemplate<T extends TemplateName>(
        templateName: T, 
        recipient: string, 
        data: TemplatePayloads[T], 
        options: { channel?: string; language?: string; messageType?: 'transactional' | 'promotional'; fcmToken?: string; ownerUid?: string; ownerEmail?: string; requestId?: string } = {}
    ): Promise<boolean> {
        const { channel = 'sms', language = 'en', messageType = 'transactional', fcmToken, ownerUid, ownerEmail, requestId } = options;

        if (!this.apiKey || !this.baseUrl) {
            gatewayInfraLogger.error('gateway_service.template_missing_configuration', { channel, recipient, template_name: templateName });
            return false;
        }

        const normalizedRecipient = (channel === 'sms' || channel === 'whatsapp') ? this.normalizePhone(recipient) : recipient;

        try {
            const payload = {
                templateName,
                recipient: normalizedRecipient,
                data,
                channel,
                language,
                messageType,
                ownerUid: ownerUid || process.env.OBI_GATEWAY_USER_ID,
                ownerEmail: ownerEmail || process.env.OBI_GATEWAY_USER_EMAIL,
                requestId,
                ...(fcmToken && channel !== 'push' ? { fcmToken } : {})
            };

            gatewayInfraLogger.debug('gateway_service.template_payload_prepared', { channel, recipient, template_name: templateName, payload });

            const endpoint = `${this.baseUrl}/api/send-template`;
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.apiKey
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const errorText = await response.text();
                gatewayInfraLogger.error('gateway_service.template_failed', { endpoint, status_code: response.status, channel, recipient, template_name: templateName, error_text: errorText });
                return false;
            }

            gatewayInfraLogger.info('gateway_service.template_sent', { channel, recipient, template_name: templateName });
            return true;
        } catch (error) {
            gatewayInfraLogger.error('gateway_service.template_exception', { channel, recipient, template_name: templateName }, error);
            return false;
        }
    }

    async getTemplateCatalog(options: {
        search?: string;
        channel?: TemplateChannel;
        language?: TemplateLanguage;
        messageType?: MessageType;
        limit?: number;
    } = {}): Promise<Array<{
        name: string;
        channel: TemplateChannel;
        language: TemplateLanguage | string;
        messageType: MessageType;
        subject?: string;
        body: string;
        variables: string[];
    }>> {
        if (!this.apiKey || !this.baseUrl) {
            gatewayInfraLogger.error('gateway_service.template_catalog_missing_configuration');
            return [];
        }

        const params = new URLSearchParams();
        if (options.search) params.set('search', options.search);
        if (options.channel) params.set('channel', options.channel);
        if (options.language) params.set('language', options.language);
        if (options.messageType) params.set('messageType', options.messageType);
        if (options.limit) params.set('limit', String(options.limit));

        const endpoint = `${this.baseUrl}/api/templates/catalog${params.size ? `?${params.toString()}` : ''}`;

        try {
            const response = await fetch(endpoint, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.apiKey
                },
            });

            if (!response.ok) {
                const errorText = await response.text();
                gatewayInfraLogger.error('gateway_service.template_catalog_failed', { endpoint, status_code: response.status, error_text: errorText });
                return [];
            }

            const payload = await response.json().catch(() => ({}));
            return Array.isArray(payload?.data) ? payload.data : [];
        } catch (error) {
            gatewayInfraLogger.error('gateway_service.template_catalog_exception', { endpoint }, error);
            return [];
        }
    }
}

export const orbiGatewayService = new OrbiGatewayService();
