import {
    FinancialPartner,
    MoneyOperation,
    ProviderCallbackConfig,
    RestEndpointConfig,
} from '../../../types.js';
import {
    IProviderAdapter,
    ProviderCallbackResult,
    ProviderExecutionRequest,
    ProviderExecutionResponse,
} from './types.js';
import net from 'net';
import { providerTokenService } from './ProviderTokenService.js';
import { providerSecretVault } from './ProviderSecretVault.js';
import {
    assertAuthConfig,
    assertCallbackConfig,
    assertOperationConfig,
    assertProviderRegistry,
    resolveOperationServiceKey,
    resolveProviderBaseUrl,
} from './ProviderRegistryAdapter.js';
import { providerCapabilityService } from '../ProviderCapabilityService.js';

export class GenericRestProvider implements IProviderAdapter {
    private readonly timeoutMs = Number(process.env.ORBI_PROVIDER_TIMEOUT_MS || 15000);
    private readonly allowInsecureProviderUrls =
        process.env.NODE_ENV !== 'production' &&
        process.env.ORBI_ALLOW_INSECURE_PROVIDER_URLS === 'true';

    private async resolvePartner(partner: FinancialPartner): Promise<FinancialPartner> {
        const resolved: FinancialPartner = {
            ...partner,
            mapping_config: partner.mapping_config ? structuredClone(partner.mapping_config) : {},
            provider_metadata: partner.provider_metadata ? structuredClone(partner.provider_metadata) : {},
            client_secret: undefined,
            connection_secret: undefined,
            webhook_secret: undefined,
            token_cache: undefined,
        };
        resolved.connection_secret = await providerSecretVault.resolvePartnerSecret(partner, 'connection_secret', 'api_key');
        resolved.client_secret = await providerSecretVault.resolvePartnerSecret(partner, 'client_secret', 'access_token');
        resolved.webhook_secret = await providerSecretVault.resolvePartnerSecret(partner, 'webhook_secret');
        if (partner.token_cache) {
            resolved.token_cache = await providerSecretVault.unwrapSecret(partner.token_cache);
        }
        return resolved;
    }

    private resolveServiceRoot(registry: ReturnType<typeof assertProviderRegistry>, service?: string): string | undefined {
        if (service && registry.service_roots?.[service]) {
            return registry.service_roots[service];
        }
        return registry.service_root;
    }

    public getCapabilities(partner: FinancialPartner) {
        return providerCapabilityService.describe(partner);
    }

    public async authenticate(partner: FinancialPartner): Promise<string> {
        const resolvedPartner = await this.resolvePartner(partner);
        const registry = assertProviderRegistry(resolvedPartner);

        const cachedToken = await providerTokenService.getCachedToken(resolvedPartner);
        if (cachedToken?.token) {
            return cachedToken.token;
        }

        if (registry.auth?.type === 'none') {
            return '';
        }

        const authConfig = assertAuthConfig(resolvedPartner);

        if (authConfig.type === 'oauth2_client_credentials') {
            const response = await this.executeRequest(authConfig, {
                partner: resolvedPartner,
                registry,
                serviceRoot: this.resolveServiceRoot(registry, resolveOperationServiceKey('AUTH')),
            });
            const token =
                typeof response.external_id === 'string' && response.external_id.trim().length > 0
                    ? response.external_id
                    : this.readMappedValue(response.raw, authConfig.response_mapping?.token_field) || '';
            if (!token) {
                throw new Error('PROVIDER_AUTH_TOKEN_MISSING');
            }
            const expiresIn = Number(
                this.readMappedValue(response.raw, authConfig.response_mapping?.expires_in_field) ||
                    authConfig.cache_ttl_seconds ||
                    3600,
            );
            await providerTokenService.cacheToken(resolvedPartner.id, token, expiresIn);
            return token;
        }

        const staticToken = await providerTokenService.resolveStaticToken(resolvedPartner);
        if (staticToken) {
            return staticToken;
        }

        throw new Error('GENERIC_PROVIDER_CREDENTIALS_MISSING');
    }

    public async execute(partner: FinancialPartner, request: ProviderExecutionRequest): Promise<ProviderExecutionResponse> {
        const resolvedPartner = await this.resolvePartner(partner);
        const registry = assertProviderRegistry(resolvedPartner);
        const config = assertOperationConfig(resolvedPartner, request.operation);
        const context = await this.buildContext(resolvedPartner, {
            phone: request.phone,
            amount: request.amount,
            reference: request.reference,
            currency: request.currency,
            account_number: request.accountNumber,
            destination_tag: request.destinationTag,
            external_reference: request.externalReference,
            metadata: request.metadata || {},
            idempotency_key: request.idempotencyKey,
        });
        const response = await this.executeRequest(config, {
            ...context,
            serviceRoot: this.resolveServiceRoot(registry, resolveOperationServiceKey(request.operation)),
        });

        if (request.operation === 'BALANCE_INQUIRY') {
            let balance = 0;
            if (config.response_mapping?.balance_field) {
                balance = Number(this.getValueByPath(response.raw, config.response_mapping.balance_field)) || 0;
            }
            return {
                success: true,
                providerRef: response.external_id || request.reference,
                status: 'completed',
                message: response.message || 'Balance retrieved successfully.',
                rawPayload: response.raw,
                balance,
                metadata: { operation: request.operation },
            };
        }

        return {
            success: true,
            providerRef:
                response.external_id ||
                request.reference ||
                `GEN-${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
            status: this.normalizeExecutionStatus(response.status),
            message: response.message || `Provider request accepted by ${resolvedPartner.name}.`,
            externalId: response.external_id,
            rawPayload: response.raw,
            metadata: {
                operation: request.operation,
                reference: request.reference,
            },
        };
    }

    public async stkPush(partner: FinancialPartner, phone: string, amount: number, reference: string): Promise<ProviderExecutionResponse> {
        return this.execute(partner, {
            operation: 'COLLECTION_REQUEST',
            phone,
            amount,
            reference,
        });
    }

    public async disburse(partner: FinancialPartner, phone: string, amount: number, reference: string): Promise<ProviderExecutionResponse> {
        return this.execute(partner, {
            operation: 'DISBURSEMENT_REQUEST',
            phone,
            amount,
            reference,
        });
    }

    public parseCallback(
        payload: any,
        partner?: FinancialPartner,
        context?: { headers?: Record<string, string | undefined> },
    ): ProviderCallbackResult {
        const resolvedPartner = partner || ({} as FinancialPartner);
        const callbackConfig = assertCallbackConfig(resolvedPartner);
        const reference =
            this.readMappedValue(payload, callbackConfig.reference_field) ||
            payload?.reference ||
            payload?.id ||
            '';
        const rawStatus =
            String(
                this.readMappedValue(payload, callbackConfig.status_field) ??
                    payload?.status ??
                    payload?.code ??
                    '',
            ).trim();
        const normalizedStatus = this.normalizeCallbackStatus(rawStatus, callbackConfig);
        const message =
            this.readMappedValue(payload, callbackConfig.message_field) ||
            payload?.message ||
            'Generic Callback Received';
        const providerEventId =
            this.readMappedValue(payload, callbackConfig.event_id_field) ||
            payload?.event_id ||
            payload?.eventId ||
            undefined;
        return {
            reference: String(reference || ''),
            status: normalizedStatus,
            message: String(message || 'Generic Callback Received'),
            providerEventId: providerEventId ? String(providerEventId) : undefined,
            rawStatus,
        };
    }

    public async getBalance(partner: FinancialPartner): Promise<number> {
        const response = await this.execute(partner, {
            operation: 'BALANCE_INQUIRY',
            reference: `balance-${partner.id}`,
        });
        return Number(response.balance || 0);
    }

    private normalizeExecutionStatus(status?: string): ProviderExecutionResponse['status'] {
        const normalized = String(status || '').trim().toLowerCase();
        if (['success', 'successful', 'completed', 'complete', 'ok'].includes(normalized)) return 'completed';
        if (['pending', 'queued'].includes(normalized)) return 'pending';
        if (['processing', 'in_progress'].includes(normalized)) return 'processing';
        if (['failed', 'rejected', 'declined', 'error'].includes(normalized)) return 'failed';
        return 'accepted';
    }

    private async executeRequest(config: RestEndpointConfig, context: any): Promise<any> {
        const url = this.resolveAbsoluteUrl(
            this.resolveTemplate(config.url, context),
            context.partner,
            context.serviceRoot,
        );
        await this.assertTrustedProviderUrl(url);

        const headers = this.resolveHeaders(config.headers || {}, context);
        headers['Accept'] ??= 'application/json';

        const body = config.payload_template
            ? JSON.stringify(this.resolveObject(config.payload_template, context))
            : undefined;

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const response = await fetch(url, {
                method: config.method,
                headers,
                body,
                signal: controller.signal,
            });
            const rawText = await response.text();
            const responseData = rawText ? JSON.parse(rawText) : {};

            if (!response.ok) {
                const error: any = new Error(responseData.message || `HTTP Error ${response.status}: ${response.statusText}`);
                error.statusCode = response.status;
                error.rawPayload = responseData;
                throw error;
            }

            if (config.response_mapping) {
                return {
                    external_id: this.readMappedValue(responseData, config.response_mapping.id_field),
                    status: this.readMappedValue(responseData, config.response_mapping.status_field),
                    message: this.readMappedValue(responseData, config.response_mapping.message_field),
                    raw: responseData,
                };
            }

            return { raw: responseData };
        } finally {
            clearTimeout(timeout);
        }
    }

    private async buildContext(
        partner: FinancialPartner,
        extra: Record<string, any> = {},
    ): Promise<Record<string, any>> {
        const resolvedPartner = await this.resolvePartner(partner);
        const registry = assertProviderRegistry(resolvedPartner);
        const authType = registry.auth?.type || 'api_key';
        const accessToken =
            authType === 'none' ? '' : await this.authenticate(resolvedPartner).catch(() => '');
        const connectionSecret = resolvedPartner.connection_secret || '';
        const clientSecret = resolvedPartner.client_secret || '';

        return {
            ...extra,
            registry,
            partner: {
                ...resolvedPartner,
                token_cache: accessToken || resolvedPartner.token_cache,
                access_token: accessToken,
                connection_secret: typeof connectionSecret === 'string' ? connectionSecret : '',
                client_secret: typeof clientSecret === 'string' ? clientSecret : '',
            },
        };
    }

    private normalizeCallbackStatus(
        rawStatus: string,
        config: ProviderCallbackConfig,
    ): 'completed' | 'failed' | 'processing' | 'pending' {
        const normalized = rawStatus.trim().toLowerCase();
        const matches = (values?: Array<string | number>) =>
            (values || []).map((value) => String(value).trim().toLowerCase()).includes(normalized);

        if (matches(config.success_values) || matches(config.completed_values)) return 'completed';
        if (matches(config.pending_values)) return 'pending';
        if (matches(config.failed_values)) return 'failed';

        if (['success', 'successful', 'completed', 'complete', '200', '0', 'ok'].includes(normalized)) {
            return 'completed';
        }
        if (['pending', 'processing', 'queued', 'in_progress'].includes(normalized)) {
            return 'processing';
        }
        return 'failed';
    }

    private resolveAbsoluteUrl(url: string, partner: FinancialPartner, serviceRoot?: string): string {
        if (/^https?:\/\//i.test(url)) return url;
        const baseUrl = serviceRoot?.trim() || resolveProviderBaseUrl(partner, assertProviderRegistry(partner));
        return new URL(url, baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`).toString();
    }

    private readMappedValue(source: any, path?: string): any {
        if (!path) return undefined;
        return this.getValueByPath(source, path);
    }

    private async assertTrustedProviderUrl(url: string): Promise<void> {
        let parsed: URL;
        try {
            parsed = new URL(url);
        } catch {
            throw new Error('PROVIDER_URL_INVALID');
        }

        if (parsed.protocol !== 'https:' && !this.allowInsecureProviderUrls) {
            throw new Error('PROVIDER_URL_INSECURE');
        }

        if ((parsed.username || parsed.password) && !this.allowInsecureProviderUrls) {
            throw new Error('PROVIDER_URL_EMBEDDED_CREDENTIALS_BLOCKED');
        }

        const hostname = parsed.hostname.toLowerCase();
        const blockedHosts = new Set([
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            'host.docker.internal',
            'metadata.google.internal',
        ]);
        if (
            (blockedHosts.has(hostname) ||
                hostname.endsWith('.local') ||
                hostname.endsWith('.internal') ||
                this.isBlockedProviderIp(hostname)) &&
            !this.allowInsecureProviderUrls
        ) {
            throw new Error('PROVIDER_URL_BLOCKED_HOST');
        }
    }

    private isBlockedProviderIp(hostname: string): boolean {
        if (!net.isIP(hostname)) {
            return false;
        }

        if (net.isIPv4(hostname)) {
            const [a, b] = hostname.split('.').map((part) => Number(part));
            return (
                a === 0 ||
                a === 10 ||
                a === 127 ||
                (a === 100 && b >= 64 && b <= 127) ||
                (a === 169 && b === 254) ||
                (a === 172 && b >= 16 && b <= 31) ||
                (a === 192 && b === 168) ||
                (a === 198 && (b === 18 || b === 19))
            );
        }

        const normalized = hostname.toLowerCase();
        return (
            normalized === '::1' ||
            normalized === '::' ||
            normalized.startsWith('fc') ||
            normalized.startsWith('fd') ||
            normalized.startsWith('fe80:')
        );
    }

    private resolveTemplate(template: string, context: any): string {
        return template.replace(/\{\{(.*?)\}\}/g, (_, key) => {
            const value = this.getValueByPath(context, key.trim());
            return value !== undefined && value !== null ? String(value) : '';
        });
    }

    private resolveHeaders(headers: Record<string, string>, context: any): Record<string, string> {
        const resolved: Record<string, string> = {};
        for (const [key, value] of Object.entries(headers)) {
            const lowered = key.toLowerCase();
            if (['host', 'content-length', 'connection'].includes(lowered)) {
                continue;
            }
            resolved[key] = this.resolveTemplate(value, context);
        }
        return resolved;
    }

    private resolveObject(template: any, context: any): any {
        if (typeof template === 'string') {
            const match = template.match(/^\{\{(.*?)\}\}$/);
            if (match) {
                const value = this.getValueByPath(context, match[1].trim());
                return value !== undefined ? value : template;
            }
            return this.resolveTemplate(template, context);
        } else if (Array.isArray(template)) {
            return template.map(item => this.resolveObject(item, context));
        } else if (typeof template === 'object' && template !== null) {
            const resolved: any = {};
            for (const [key, value] of Object.entries(template)) {
                resolved[key] = this.resolveObject(value, context);
            }
            return resolved;
        }
        return template;
    }

    private getValueByPath(obj: any, path: string): any {
        return path.split('.').reduce((acc: any, part: string) => {
            if (acc === null || acc === undefined) return undefined;
            return acc[part];
        }, obj);
    }
}
