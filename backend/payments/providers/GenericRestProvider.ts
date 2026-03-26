
import {
    FinancialPartner,
    ProviderCallbackConfig,
    ProviderRegistryConfig,
    RestEndpointConfig,
} from '../../../types.js';
import { IPaymentProvider, ProviderCallbackResult, ProviderResponse } from './types.js';
import { DataVault } from '../../security/encryption.js';
import { MerchantFabric } from './MerchantFabric.js';

/**
 * UNIVERSAL REST ADAPTER (V2.0)
 * ----------------------------
 * Handles standard providers via DB-defined JSON mappings.
 * Supports dynamic payload templating and endpoint configuration.
 */
export class GenericRestProvider implements IPaymentProvider {
    private readonly timeoutMs = Number(process.env.ORBI_PROVIDER_TIMEOUT_MS || 15000);
    private readonly allowInsecureProviderUrls =
        process.env.NODE_ENV !== 'production' &&
        process.env.ORBI_ALLOW_INSECURE_PROVIDER_URLS === 'true';

    private async resolvePartner(partner: FinancialPartner): Promise<FinancialPartner> {
        const translated = await DataVault.translate({
            ...partner,
            mapping_config: partner.mapping_config ?? {},
            provider_metadata: partner.provider_metadata ?? {},
        });
        return translated as FinancialPartner;
    }

    private getRegistry(partner: FinancialPartner): ProviderRegistryConfig {
        return (partner.mapping_config || {}) as ProviderRegistryConfig;
    }

    private resolveServiceRoot(registry: ProviderRegistryConfig, service?: string): string | undefined {
        if (service && registry.service_roots?.[service]) {
            return registry.service_roots[service];
        }
        return registry.service_root;
    }

    private getOperationConfig(
        registry: ProviderRegistryConfig,
        operation: string,
        fallback?: RestEndpointConfig,
    ): RestEndpointConfig | undefined {
        return registry.operations?.[operation as keyof NonNullable<ProviderRegistryConfig['operations']>] || fallback;
    }

    public async authenticate(partner: FinancialPartner): Promise<string> {
        const resolvedPartner = await this.resolvePartner(partner);
        const registry = this.getRegistry(resolvedPartner);
        const authConfig = registry.auth;

        if (resolvedPartner.token_cache && resolvedPartner.token_expiry && resolvedPartner.token_expiry > Date.now()) {
            const cached = typeof resolvedPartner.token_cache === 'string'
                ? resolvedPartner.token_cache
                : await DataVault.decrypt(resolvedPartner.token_cache);
            if (typeof cached === 'string' && cached.trim().length > 0) {
                return cached;
            }
        }

        if (!authConfig || authConfig.type === 'none') {
            return '';
        }

        if (authConfig.type === 'oauth2_client_credentials') {
        const response = await this.executeRequest(authConfig, {
                partner: resolvedPartner,
                registry,
                serviceRoot: this.resolveServiceRoot(registry, 'auth'),
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
            await MerchantFabric.updatePartnerToken(resolvedPartner.id, token, expiresIn);
            return token;
        }

        const secrets = resolvedPartner.provider_metadata?.secrets || {};
        const connectionSecret = resolvedPartner.connection_secret || secrets.connection_secret || secrets.api_key;
        if (typeof connectionSecret === 'string' && connectionSecret.trim().length > 0) {
            return connectionSecret;
        }

        const clientSecret = resolvedPartner.client_secret || secrets.client_secret || secrets.access_token;
        if (typeof clientSecret === 'string' && clientSecret.trim().length > 0) {
            return clientSecret;
        }

        throw new Error('GENERIC_PROVIDER_CREDENTIALS_MISSING');
    }

    public async stkPush(partner: FinancialPartner, phone: string, amount: number, reference: string): Promise<ProviderResponse> {
        const resolvedPartner = await this.resolvePartner(partner);
        const registry = this.getRegistry(resolvedPartner);
        const config = this.getOperationConfig(registry, 'COLLECTION_REQUEST', registry.stk_push);
        if (!config) throw new Error("STK_PUSH_CONFIG_MISSING");

        const context = await this.buildContext(resolvedPartner, { phone, amount, reference });
        const response = await this.executeRequest(config, {
            ...context,
            serviceRoot: this.resolveServiceRoot(registry, 'stk_push'),
        });

        return {
            success: true,
            providerRef: response.external_id || `GEN-${Math.random().toString(36).substring(7).toUpperCase()}`,
            message: response.status || `Generic request sent to ${partner.name}.`,
            rawPayload: response.raw
        };
    }

    public async disburse(partner: FinancialPartner, phone: string, amount: number, reference: string): Promise<ProviderResponse> {
        const resolvedPartner = await this.resolvePartner(partner);
        const registry = this.getRegistry(resolvedPartner);
        const config = this.getOperationConfig(registry, 'DISBURSEMENT_REQUEST', registry.disbursement);
        if (!config) throw new Error("DISBURSEMENT_CONFIG_MISSING");

        const context = await this.buildContext(resolvedPartner, { phone, amount, reference });
        const response = await this.executeRequest(config, {
            ...context,
            serviceRoot: this.resolveServiceRoot(registry, 'disbursement'),
        });

        return {
            success: true,
            providerRef: response.external_id || `GEN-PAY-${Math.random().toString(36).substring(7).toUpperCase()}`,
            message: response.status || "Disbursement processed via Generic REST node.",
            rawPayload: response.raw
        };
    }

    public parseCallback(
        payload: any,
        partner?: FinancialPartner,
    ): ProviderCallbackResult {
        const resolvedPartner = partner || ({} as FinancialPartner);
        const callbackConfig = this.getRegistry(resolvedPartner).callback || {};
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
        const resolvedPartner = await this.resolvePartner(partner);
        const registry = this.getRegistry(resolvedPartner);
        const config = this.getOperationConfig(registry, 'BALANCE_INQUIRY', registry.balance);
        if (!config) {
            console.warn(`[GenericRestProvider] Balance config missing for ${resolvedPartner.name}`);
            return 0;
        }

        const context = await this.buildContext(resolvedPartner);
        const response = await this.executeRequest(config, {
            ...context,
            serviceRoot: this.resolveServiceRoot(registry, 'balance'),
        });
        
        if (config.response_mapping?.balance_field) {
            const balance = this.getValueByPath(response.raw, config.response_mapping.balance_field);
            return Number(balance) || 0;
        }
        
        return 0;
    }

    private async executeRequest(config: RestEndpointConfig, context: any): Promise<any> {
        // 1. Resolve Endpoint
        const url = this.resolveAbsoluteUrl(
            this.resolveTemplate(config.url, context),
            context.partner,
            context.serviceRoot,
        );
        this.assertTrustedProviderUrl(url);

        // 2. Resolve Headers
        const headers = this.resolveHeaders(config.headers || {}, context);
        headers['Accept'] ??= 'application/json';

        // 3. Resolve Payload
        const body = config.payload_template 
            ? JSON.stringify(this.resolveObject(config.payload_template, context))
            : undefined;

        console.log(`[GenericRestProvider] Executing ${config.method} ${url}`);
        
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
                throw new Error(responseData.message || `HTTP Error ${response.status}: ${response.statusText}`);
            }

            if (config.response_mapping) {
                return {
                    external_id: this.readMappedValue(responseData, config.response_mapping.id_field),
                    status: this.readMappedValue(responseData, config.response_mapping.status_field),
                    message: this.readMappedValue(responseData, config.response_mapping.message_field),
                    raw: responseData
                };
            }

            return { raw: responseData };
        } catch (error) {
            console.error(`[GenericRestProvider] Error:`, error);
            throw error;
        } finally {
            clearTimeout(timeout);
        }
    }

    private async buildContext(
        partner: FinancialPartner,
        extra: Record<string, any> = {},
    ): Promise<Record<string, any>> {
        const resolvedPartner = await this.resolvePartner(partner);
        const registry = this.getRegistry(resolvedPartner);
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
        const baseUrl = serviceRoot?.trim() || partner.api_base_url?.trim();
        if (!baseUrl) {
            throw new Error('PROVIDER_BASE_URL_MISSING');
        }
        return new URL(url, baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`).toString();
    }

    private readMappedValue(source: any, path?: string): any {
        if (!path) return undefined;
        return this.getValueByPath(source, path);
    }

    private assertTrustedProviderUrl(url: string): void {
        let parsed: URL;
        try {
            parsed = new URL(url);
        } catch {
            throw new Error('PROVIDER_URL_INVALID');
        }

        if (parsed.protocol !== 'https:' && !this.allowInsecureProviderUrls) {
            throw new Error('PROVIDER_URL_INSECURE');
        }

        const hostname = parsed.hostname.toLowerCase();
        const blockedHosts = new Set(['localhost', '127.0.0.1', '0.0.0.0']);
        if (blockedHosts.has(hostname) && !this.allowInsecureProviderUrls) {
            throw new Error('PROVIDER_URL_BLOCKED_HOST');
        }
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
