import { getAdminSupabase } from '../supabaseClient.js';
import { RedisClusterFactory } from '../infrastructure/RedisClusterFactory.js';
import {
    FinancialPartner,
    MoneyOperation,
    ProviderResolutionInput,
    ProviderRoutingDecision,
    RailType,
    ResolvedProviderConfig,
} from '../../types.js';
import { normalizeFinancialPartnerMetadata, resolveProviderCode } from './financialPartnerMetadata.js';
import {
    assertProviderRegistry,
    resolveOperationConfig,
    resolveOperationServiceKey,
    resolveProviderBaseUrl,
} from './providers/ProviderRegistryAdapter.js';

function normalizeRail(value?: string): RailType | undefined {
    const normalized = String(value || '').trim().toUpperCase();
    if (!normalized) return undefined;
    if (normalized === 'MOBILE_MONEY') return 'MOBILE_MONEY';
    if (normalized === 'BANK') return 'BANK';
    if (normalized === 'CARD_GATEWAY') return 'CARD_GATEWAY';
    if (normalized === 'CRYPTO') return 'CRYPTO';
    if (normalized === 'WALLET') return 'WALLET';
    return undefined;
}

function fallbackRailFromPartner(partner: FinancialPartner): RailType {
    const type = String(partner.type || '').trim().toLowerCase();
    if (type === 'mobile_money') return 'MOBILE_MONEY';
    if (type === 'bank') return 'BANK';
    if (type === 'crypto') return 'CRYPTO';
    if (type === 'card') return 'CARD_GATEWAY';
    return 'WALLET';
}

export class ProviderRoutingService {
    private cache = new Map<string, { expiresAt: number; data: ResolvedProviderConfig }>();
    private cacheTtlMs = 60 * 1000;

    async resolveProvider(input: ProviderResolutionInput): Promise<ResolvedProviderConfig> {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const cacheKey = this.buildCacheKey(input);
        const cached = this.cache.get(cacheKey);
        if (cached && cached.expiresAt > Date.now()) {
            return cached.data;
        }
        const redis = RedisClusterFactory.getClient('monitor');
        if (redis && process.env.ORBI_DISABLE_REDIS_CACHE !== 'true') {
            try {
                const cachedRaw = await redis.get(`provider_route:${cacheKey}`);
                if (cachedRaw) {
                    const parsed = JSON.parse(String(cachedRaw));
                    this.cache.set(cacheKey, { expiresAt: Date.now() + this.cacheTtlMs, data: parsed });
                    return parsed;
                }
            } catch (e) {
                // Redis is optional; fall back to DB.
            }
        }

        const routed = await this.resolveViaRoutingRules(sb, input);
        if (routed) {
            const resolved = this.toResolvedProviderConfig(routed.partner, input.operation, this.buildDecision({
                input,
                partner: routed.partner,
                source: 'routing_rule',
                ruleId: routed.ruleId,
                priority: routed.priority,
            }));
            this.cache.set(cacheKey, { expiresAt: Date.now() + this.cacheTtlMs, data: resolved });
            if (redis && process.env.ORBI_DISABLE_REDIS_CACHE !== 'true') {
                try {
                    await redis.set(`provider_route:${cacheKey}`, JSON.stringify(resolved), 'EX', Math.ceil(this.cacheTtlMs / 1000));
                } catch (e) {
                    // Ignore Redis write errors.
                }
            }
            return resolved;
        }

        let query = sb
            .from('financial_partners')
            .select('*')
            .eq('status', 'ACTIVE');

        if (input.preferredProviderId) {
            query = query.eq('id', input.preferredProviderId);
        }

        const { data, error } = await query;
        if (error) throw new Error(error.message);

        const partners = (data || []) as FinancialPartner[];
        const ranked = partners
            .filter((partner) => this.matchesResolutionInput(partner, input))
            .sort((a, b) => this.resolvePriority(a, input.operation) - this.resolvePriority(b, input.operation));

        const partner = ranked[0];
        if (!partner) {
            throw new Error(`PROVIDER_ROUTE_NOT_FOUND:${input.rail}:${input.operation}`);
        }

        const resolved = this.toResolvedProviderConfig(
            partner,
            input.operation,
            this.buildDecision({ input, partner, source: 'registry_fallback' }),
        );
        this.cache.set(cacheKey, { expiresAt: Date.now() + this.cacheTtlMs, data: resolved });
        if (redis && process.env.ORBI_DISABLE_REDIS_CACHE !== 'true') {
            try {
                await redis.set(`provider_route:${cacheKey}`, JSON.stringify(resolved), 'EX', Math.ceil(this.cacheTtlMs / 1000));
            } catch (e) {
                // Ignore Redis write errors.
            }
        }
        return resolved;
    }

    private buildCacheKey(input: ProviderResolutionInput) {
        return JSON.stringify({
            rail: input.rail,
            operation: input.operation,
            countryCode: input.countryCode || '',
            currency: input.currency || '',
            preferredProviderCode: input.preferredProviderCode || '',
            preferredProviderId: input.preferredProviderId || '',
        });
    }

    private async resolveViaRoutingRules(
        sb: any,
        input: ProviderResolutionInput,
    ): Promise<{ partner: FinancialPartner; ruleId?: string; priority?: number } | null> {
        let routingQuery = sb
            .from('provider_routing_rules')
            .select('id, priority, country_code, currency, provider_id, financial_partners(*)')
            .eq('rail', input.rail)
            .eq('operation_code', input.operation)
            .eq('status', 'ACTIVE')
            .order('priority', { ascending: true })
            .limit(20);

        if (input.countryCode) {
            routingQuery = routingQuery.in('country_code', [String(input.countryCode).trim().toUpperCase(), null]);
        }
        if (input.currency) {
            routingQuery = routingQuery.in('currency', [String(input.currency).trim().toUpperCase(), null]);
        }
        if (input.preferredProviderId) {
            routingQuery = routingQuery.eq('provider_id', input.preferredProviderId);
        }

        const { data, error } = await routingQuery;
        if (error) {
            // If the new table is not deployed yet, fall back to metadata-based routing.
            if (String(error.message || '').includes('provider_routing_rules')) {
                return null;
            }
            throw new Error(error.message);
        }

        const candidates = (data || [])
            .map((row: any) => ({
                partner: row.financial_partners as FinancialPartner,
                ruleId: row.id as string | undefined,
                priority: row.priority as number | undefined,
            }))
            .filter((row: any) => row.partner);

        const filtered = candidates.filter((row: any) => this.matchesResolutionInput(row.partner, input));
        return filtered[0] || null;
    }

    private toResolvedProviderConfig(
        partner: FinancialPartner,
        operation: MoneyOperation,
        routingDecision?: ProviderRoutingDecision,
    ): ResolvedProviderConfig {
        const registry = assertProviderRegistry(partner);
        const operationConfig = resolveOperationConfig(registry, operation);
        const baseUrl = resolveProviderBaseUrl(partner, registry, operation);

        return {
            providerId: partner.id,
            providerCode: resolveProviderCode(partner),
            providerName: partner.name,
            rail: normalizeRail(String(normalizeFinancialPartnerMetadata(partner).rail || '')) || fallbackRailFromPartner(partner),
            operation,
            authType: partner.logic_type,
            baseUrl,
            timeoutMs: operationConfig ? Number((operationConfig as any).timeout_ms || 30000) : undefined,
            requestTemplate: operationConfig?.payload_template,
            responseMapping: operationConfig?.response_mapping,
            extraConfig: {
                partnerType: partner.type,
                supportedCurrencies: partner.supported_currencies || [],
                providerMetadata: normalizeFinancialPartnerMetadata(partner),
            },
            routingDecision,
        };
    }

    private matchesResolutionInput(partner: FinancialPartner, input: ProviderResolutionInput): boolean {
        const metadata = normalizeFinancialPartnerMetadata(partner);
        const registry = assertProviderRegistry(partner);
        if (input.preferredProviderCode) {
            const code = resolveProviderCode(partner).trim().toUpperCase();
            if (code !== String(input.preferredProviderCode).trim().toUpperCase()) {
                return false;
            }
        }

        const rail = normalizeRail(String(metadata.rail || '')) || fallbackRailFromPartner(partner);
        if (rail !== input.rail) return false;

        const operations = (metadata.operations || []) as Array<MoneyOperation | string>;
        if (operations.length > 0 && !operations.map((value) => String(value).trim().toUpperCase()).includes(input.operation)) {
            return false;
        }

        const countryCodes = (metadata.countries || []) as string[];
        if (input.countryCode && countryCodes.length > 0) {
            const requestedCountry = String(input.countryCode).trim().toUpperCase();
            if (!countryCodes.map((code) => String(code).trim().toUpperCase()).includes(requestedCountry)) {
                return false;
            }
        }

        const supportedCurrencies = (partner.supported_currencies || []) as string[];
        if (input.currency && supportedCurrencies.length > 0) {
            const requestedCurrency = String(input.currency).trim().toUpperCase();
            if (!supportedCurrencies.map((currency) => String(currency).trim().toUpperCase()).includes(requestedCurrency)) {
                return false;
            }
        }

        if (input.operation && !resolveOperationConfig(registry, input.operation)) {
            const fallbackAllowed =
                (input.operation === 'COLLECTION_REQUEST' && registry.stk_push) ||
                (input.operation === 'DISBURSEMENT_REQUEST' && registry.disbursement) ||
                (input.operation === 'BALANCE_INQUIRY' && registry.balance);
            if (!fallbackAllowed) return false;
        }

        return true;
    }

    private resolvePriority(partner: FinancialPartner, operation: MoneyOperation): number {
        const metadataPriority = Number(normalizeFinancialPartnerMetadata(partner).routing_priority);
        const operationPriority = Number((assertProviderRegistry(partner) as any)?.routing?.[operation]?.priority);
        if (Number.isFinite(operationPriority)) return operationPriority;
        if (Number.isFinite(metadataPriority)) return metadataPriority;
        return 100;
    }

    private buildDecision(params: {
        input: ProviderResolutionInput;
        partner: FinancialPartner;
        source: ProviderRoutingDecision['source'];
        ruleId?: string;
        priority?: number;
    }): ProviderRoutingDecision {
        return {
            providerId: params.partner.id,
            providerCode: resolveProviderCode(params.partner),
            rail: params.input.rail,
            operation: params.input.operation,
            source: params.source,
            ruleId: params.ruleId,
            priority: params.priority,
            countryCode: params.input.countryCode,
            currency: params.input.currency,
            preferredProviderCode: params.input.preferredProviderCode,
            preferredProviderId: params.input.preferredProviderId,
            resolvedAt: new Date().toISOString(),
        };
    }
}

export const providerRoutingService = new ProviderRoutingService();
