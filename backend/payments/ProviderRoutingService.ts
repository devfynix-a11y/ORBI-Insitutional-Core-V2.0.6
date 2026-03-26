import { getAdminSupabase } from '../supabaseClient.js';
import {
    FinancialPartner,
    MoneyOperation,
    ProviderResolutionInput,
    RailType,
    ResolvedProviderConfig,
} from '../../types.js';

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
    async resolveProvider(input: ProviderResolutionInput): Promise<ResolvedProviderConfig> {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const routed = await this.resolveViaRoutingRules(sb, input);
        if (routed) {
            return this.toResolvedProviderConfig(routed, input.operation);
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

        const operationConfig = partner.mapping_config?.operations?.[input.operation];
        const baseUrl =
            partner.mapping_config?.service_roots?.[this.operationToServiceKey(input.operation)] ||
            partner.mapping_config?.service_root ||
            partner.api_base_url ||
            undefined;

        return this.toResolvedProviderConfig(partner, input.operation);
    }

    private async resolveViaRoutingRules(sb: any, input: ProviderResolutionInput): Promise<FinancialPartner | null> {
        let routingQuery = sb
            .from('provider_routing_rules')
            .select('priority, country_code, currency, provider_id, financial_partners(*)')
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
            .map((row: any) => row.financial_partners)
            .filter(Boolean) as FinancialPartner[];

        const filtered = candidates.filter((partner) => this.matchesResolutionInput(partner, input));
        return filtered[0] || null;
    }

    private toResolvedProviderConfig(partner: FinancialPartner, operation: MoneyOperation): ResolvedProviderConfig {
        const operationConfig = partner.mapping_config?.operations?.[operation];
        const baseUrl =
            partner.mapping_config?.service_roots?.[this.operationToServiceKey(operation)] ||
            partner.mapping_config?.service_root ||
            partner.api_base_url ||
            undefined;

        return {
            providerId: partner.id,
            providerCode: String(
                partner.provider_metadata?.provider_code ||
                partner.provider_metadata?.brand_name ||
                partner.name,
            ),
            providerName: partner.name,
            rail: normalizeRail(String(partner.provider_metadata?.rail || '')) || fallbackRailFromPartner(partner),
            operation,
            authType: partner.logic_type,
            baseUrl,
            timeoutMs: operationConfig ? Number((operationConfig as any).timeout_ms || 30000) : undefined,
            requestTemplate: operationConfig?.payload_template,
            responseMapping: operationConfig?.response_mapping,
            extraConfig: {
                partnerType: partner.type,
                supportedCurrencies: partner.supported_currencies || [],
                providerMetadata: partner.provider_metadata || {},
            },
        };
    }

    private matchesResolutionInput(partner: FinancialPartner, input: ProviderResolutionInput): boolean {
        if (input.preferredProviderCode) {
            const code = String(
                partner.provider_metadata?.provider_code ||
                partner.provider_metadata?.brand_name ||
                partner.name,
            ).trim().toUpperCase();
            if (code !== String(input.preferredProviderCode).trim().toUpperCase()) {
                return false;
            }
        }

        const rail = normalizeRail(String(partner.provider_metadata?.rail || '')) || fallbackRailFromPartner(partner);
        if (rail !== input.rail) return false;

        const operations = (partner.provider_metadata?.operations || []) as Array<MoneyOperation | string>;
        if (operations.length > 0 && !operations.map((value) => String(value).trim().toUpperCase()).includes(input.operation)) {
            return false;
        }

        const countryCodes = (partner.provider_metadata?.countries || []) as string[];
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

        if (input.operation && partner.mapping_config?.operations && !partner.mapping_config.operations[input.operation]) {
            const fallbackAllowed =
                (input.operation === 'COLLECTION_REQUEST' && partner.mapping_config.stk_push) ||
                (input.operation === 'DISBURSEMENT_REQUEST' && partner.mapping_config.disbursement) ||
                (input.operation === 'BALANCE_INQUIRY' && partner.mapping_config.balance);
            if (!fallbackAllowed) return false;
        }

        return true;
    }

    private resolvePriority(partner: FinancialPartner, operation: MoneyOperation): number {
        const metadataPriority = Number(partner.provider_metadata?.routing_priority);
        const operationPriority = Number((partner.mapping_config as any)?.routing?.[operation]?.priority);
        if (Number.isFinite(operationPriority)) return operationPriority;
        if (Number.isFinite(metadataPriority)) return metadataPriority;
        return 100;
    }

    private operationToServiceKey(operation: MoneyOperation): string {
        if (operation === 'COLLECTION_REQUEST') return 'stk_push';
        if (operation === 'DISBURSEMENT_REQUEST') return 'disbursement';
        if (operation === 'BALANCE_INQUIRY') return 'balance';
        if (operation === 'AUTH') return 'auth';
        return operation.toLowerCase();
    }
}

export const providerRoutingService = new ProviderRoutingService();
