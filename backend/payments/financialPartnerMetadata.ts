import {
    FinancialPartner,
    FinancialPartnerMetadata,
    ProviderGroup,
} from '../../types.js';

function normalizeGroup(value?: string): ProviderGroup | undefined {
    const normalized = String(value || '').trim().toLowerCase();
    if (!normalized) return undefined;
    if (normalized === 'mobile' || normalized === 'mobile_money') return 'Mobile';
    if (normalized === 'bank' || normalized === 'banking') return 'Bank';
    if (
        normalized === 'gateway' ||
        normalized === 'gateways' ||
        normalized === 'processor' ||
        normalized === 'payment_gateway'
    ) {
        return 'Gateways';
    }
    if (normalized === 'crypto') return 'Crypto';
    return undefined;
}

export function resolveProviderGroup(
    partner?: Partial<FinancialPartner> | null,
    metadata?: FinancialPartnerMetadata | null,
): ProviderGroup {
    const metadataGroup =
        normalizeGroup(metadata?.group) ||
        normalizeGroup(metadata?.provider_group) ||
        normalizeGroup((metadata as any)?.category);
    if (metadataGroup) return metadataGroup;

    const type = String(partner?.type || '').trim().toLowerCase();
    if (type === 'mobile_money') return 'Mobile';
    if (type === 'bank') return 'Bank';
    if (type === 'crypto') return 'Crypto';
    return 'Gateways';
}

export function normalizeFinancialPartnerMetadata(
    partner?: Partial<FinancialPartner> | null,
): FinancialPartnerMetadata {
    const metadata = (partner?.provider_metadata || {}) as FinancialPartnerMetadata;
    const brandName = metadata.brand_name || metadata.display_name || partner?.name || '';
    const displayIcon = metadata.display_icon || metadata.icon || partner?.icon || '';
    const channels = Array.isArray(metadata.channels) ? metadata.channels : [];
    const countries = Array.isArray(metadata.countries) ? metadata.countries : [];
    const operations = Array.isArray(metadata.operations) ? metadata.operations : [];

    return {
        ...metadata,
        group: resolveProviderGroup(partner, metadata),
        brand_name: brandName,
        display_name: metadata.display_name || brandName,
        display_icon: displayIcon,
        icon: metadata.icon || displayIcon,
        color: metadata.color || partner?.color || '',
        channels,
        checkout_mode: metadata.checkout_mode || 'server_to_server',
        countries,
        operations,
        sort_order:
            typeof metadata.sort_order === 'string'
                ? Number(metadata.sort_order)
                : metadata.sort_order,
        routing_priority:
            typeof metadata.routing_priority === 'string'
                ? Number(metadata.routing_priority)
                : metadata.routing_priority,
    };
}

export function resolveProviderCode(partner?: Partial<FinancialPartner> | null): string {
    const metadata = normalizeFinancialPartnerMetadata(partner);
    return String(metadata.provider_code || metadata.brand_name || partner?.name || '').trim();
}

