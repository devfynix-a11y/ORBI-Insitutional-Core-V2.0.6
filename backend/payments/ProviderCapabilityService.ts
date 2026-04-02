import { FinancialPartner, MoneyOperation, RailType } from '../../types.js';
import { normalizeFinancialPartnerMetadata, resolveProviderCode } from './financialPartnerMetadata.js';
import { ProviderCapabilityDescriptor } from './providers/types.js';
import { assertProviderRegistry, resolveOperationConfig } from './providers/ProviderRegistryAdapter.js';

function resolveCategory(partner: FinancialPartner): ProviderCapabilityDescriptor['category'] {
  const normalized = String(partner.type || '').trim().toLowerCase();
  if (normalized === 'mobile_money') return 'mobile_money';
  if (normalized === 'bank') return 'bank';
  if (normalized === 'crypto') return 'crypto';
  return 'card';
}

function resolveRail(partner: FinancialPartner): RailType {
  const metadata = normalizeFinancialPartnerMetadata(partner);
  const rail = String(metadata.rail || '').trim().toUpperCase();
  if (rail === 'MOBILE_MONEY') return 'MOBILE_MONEY';
  if (rail === 'BANK') return 'BANK';
  if (rail === 'CRYPTO') return 'CRYPTO';
  if (rail === 'CARD_GATEWAY') return 'CARD_GATEWAY';
  return resolveCategory(partner) === 'mobile_money' ? 'MOBILE_MONEY' : resolveCategory(partner) === 'bank' ? 'BANK' : resolveCategory(partner) === 'crypto' ? 'CRYPTO' : 'CARD_GATEWAY';
}

export class ProviderCapabilityService {
  describe(partner: FinancialPartner): ProviderCapabilityDescriptor {
    const metadata = normalizeFinancialPartnerMetadata(partner);
    const registry = assertProviderRegistry(partner);
    const supportedOperations = new Set<MoneyOperation>();

    for (const operation of metadata.operations || []) {
      supportedOperations.add(String(operation).trim().toUpperCase() as MoneyOperation);
    }
    for (const operation of ['COLLECTION_REQUEST', 'DISBURSEMENT_REQUEST', 'BALANCE_INQUIRY'] as MoneyOperation[]) {
      if (resolveOperationConfig(registry, operation)) {
        supportedOperations.add(operation);
      }
    }

    const operationList = Array.from(supportedOperations);
    return {
      providerId: partner.id,
      providerCode: resolveProviderCode(partner),
      providerName: partner.name,
      category: resolveCategory(partner),
      rail: resolveRail(partner),
      supportsWebhooks: metadata.supports_webhooks === true || Boolean(registry.callback),
      supportsPolling: metadata.supports_polling === true,
      supportedOperations: operationList,
      supportedCurrencies: Array.isArray(partner.supported_currencies) ? partner.supported_currencies : [],
      supportedCountries: Array.isArray(metadata.countries) ? metadata.countries : [],
      retryableOperations: operationList.filter((op) => op !== 'AUTH'),
      preferredRoutingPriority: Number(metadata.routing_priority || 100),
      extra: {
        checkoutMode: metadata.checkout_mode,
        channels: metadata.channels || [],
        providerGroup: metadata.group,
      },
    };
  }
}

export const providerCapabilityService = new ProviderCapabilityService();
