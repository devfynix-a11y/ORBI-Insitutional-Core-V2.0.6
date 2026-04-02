import { IProviderAdapter } from './types.js';
import { GenericRestProvider } from './GenericRestProvider.js';
import { FinancialPartner } from '../../../types.js';
import { assertProviderRegistry } from './ProviderRegistryAdapter.js';

export class ProviderFactory {
    private static registryProvider: IProviderAdapter | null = null;

    /**
     * Formal registry-driven adapter resolver.
     * All provider categories resolve to registry-backed adapters.
     */
    public static getProvider(partner: FinancialPartner): IProviderAdapter {
        assertProviderRegistry(partner);
        if (!this.registryProvider) {
            this.registryProvider = new GenericRestProvider();
        }
        return this.registryProvider;
    }
}
