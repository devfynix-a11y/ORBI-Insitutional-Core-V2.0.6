import { ProviderResolutionInput, ResolvedProviderConfig } from '../../types.js';
import { providerRoutingService } from './ProviderRoutingService.js';

export interface ProviderSelectionResult {
  resolved: ResolvedProviderConfig;
  selectedAt: string;
}

export class ProviderSelectionService {
  async select(input: ProviderResolutionInput): Promise<ProviderSelectionResult> {
    const resolved = await providerRoutingService.resolveProvider(input);
    return {
      resolved,
      selectedAt: new Date().toISOString(),
    };
  }
}

export const providerSelectionService = new ProviderSelectionService();
