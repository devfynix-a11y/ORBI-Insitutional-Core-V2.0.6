import { FinancialPartner, ProviderResolutionInput } from '../../types.js';
import { providerSelectionService } from './ProviderSelectionService.js';
import { ProviderFactory } from './providers/ProviderFactory.js';
import { toProviderDomainError } from './providers/ProviderErrorNormalizer.js';
import { providerRetryPolicy } from './providers/ProviderRetryPolicy.js';

export class GatewayService {
    public async initiateCollection(partner: FinancialPartner, phone: string, amount: number, reference: string) {
        const providerNode = ProviderFactory.getProvider(partner);
        const response = await providerRetryPolicy.execute(
            partner,
            'COLLECTION_REQUEST',
            () => providerNode.execute(partner, {
                operation: 'COLLECTION_REQUEST',
                phone,
                amount,
                reference,
            }),
        );

        if (!response.success) {
            throw toProviderDomainError(new Error(`PROVIDER_REJECTION: ${response.message}`), partner);
        }

        return {
            success: true,
            provider_ref: response.providerRef,
            message: response.message,
            status: response.status,
        };
    }

    public async initiateStkPush(partner: FinancialPartner, phone: string, amount: number, reference: string) {
        return this.initiateCollection(partner, phone, amount, reference);
    }

    public async processPayout(partner: FinancialPartner, phone: string, amount: number, reference: string) {
        const providerNode = ProviderFactory.getProvider(partner);
        const response = await providerRetryPolicy.execute(
            partner,
            'DISBURSEMENT_REQUEST',
            () => providerNode.execute(partner, {
                operation: 'DISBURSEMENT_REQUEST',
                phone,
                amount,
                reference,
            }),
        );

        if (!response.success) {
            throw toProviderDomainError(new Error(`DISBURSEMENT_REJECTED: ${response.message}`), partner);
        }

        return {
            success: true,
            provider_ref: response.providerRef,
            status: response.status.toUpperCase(),
        };
    }

    public async resolveSelection(input: ProviderResolutionInput) {
        return providerSelectionService.select(input);
    }
}

export const ExternalGateway = new GatewayService();
