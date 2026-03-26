
import { FinancialPartner } from '../../types.js';
import { ProviderFactory } from './providers/ProviderFactory.js';

/**
 * ORBI EXTERNAL GATEWAY SERVICE (V3.0)
 * ------------------------------
 * Orchestrator node using provider-registry driven execution.
 */
export class GatewayService {
    
    /**
     * INITIATE STK PUSH (CASH-IN)
     */
    public async initiateStkPush(partner: FinancialPartner, phone: string, amount: number, reference: string) {
        // ProviderFactory now resolves the registry-backed adapter for this partner.
        const providerNode = ProviderFactory.getProvider(partner);
        
        const response = await providerNode.stkPush(partner, phone, amount, reference);
        
        if (!response.success) {
            throw new Error(`PROVIDER_REJECTION: ${response.message}`);
        }

        return {
            success: true,
            provider_ref: response.providerRef,
            message: response.message
        };
    }

    /**
     * DISBURSEMENT (CASH-OUT / B2C)
     */
    public async processPayout(partner: FinancialPartner, phone: string, amount: number, reference: string) {
        const providerNode = ProviderFactory.getProvider(partner);
        
        const response = await providerNode.disburse(partner, phone, amount, reference);
        
        if (!response.success) {
            throw new Error(`DISBURSEMENT_REJECTED: ${response.message}`);
        }

        return {
            success: true,
            provider_ref: response.providerRef,
            status: 'PROCESSING'
        };
    }
}

export const ExternalGateway = new GatewayService();
