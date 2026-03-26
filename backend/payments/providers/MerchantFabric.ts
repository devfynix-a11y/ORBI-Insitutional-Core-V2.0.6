
import { FinancialPartner } from '../../../types.js';
import { getSupabase } from '../../../services/supabaseClient.js';
import { DataVault } from '../../security/encryption.js';
import { UUID } from '../../../services/utils.js';
import { secureProviderRegistryPayload } from './RegistryPayloadSecurity.js';
import { normalizeFinancialPartnerInput } from './ProviderRegistryValidator.js';

/**
 * ORBI MERCHANT FABRIC (V2.1)
 * ----------------------------
 * Central registry for external liquidity nodes.
 * Implements "Zero-Visibility Persistence" for all node secrets.
 */
class MerchantFabricService {
    
    public async registerPartner(payload: Partial<FinancialPartner>): Promise<FinancialPartner> {
        const sb = getSupabase();
        if (!sb) throw new Error("VAULT_OFFLINE");

        const normalized = normalizeFinancialPartnerInput({
            ...payload,
            logic_type: payload.logic_type || 'REGISTRY',
        });

        const partner: FinancialPartner = {
            id: UUID.generate(),
            name: normalized.name || 'Unknown Node',
            type: normalized.type || 'mobile_money',
            icon: payload.icon || 'university',
            color: payload.color || '#4361EE',
            client_id: payload.client_id,
            client_secret: payload.client_secret,
            api_base_url: normalized.api_base_url,
            status: 'ACTIVE',
            created_at: new Date().toISOString(),
            logic_type: normalized.logic_type || 'REGISTRY',
            mapping_config: normalized.mapping_config,
            provider_metadata: payload.provider_metadata,
            connection_secret: payload.connection_secret,
            webhook_secret: payload.webhook_secret,
        };

        const securedPartner = await secureProviderRegistryPayload(partner);
        const { error } = await sb.from('financial_partners').insert(securedPartner);
        if (error) throw error;
        
        return securedPartner;
    }

    /**
     * SECURE RETRIEVAL
     * Explicitly selects only non-sensitive columns.
     * The 'client_secret' and 'connection_secret' columns are NEVER returned to the UI.
     */
    public async getPartners(): Promise<FinancialPartner[]> {
        const sb = getSupabase();
        if (!sb) return [];
        
        const { data } = await sb.from('financial_partners')
            .select(`
                id, 
                name, 
                type, 
                icon, 
                color, 
                api_base_url, 
                status, 
                logic_type, 
                created_at,
                provider_metadata,
                mapping_config
            `)
            .eq('status', 'ACTIVE');
            
        return data || [];
    }

    public async updatePartnerToken(id: string, token: string, expiresIn: number): Promise<void> {
        const sb = getSupabase();
        if (!sb) return;
        const expiry = Date.now() + (expiresIn * 1000);
        
        // Tokens are also encrypted at rest
        const encryptedToken = await DataVault.encrypt(token);
        
        await sb.from('financial_partners').update({
            token_cache: encryptedToken,
            token_expiry: expiry
        }).eq('id', id);
    }
}

export const MerchantFabric = new MerchantFabricService();
