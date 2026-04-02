import { getAdminSupabase } from '../supabaseClient.js';
import { FinancialPartner } from '../../types.js';
import { secureProviderRegistryPayload } from '../payments/providers/RegistryPayloadSecurity.js';
import {
    assertPartnerActivationReady,
    normalizeFinancialPartnerInput,
} from '../payments/providers/ProviderRegistryValidator.js';

export class PartnerRegistry {
    private static sb = getAdminSupabase();

    public static async listPartners() {
        return await this.sb!.from('financial_partners').select('*');
    }

    public static async addPartner(partner: Omit<FinancialPartner, 'id' | 'created_at'>) {
        const normalized = normalizeFinancialPartnerInput({
            ...partner,
            logic_type: partner.logic_type || 'REGISTRY',
        });
        assertPartnerActivationReady(normalized);
        const secured = await secureProviderRegistryPayload({
            ...normalized,
        });
        return await this.sb!.from('financial_partners').insert(secured);
    }

    public static async updatePartner(id: string, updates: Partial<FinancialPartner>) {
        const { data: existing, error: existingError } = await this.sb!
            .from('financial_partners')
            .select('*')
            .eq('id', id)
            .maybeSingle();
        if (existingError) return { data: null, error: existingError };
        if (!existing) {
            return {
                data: null,
                error: { message: 'PARTNER_NOT_FOUND' },
            } as any;
        }

        const normalized = normalizeFinancialPartnerInput(updates, 'update');
        const activationCandidate = {
            ...existing,
            ...normalized,
            provider_metadata: {
                ...(existing.provider_metadata || {}),
                ...(normalized.provider_metadata || {}),
            },
            mapping_config: normalized.mapping_config || existing.mapping_config,
        };
        assertPartnerActivationReady(activationCandidate);
        const secured = await secureProviderRegistryPayload(normalized);
        return await this.sb!.from('financial_partners').update(secured).eq('id', id);
    }

    public static async deletePartner(id: string) {
        return await this.sb!.from('financial_partners').delete().eq('id', id);
    }
}
