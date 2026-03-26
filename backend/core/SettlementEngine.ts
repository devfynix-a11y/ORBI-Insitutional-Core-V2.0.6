import { getSupabase } from '../supabaseClient.js';
import { UUID } from '../../services/utils.js';
import { platformFeeService } from '../payments/PlatformFeeService.js';

export class SettlementEngineService {
    
    /**
     * Get Settlement Configuration for a Tenant
     */
    async getSettlementConfig(userId: string, tenantId: string) {
        const sb = getSupabase();
        if (!sb) throw new Error("Database not connected");

        // Verify access
        const { data: link } = await sb
            .from('tenant_users')
            .select('role')
            .eq('tenant_id', tenantId)
            .eq('user_id', userId)
            .single();

        if (!link) throw new Error("Unauthorized");

        const { data, error } = await sb
            .from('tenant_settlements')
            .select('*')
            .eq('tenant_id', tenantId)
            .single();

        if (error && error.code !== 'PGRST116') throw new Error(error.message);
        return data || null;
    }

    /**
     * Update Settlement Configuration
     */
    async updateSettlementConfig(userId: string, tenantId: string, config: any) {
        const sb = getSupabase();
        if (!sb) throw new Error("Database not connected");

        // Verify access (owner/admin only)
        const { data: link } = await sb
            .from('tenant_users')
            .select('role')
            .eq('tenant_id', tenantId)
            .eq('user_id', userId)
            .single();

        if (!link || !['owner', 'admin'].includes(link.role)) {
            throw new Error("Unauthorized to update settlement config");
        }

        const { data, error } = await sb
            .from('tenant_settlements')
            .upsert({
                tenant_id: tenantId,
                ...config,
                updated_at: new Date().toISOString()
            })
            .select()
            .single();

        if (error) throw new Error(error.message);
        return data;
    }

    /**
     * Calculate Pending Settlement Amount for a Tenant
     * This sums up all COMPLETED transactions that haven't been settled yet.
     */
    async calculatePendingSettlement(tenantId: string) {
        const sb = getSupabase();
        if (!sb) throw new Error("Database not connected");

        // We sum 'CREDIT' transactions (money coming into the tenant) 
        // and subtract 'DEBIT' (money going out, e.g., refunds).
        // For simplicity, we assume we're settling the tenant's primary wallet.
        const { data, error } = await sb
            .from('transactions')
            .select('amount, type')
            .eq('tenant_id', tenantId)
            .eq('status', 'COMPLETED')
            .eq('settlement_status', 'PENDING');

        if (error) throw new Error(error.message);

        let total = 0;
        data.forEach(tx => {
            if (tx.type === 'CREDIT') total += Number(tx.amount);
            else if (tx.type === 'DEBIT') total -= Number(tx.amount);
        });

        return total;
    }

    /**
     * Trigger a Manual Settlement Payout
     */
    async triggerPayout(userId: string, tenantId: string) {
        const sb = getSupabase();
        if (!sb) throw new Error("Database not connected");

        // 1. Verify access
        const { data: link } = await sb
            .from('tenant_users')
            .select('role')
            .eq('tenant_id', tenantId)
            .eq('user_id', userId)
            .single();

        if (!link || !['owner', 'admin'].includes(link.role)) {
            throw new Error("Unauthorized to trigger payout");
        }

        // 2. Get Settlement Config
        const config = await this.getSettlementConfig(userId, tenantId);
        if (!config) throw new Error("Settlement configuration not found. Please set up bank details first.");

        // 3. Calculate Amount
        const amount = await this.calculatePendingSettlement(tenantId);
        if (amount <= 0) throw new Error("No pending funds available for settlement.");

        // 4. Calculate Fees from admin-managed platform fee configuration
        const payoutCurrency = String(config?.currency || '').trim().toUpperCase();
        if (!payoutCurrency) {
            throw new Error("CURRENCY_REQUIRED: Settlement payout requires an explicit configured currency.");
        }
        const payoutFee = await platformFeeService.resolveFee({
            flowCode: 'TENANT_SETTLEMENT_PAYOUT',
            amount,
            currency: payoutCurrency,
            transactionType: 'TENANT_SETTLEMENT_PAYOUT',
            metadata: {
                tenant_id: tenantId,
            },
        });
        const feeDeducted = payoutFee.totalFee;
        const netAmount = amount - feeDeducted;

        if (netAmount <= 0) throw new Error("Amount too small for settlement after fees.");

        // 5. Create Payout Record (Atomic Transaction)
        const { data: payout, error: payoutError } = await sb
            .from('settlement_payouts')
            .insert({
                tenant_id: tenantId,
                amount,
                fee_deducted: feeDeducted,
                net_amount: netAmount,
                status: 'PROCESSING',
                destination_snapshot: config,
                reference: `PAY-${UUID.generate().substring(0, 8).toUpperCase()}`
            })
            .select()
            .single();

        if (payoutError) throw new Error(payoutError.message);

        // 6. Link Transactions to this Payout
        const { error: updateError } = await sb
            .from('transactions')
            .update({ 
                settlement_id: payout.id,
                settlement_status: 'IN_PROGRESS'
            })
            .eq('tenant_id', tenantId)
            .eq('status', 'COMPLETED')
            .eq('settlement_status', 'PENDING');

        if (updateError) {
            // Rollback payout if update fails
            await sb.from('settlement_payouts').delete().eq('id', payout.id);
            throw new Error(`Failed to link transactions: ${updateError.message}`);
        }

        // 7. Execute Payout (In a real system, this would call a Bank API)
        // For this demo, we simulate success after 2 seconds.
        setTimeout(async () => {
            const { error: finalError } = await sb
                .from('settlement_payouts')
                .update({ 
                    status: 'COMPLETED',
                    processed_at: new Date().toISOString()
                })
                .eq('id', payout.id);

            if (!finalError) {
                await sb
                    .from('transactions')
                    .update({ settlement_status: 'SETTLED' })
                    .eq('settlement_id', payout.id);
            }
        }, 2000);

        return payout;
    }

    /**
     * Get Payout History
     */
    async getPayoutHistory(userId: string, tenantId: string) {
        const sb = getSupabase();
        if (!sb) return [];

        const { data, error } = await sb
            .from('settlement_payouts')
            .select('*')
            .eq('tenant_id', tenantId)
            .order('created_at', { ascending: false });

        if (error) throw new Error(error.message);
        return data;
    }
}

export const SettlementEngine = new SettlementEngineService();
