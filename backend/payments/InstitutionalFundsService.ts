import { getAdminSupabase } from '../supabaseClient.js';
import { TransactionService } from '../../ledger/transactionService.js';
import { Audit } from '../security/audit.js';
import { UUID } from '../../services/utils.js';
import {
    ExternalFundMovementDirection,
    ExternalFundMovementStatus,
    InstitutionalAccountRole,
    LedgerEntry,
    MoneyOperation,
    RailType,
} from '../../types.js';
import { providerRoutingService } from './ProviderRoutingService.js';
import { platformFeeService } from './PlatformFeeService.js';
import { GoalService } from '../../strategy/goalService.js';

type InstitutionalAccountLookup = {
    id?: string;
    role: InstitutionalAccountRole;
    currency: string;
    providerId?: string;
};

type ExternalFundMovementPayload = {
    direction: ExternalFundMovementDirection;
    amount: number;
    currency?: string;
    providerId?: string;
    rail?: RailType;
    countryCode?: string;
    operation?: MoneyOperation;
    preferredProviderCode?: string;
    description?: string;
    transactionType?: string;
    transaction_type?: string;
    providerInput?: string;
    provider_input?: string;
    counterpartyType?: string;
    counterparty_type?: string;
    sourceWalletId?: string;
    targetWalletId?: string;
    sourceInstitutionalAccountId?: string;
    targetInstitutionalAccountId?: string;
    externalReference?: string;
    sourceExternalRef?: string;
    targetExternalRef?: string;
    feeAmount?: number;
    taxAmount?: number;
    metadata?: Record<string, any>;
};

type NormalizedMovement = {
    direction: ExternalFundMovementDirection;
    amount: number;
    grossAmount: number;
    netAmount: number;
    feeAmount: number;
    taxAmount: number;
    currency: string;
    providerId?: string;
    rail?: RailType;
    countryCode?: string;
    operation?: MoneyOperation;
    preferredProviderCode?: string;
    transactionType?: string;
    providerInput?: string;
    counterpartyType?: string;
    description: string;
    sourceWalletId?: string;
    targetWalletId?: string;
    sourceInstitutionalAccountId?: string;
    targetInstitutionalAccountId?: string;
    externalReference?: string;
    sourceExternalRef?: string;
    targetExternalRef?: string;
    metadata: Record<string, any>;
};

type MovementContext = Awaited<ReturnType<InstitutionalFundsService['buildMovementContext']>>;

export class InstitutionalFundsService {
    private readonly ledger = new TransactionService();
    private readonly goals = new GoalService();

    async listInstitutionalAccounts(filters?: {
        role?: string;
        status?: string;
        providerId?: string;
        currency?: string;
    }) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        let query = sb
            .from('institutional_payment_accounts')
            .select('*, financial_partners(id, name, type, status, provider_metadata)')
            .order('role', { ascending: true })
            .order('is_primary', { ascending: false })
            .order('created_at', { ascending: false });

        if (filters?.role) query = query.eq('role', filters.role);
        if (filters?.status) query = query.eq('status', filters.status);
        if (filters?.providerId) query = query.eq('provider_id', filters.providerId);
        if (filters?.currency) query = query.eq('currency', filters.currency.toUpperCase());

        const { data, error } = await query;
        if (error) throw new Error(error.message);
        return data || [];
    }

    async upsertInstitutionalAccount(payload: any, actorId: string, accountId?: string) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const existing = accountId
            ? await sb
                .from('institutional_payment_accounts')
                .select('*')
                .eq('id', accountId)
                .maybeSingle()
            : { data: null, error: null };

        if (existing.error) throw new Error(existing.error.message);
        if (accountId && !existing.data) throw new Error('INSTITUTIONAL_ACCOUNT_NOT_FOUND');

        const current = existing.data || {};
        const auditMetadata = {
            updated_by: actorId,
            updated_at: new Date().toISOString(),
        };
        const normalized = {
            role: String(payload.role ?? current.role ?? '').trim().toUpperCase(),
            provider_id: payload.providerId ?? payload.provider_id ?? current.provider_id ?? null,
            bank_name: String(payload.bankName ?? payload.bank_name ?? current.bank_name ?? '').trim(),
            account_name: String(payload.accountName ?? payload.account_name ?? current.account_name ?? '').trim(),
            account_number: String(payload.accountNumber ?? payload.account_number ?? current.account_number ?? '').trim(),
            currency: String(payload.currency ?? current.currency ?? 'TZS').trim().toUpperCase(),
            country_code: payload.countryCode ?? payload.country_code ?? current.country_code ?? null,
            status: String(payload.status ?? current.status ?? 'ACTIVE').trim().toUpperCase(),
            is_primary: payload.isPrimary ?? payload.is_primary ?? current.is_primary ?? false,
            metadata: {
                ...(current.metadata || {}),
                ...(payload.metadata || {}),
                admin_audit: {
                    ...((current.metadata || {}).admin_audit || {}),
                    ...(((payload.metadata || {}).admin_audit) || {}),
                    ...auditMetadata,
                },
            },
            updated_at: new Date().toISOString(),
        };

        if (!normalized.role || !normalized.bank_name || !normalized.account_name || !normalized.account_number) {
            throw new Error('INVALID_INSTITUTIONAL_ACCOUNT_PAYLOAD');
        }

        if (normalized.is_primary) {
            const primaryResetQuery = sb
                .from('institutional_payment_accounts')
                .update({ is_primary: false, updated_at: normalized.updated_at })
                .eq('role', normalized.role)
                .eq('currency', normalized.currency);

            const scopedPrimaryResetQuery = normalized.provider_id
                ? primaryResetQuery.eq('provider_id', normalized.provider_id)
                : primaryResetQuery.is('provider_id', null);

            await scopedPrimaryResetQuery;
        }

        const tablePayload = {
            ...normalized,
            created_at: new Date().toISOString(),
        };

        const query = accountId
            ? sb
                .from('institutional_payment_accounts')
                .update(normalized)
                .eq('id', accountId)
                .select('*')
                .single()
            : sb
                .from('institutional_payment_accounts')
                .insert(tablePayload)
                .select('*')
                .single();

        const { data, error } = await query;
        if (error) throw new Error(error.message);

        await Audit.log('ADMIN', actorId, accountId ? 'INSTITUTIONAL_ACCOUNT_UPDATED' : 'INSTITUTIONAL_ACCOUNT_CREATED', {
            accountId: data.id,
            role: data.role,
            currency: data.currency,
            providerId: data.provider_id,
        });

        return data;
    }

    async previewMovement(userId: string, payload: ExternalFundMovementPayload) {
        return this.buildMovementContext(userId, payload);
    }

    async createIncomingDepositIntent(userId: string, payload: Omit<ExternalFundMovementPayload, 'direction'>) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const preview = await this.buildMovementContext(userId, {
            ...payload,
            direction: 'EXTERNAL_TO_INTERNAL',
        });
        const movementId = UUID.generate();
        const externalReference = preview.externalReference || `CASHIN-${UUID.generateShortCode(12)}`;
        const now = new Date().toISOString();

        const { data, error } = await sb
            .from('external_fund_movements')
            .insert({
                id: movementId,
                user_id: userId,
                direction: 'EXTERNAL_TO_INTERNAL',
                status: 'initiated',
                provider_id: preview.providerId || null,
                institutional_source_account_id: preview.sourceInstitutionalAccount?.id || null,
                target_wallet_id: preview.targetWalletId || null,
                gross_amount: preview.grossAmount,
                net_amount: preview.netAmount,
                fee_amount: preview.feeAmount,
                tax_amount: preview.taxAmount,
                currency: preview.currency,
                description: preview.description,
                external_reference: externalReference,
                source_external_ref: preview.sourceExternalRef || null,
                target_external_ref: preview.targetExternalRef || null,
                metadata: {
                    ...preview.metadata,
                    intent_kind: 'INCOMING_DEPOSIT',
                    settlement_model: 'WEBHOOK_DRIVEN_EXTERNAL_TO_INTERNAL',
                    double_entry_posted: false,
                },
                created_at: now,
                updated_at: now,
            })
            .select('*')
            .single();

        if (error) throw new Error(error.message);

        await Audit.log('FINANCIAL', userId, 'EXTERNAL_DEPOSIT_INTENT_CREATED', {
            movementId,
            providerId: preview.providerId,
            targetWalletId: preview.targetWalletId,
            amount: preview.amount,
            currency: preview.currency,
            externalReference,
        });

        return {
            movement: data,
            instructions: {
                reference: externalReference,
                providerId: preview.providerId || null,
                amount: preview.amount,
                currency: preview.currency,
                channel: 'NETWORK_DEPOSIT',
            },
        };
    }

    async processMovement(userId: string, payload: ExternalFundMovementPayload) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const preview = await this.buildMovementContext(userId, payload);
        const movementId = UUID.generate();
        const now = new Date().toISOString();

        if (preview.direction === 'EXTERNAL_TO_EXTERNAL') {
            const { data, error } = await sb
                .from('external_fund_movements')
                .insert({
                    id: movementId,
                    user_id: userId,
                    direction: preview.direction,
                    status: 'recorded',
                    provider_id: preview.providerId || null,
                    institutional_source_account_id: preview.sourceInstitutionalAccount?.id || null,
                    institutional_target_account_id: preview.targetInstitutionalAccount?.id || null,
                    source_wallet_id: preview.sourceWalletId || null,
                    target_wallet_id: preview.targetWalletId || null,
                    gross_amount: preview.grossAmount,
                    net_amount: preview.netAmount,
                    fee_amount: preview.feeAmount,
                    tax_amount: preview.taxAmount,
                    currency: preview.currency,
                    description: preview.description,
                    external_reference: preview.externalReference || null,
                    source_external_ref: preview.sourceExternalRef || null,
                    target_external_ref: preview.targetExternalRef || null,
                    metadata: {
                        ...preview.metadata,
                        settlement_model: 'RECORD_ONLY',
                        double_entry_posted: false,
                    },
                    created_at: now,
                    updated_at: now,
                })
                .select('*')
                .single();

            if (error) throw new Error(error.message);

            await Audit.log('FINANCIAL', userId, 'EXTERNAL_FUND_MOVEMENT_RECORDED', {
                movementId,
                direction: preview.direction,
                amount: preview.amount,
                currency: preview.currency,
            });

            return {
                movement: data,
                ledgerPosted: false,
            };
        }

        const { data, error } = await sb
            .from('external_fund_movements')
            .insert({
                id: movementId,
                user_id: userId,
                direction: preview.direction,
                status: 'initiated',
                provider_id: preview.providerId || null,
                institutional_source_account_id: preview.sourceInstitutionalAccount?.id || null,
                institutional_target_account_id: preview.targetInstitutionalAccount?.id || null,
                source_wallet_id: preview.sourceWalletId || null,
                target_wallet_id: preview.targetWalletId || null,
                gross_amount: preview.grossAmount,
                net_amount: preview.netAmount,
                fee_amount: preview.feeAmount,
                tax_amount: preview.taxAmount,
                currency: preview.currency,
                description: preview.description,
                external_reference: preview.externalReference || null,
                source_external_ref: preview.sourceExternalRef || null,
                target_external_ref: preview.targetExternalRef || null,
                metadata: {
                    ...preview.metadata,
                    settlement_model: 'WEBHOOK_DRIVEN_EXTERNAL_SETTLEMENT',
                    double_entry_posted: false,
                },
                created_at: now,
                updated_at: now,
            })
            .select('*')
            .single();

        if (error) throw new Error(error.message);

        await Audit.log('FINANCIAL', userId, 'EXTERNAL_FUND_MOVEMENT_INITIATED', {
            movementId,
            direction: preview.direction,
            amount: preview.amount,
            currency: preview.currency,
        });

        return {
            movement: data,
            ledgerPosted: false,
        };
    }

    async handleWebhookMovement(
        providerId: string,
        reference: string,
        status: 'completed' | 'failed' | 'processing' | 'pending',
        message?: string,
        providerEventId?: string,
        rawPayload?: any,
    ) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');
        if (!reference) throw new Error('WEBHOOK_REFERENCE_MISSING');

        const { data: movement, error } = await sb
            .from('external_fund_movements')
            .select('*')
            .eq('provider_id', providerId)
            .or(`external_reference.eq.${reference},source_external_ref.eq.${reference},target_external_ref.eq.${reference}`)
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

        if (error) throw new Error(error.message);
        if (!movement) {
            throw new Error(`MOVEMENT_NOT_FOUND:${reference}`);
        }

        if (movement.transaction_id || movement.status === 'completed') {
            return {
                movement,
                transactionId: movement.transaction_id,
                alreadyProcessed: true,
            };
        }

        if (status === 'processing' || status === 'pending') {
            const { data: updated, error: updateError } = await sb
                .from('external_fund_movements')
                .update({
                    status: 'processing',
                    updated_at: new Date().toISOString(),
                    metadata: {
                        ...(movement.metadata || {}),
                        webhook_status: status,
                        webhook_message: message || null,
                        provider_event_id: providerEventId || null,
                        last_webhook_payload: rawPayload || null,
                    },
                })
                .eq('id', movement.id)
                .select('*')
                .single();
            if (updateError) throw new Error(updateError.message);
            return { movement: updated, processing: true };
        }

        if (status === 'failed') {
            const { data: updated, error: updateError } = await sb
                .from('external_fund_movements')
                .update({
                    status: 'failed',
                    updated_at: new Date().toISOString(),
                    metadata: {
                        ...(movement.metadata || {}),
                        webhook_status: status,
                        webhook_message: message || null,
                        provider_event_id: providerEventId || null,
                        last_webhook_payload: rawPayload || null,
                    },
                })
                .eq('id', movement.id)
                .select('*')
                .single();
            if (updateError) throw new Error(updateError.message);
            return { movement: updated, failed: true };
        }

        if (movement.direction === 'EXTERNAL_TO_EXTERNAL') {
            const { data: updated, error: updateError } = await sb
                .from('external_fund_movements')
                .update({
                    status: 'completed',
                    updated_at: new Date().toISOString(),
                    metadata: {
                        ...(movement.metadata || {}),
                        webhook_status: status,
                        webhook_message: message || null,
                        provider_event_id: providerEventId || null,
                        last_webhook_payload: rawPayload || null,
                        double_entry_posted: false,
                    },
                })
                .eq('id', movement.id)
                .select('*')
                .single();
            if (updateError) throw new Error(updateError.message);
            return { movement: updated, ledgerPosted: false };
        }

        const preview = await this.buildMovementContext(movement.user_id, {
            direction: movement.direction,
            amount: Number(movement.gross_amount || 0),
            currency: movement.currency,
            providerId: movement.provider_id || undefined,
            description: movement.description || 'External settlement',
            sourceWalletId: movement.source_wallet_id || undefined,
            targetWalletId: movement.target_wallet_id || undefined,
            sourceInstitutionalAccountId: movement.institutional_source_account_id || undefined,
            targetInstitutionalAccountId: movement.institutional_target_account_id || undefined,
            externalReference: movement.external_reference || undefined,
            sourceExternalRef: movement.source_external_ref || undefined,
            targetExternalRef: movement.target_external_ref || undefined,
            feeAmount: Number(movement.fee_amount || 0),
            taxAmount: Number(movement.tax_amount || 0),
            metadata: {
                ...(movement.metadata || {}),
                webhook_status: status,
                webhook_message: message || null,
                provider_event_id: providerEventId || null,
                last_webhook_payload: rawPayload || null,
            },
        });

        return this.commitMovementRecord({
            movementId: movement.id,
            userId: movement.user_id,
            preview,
            existingMovement: movement,
            createdAt: movement.created_at || new Date().toISOString(),
        });
    }

    async handleWebhookDepositIntent(
        providerId: string,
        reference: string,
        status: 'completed' | 'failed' | 'processing' | 'pending',
        message?: string,
        providerEventId?: string,
        rawPayload?: any,
    ) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');
        if (!reference) throw new Error('WEBHOOK_REFERENCE_MISSING');

        const { data: movement, error } = await sb
            .from('external_fund_movements')
            .select('*')
            .eq('provider_id', providerId)
            .or(`external_reference.eq.${reference},source_external_ref.eq.${reference},target_external_ref.eq.${reference}`)
            .eq('direction', 'EXTERNAL_TO_INTERNAL')
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

        if (error) throw new Error(error.message);
        if (!movement) {
            throw new Error(`DEPOSIT_INTENT_NOT_FOUND:${reference}`);
        }

        if (movement.transaction_id || movement.status === 'completed') {
            return {
                movement,
                transactionId: movement.transaction_id,
                alreadyProcessed: true,
            };
        }

        if (status === 'processing' || status === 'pending') {
            const { data: updated, error: updateError } = await sb
                .from('external_fund_movements')
                .update({
                    status: 'processing',
                    updated_at: new Date().toISOString(),
                    metadata: {
                        ...(movement.metadata || {}),
                        webhook_status: status,
                        webhook_message: message || null,
                        provider_event_id: providerEventId || null,
                        last_webhook_payload: rawPayload || null,
                    },
                })
                .eq('id', movement.id)
                .select('*')
                .single();
            if (updateError) throw new Error(updateError.message);
            return { movement: updated, processing: true };
        }

        if (status === 'failed') {
            const { data: updated, error: updateError } = await sb
                .from('external_fund_movements')
                .update({
                    status: 'failed',
                    updated_at: new Date().toISOString(),
                    metadata: {
                        ...(movement.metadata || {}),
                        webhook_status: status,
                        webhook_message: message || null,
                        provider_event_id: providerEventId || null,
                        last_webhook_payload: rawPayload || null,
                    },
                })
                .eq('id', movement.id)
                .select('*')
                .single();
            if (updateError) throw new Error(updateError.message);
            return { movement: updated, failed: true };
        }

        const preview = await this.buildMovementContext(movement.user_id, {
            direction: 'EXTERNAL_TO_INTERNAL',
            amount: Number(movement.gross_amount || 0),
            currency: movement.currency,
            providerId: movement.provider_id || undefined,
            description: movement.description || 'External deposit settlement',
            targetWalletId: movement.target_wallet_id || undefined,
            sourceInstitutionalAccountId: movement.institutional_source_account_id || undefined,
            externalReference: movement.external_reference || undefined,
            sourceExternalRef: movement.source_external_ref || undefined,
            targetExternalRef: movement.target_external_ref || undefined,
            feeAmount: Number(movement.fee_amount || 0),
            taxAmount: Number(movement.tax_amount || 0),
            metadata: {
                ...(movement.metadata || {}),
                webhook_status: status,
                webhook_message: message || null,
                provider_event_id: providerEventId || null,
                last_webhook_payload: rawPayload || null,
            },
        });

        return this.commitMovementRecord({
            movementId: movement.id,
            userId: movement.user_id,
            preview,
            existingMovement: movement,
            createdAt: movement.created_at || new Date().toISOString(),
        });
    }

    async listMovements(userId: string, limit: number = 50, offset: number = 0) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const { data, error } = await sb
            .from('external_fund_movements')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .range(offset, offset + limit - 1);

        if (error) throw new Error(error.message);
        return data || [];
    }

    async getMovementById(userId: string, movementId: string) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const { data, error } = await sb
            .from('external_fund_movements')
            .select('*')
            .eq('id', movementId)
            .eq('user_id', userId)
            .maybeSingle();

        if (error) throw new Error(error.message);
        return data;
    }

    private async commitMovementRecord(args: {
        movementId: string;
        userId: string;
        preview: MovementContext;
        existingMovement: any | null;
        createdAt: string;
    }) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const txId = UUID.generate();
        const referenceId = `EXT-${UUID.generateShortCode(12)}`;
        const now = new Date().toISOString();
        const { movementId, userId, preview, existingMovement, createdAt } = args;
        if (preview.direction === 'EXTERNAL_TO_EXTERNAL') {
            throw new Error('EXTERNAL_TO_EXTERNAL_NO_LEDGER');
        }
        const ledgerEntries = this.buildLedgerEntries(preview, txId);
        const transactionType = preview.direction === 'INTERNAL_TO_EXTERNAL' ? 'withdrawal' : 'deposit';

        await this.ledger.postTransactionWithLedger(
            {
                id: txId,
                referenceId,
                user_id: userId,
                walletId: preview.sourceWalletId || preview.sourceInstitutionalAccount?.id || null,
                toWalletId: preview.targetWalletId || preview.targetInstitutionalAccount?.id || null,
                amount: preview.grossAmount,
                currency: preview.currency,
                description: preview.description,
                type: transactionType,
                status: 'completed',
                createdAt: now,
                metadata: {
                    ...preview.metadata,
                    settlement_path: 'EXTERNAL_ROUTING',
                    external_fund_direction: preview.direction,
                    provider_id: preview.providerId || null,
                    external_reference: preview.externalReference || null,
                    source_external_ref: preview.sourceExternalRef || null,
                    target_external_ref: preview.targetExternalRef || null,
                    institutional_source_account_id: preview.sourceInstitutionalAccount?.id || null,
                    institutional_target_account_id: preview.targetInstitutionalAccount?.id || null,
                    fee_amount: preview.feeAmount,
                    tax_amount: preview.taxAmount,
                },
            },
            ledgerEntries,
        );

        const payload = {
            user_id: userId,
            direction: preview.direction,
            status: 'completed' as ExternalFundMovementStatus,
            provider_id: preview.providerId || null,
            institutional_source_account_id: preview.sourceInstitutionalAccount?.id || null,
            institutional_target_account_id: preview.targetInstitutionalAccount?.id || null,
            transaction_id: txId,
            source_wallet_id: preview.sourceWalletId || null,
            target_wallet_id: preview.targetWalletId || null,
            gross_amount: preview.grossAmount,
            net_amount: preview.netAmount,
            fee_amount: preview.feeAmount,
            tax_amount: preview.taxAmount,
            currency: preview.currency,
            description: preview.description,
            external_reference: preview.externalReference || null,
            source_external_ref: preview.sourceExternalRef || null,
            target_external_ref: preview.targetExternalRef || null,
            metadata: {
                ...preview.metadata,
                settlement_model: 'DOUBLE_ENTRY_WITH_INSTITUTIONAL_ACCOUNTS',
                ledger_transaction_id: txId,
                double_entry_posted: true,
            },
            updated_at: now,
        };

        const query = existingMovement
            ? sb
                .from('external_fund_movements')
                .update(payload)
                .eq('id', movementId)
                .select('*')
                .single()
            : sb
                .from('external_fund_movements')
                .insert({
                    id: movementId,
                    ...payload,
                    created_at: createdAt,
                })
                .select('*')
                .single();

        const { data: movement, error } = await query;
        if (error) throw new Error(error.message);

        await Audit.log('FINANCIAL', userId, 'EXTERNAL_FUND_MOVEMENT_SETTLED', {
            movementId,
            transactionId: txId,
            direction: preview.direction,
            grossAmount: preview.grossAmount,
            netAmount: preview.netAmount,
            currency: preview.currency,
        });

        const settled = {
            movement,
            transactionId: txId,
            referenceId,
            ledgerPosted: true,
        };

        const triggerType = preview.direction === 'EXTERNAL_TO_INTERNAL' ? 'EXTERNAL_DEPOSIT' : null;
        if (triggerType && preview.targetWalletId) {
            try {
                await this.goals.runAutoAllocationsForCredit({
                    userId,
                    sourceTransactionId: txId,
                    sourceReferenceId: referenceId,
                    sourceWalletId: preview.targetWalletId,
                    sourceAmount: preview.netAmount,
                    currency: preview.currency,
                    triggerType,
                    metadata: {
                        source: 'institutional_funds',
                        movement_id: movementId,
                        provider_id: preview.providerId || null,
                    },
                });
            } catch (autoAllocationError: any) {
                console.error('[GoalAutoAllocation] Institutional settlement trigger failed:', autoAllocationError?.message || autoAllocationError);
            }
        }

        return settled;
    }

    private async buildMovementContext(userId: string, payload: ExternalFundMovementPayload) {
        const normalized = await this.normalizePayload(payload);
        normalized.providerId = normalized.providerId || await this.resolveProviderId(normalized);
        const internalFlow = normalized.direction !== 'EXTERNAL_TO_EXTERNAL';
        const sourceInternalWallet = normalized.direction === 'INTERNAL_TO_EXTERNAL'
            ? await this.resolveOperatingAndPaySafeWallets(userId, normalized.sourceWalletId)
            : null;
        const targetInternalWallet = normalized.direction === 'EXTERNAL_TO_INTERNAL'
            ? await this.resolveOperatingAndPaySafeWallets(userId, normalized.targetWalletId)
            : null;
        const sourceWalletId = sourceInternalWallet?.operatingWalletId || normalized.sourceWalletId;
        const targetWalletId = targetInternalWallet?.operatingWalletId || normalized.targetWalletId;

        if (normalized.direction === 'INTERNAL_TO_EXTERNAL' && !sourceWalletId) {
            throw new Error('OPERATING_WALLET_REQUIRED');
        }
        if (normalized.direction === 'EXTERNAL_TO_INTERNAL' && !targetWalletId) {
            throw new Error('OPERATING_WALLET_REQUIRED');
        }

        const sourceInstitutionalAccount = normalized.direction === 'EXTERNAL_TO_INTERNAL' || normalized.direction === 'EXTERNAL_TO_EXTERNAL'
            ? await this.resolveInstitutionalAccount({
                id: normalized.sourceInstitutionalAccountId,
                role: 'MAIN_COLLECTION',
                currency: normalized.currency,
                providerId: normalized.providerId,
            }, normalized.direction !== 'EXTERNAL_TO_EXTERNAL')
            : undefined;

        const targetInstitutionalAccount = normalized.direction === 'INTERNAL_TO_EXTERNAL' || normalized.direction === 'EXTERNAL_TO_EXTERNAL'
            ? await this.resolveInstitutionalAccount({
                id: normalized.targetInstitutionalAccountId,
                role: 'TRANSFER_SAVINGS',
                currency: normalized.currency,
                providerId: normalized.providerId,
            }, normalized.direction !== 'EXTERNAL_TO_EXTERNAL')
            : undefined;

        const feeAccount = normalized.feeAmount > 0
            ? await this.resolveInstitutionalAccount({
                role: 'FEE_COLLECTION',
                currency: normalized.currency,
                providerId: normalized.providerId,
            })
            : undefined;

        const taxAccount = normalized.taxAmount > 0
            ? await this.resolveInstitutionalAccount({
                role: 'TAX_COLLECTION',
                currency: normalized.currency,
                providerId: normalized.providerId,
            })
            : undefined;

        return {
            userId,
            ...normalized,
            sourceWalletId,
            targetWalletId,
            sourceInstitutionalAccount,
            targetInstitutionalAccount,
            feeAccount,
            taxAccount,
            sourceInternalWallet,
            targetInternalWallet,
            internalFlow,
        };
    }

    private async resolveProviderId(normalized: NormalizedMovement): Promise<string | undefined> {
        if (normalized.providerId) return normalized.providerId;
        if (!normalized.rail) return undefined;

        const defaultOperation: MoneyOperation =
            normalized.direction === 'INTERNAL_TO_EXTERNAL'
                ? 'DISBURSEMENT_REQUEST'
                : 'COLLECTION_REQUEST';

        const resolved = await providerRoutingService.resolveProvider({
            rail: normalized.rail,
            operation: normalized.operation || defaultOperation,
            countryCode: normalized.countryCode,
            currency: normalized.currency,
            preferredProviderCode: normalized.preferredProviderCode,
        });

        return resolved.providerId;
    }

    private async normalizePayload(payload: ExternalFundMovementPayload): Promise<NormalizedMovement> {
        const direction = String(payload.direction || '').trim().toUpperCase() as ExternalFundMovementDirection;
        if (!['INTERNAL_TO_EXTERNAL', 'EXTERNAL_TO_INTERNAL', 'EXTERNAL_TO_EXTERNAL'].includes(direction)) {
            throw new Error('INVALID_EXTERNAL_FUND_DIRECTION');
        }

        const amount = this.requirePositiveAmount(payload.amount, 'AMOUNT_REQUIRED');
        const currency = String(payload.currency || 'TZS').trim().toUpperCase();
        const description = String(payload.description || 'External fund movement').trim();
        const metadata = payload.metadata || {};
        const feeOverrideProvided = payload.feeAmount !== undefined && payload.feeAmount !== null;
        const taxOverrideProvided = payload.taxAmount !== undefined && payload.taxAmount !== null;

        const normalizedTransactionType = String(payload.transactionType ?? payload.transaction_type ?? '').trim().toUpperCase() || undefined;
        const normalizedProviderInput = String(payload.providerInput ?? payload.provider_input ?? '').trim() || undefined;
        const normalizedCounterpartyType = String(payload.counterpartyType ?? payload.counterparty_type ?? '').trim().toUpperCase() || undefined;

        const resolvedFee = await platformFeeService.resolveFee({
            flowCode: direction,
            amount,
            currency,
            providerId: payload.providerId,
            countryCode: payload.countryCode,
            rail: payload.rail,
            direction,
            operationType: payload.operation,
            transactionType: normalizedTransactionType,
            metadata,
        });

        const feeAmount = feeOverrideProvided ? this.parseAmount(payload.feeAmount) : resolvedFee.serviceFee;
        const taxAmount = taxOverrideProvided ? this.parseAmount(payload.taxAmount) : resolvedFee.taxAmount + resolvedFee.govFeeAmount + resolvedFee.stampDutyFixed;

        let grossAmount = amount;
        let netAmount = amount;

        if (direction === 'INTERNAL_TO_EXTERNAL') {
            grossAmount = this.roundAmount(amount + feeAmount + taxAmount);
            netAmount = amount;
        } else {
            grossAmount = amount;
            netAmount = this.roundAmount(amount - feeAmount - taxAmount);
        }

        if (netAmount < 0) {
            throw new Error('INVALID_NET_AMOUNT');
        }

        return {
            direction,
            amount,
            grossAmount,
            netAmount,
            feeAmount,
            taxAmount,
            currency,
            providerId: payload.providerId,
            rail: payload.rail,
            countryCode: payload.countryCode,
            operation: payload.operation,
            preferredProviderCode: payload.preferredProviderCode,
            transactionType: normalizedTransactionType,
            providerInput: normalizedProviderInput,
            counterpartyType: normalizedCounterpartyType,
            description,
            sourceWalletId: payload.sourceWalletId,
            targetWalletId: payload.targetWalletId,
            sourceInstitutionalAccountId: payload.sourceInstitutionalAccountId,
            targetInstitutionalAccountId: payload.targetInstitutionalAccountId,
            externalReference: payload.externalReference,
            sourceExternalRef: payload.sourceExternalRef,
            targetExternalRef: payload.targetExternalRef,
            metadata: {
                ...metadata,
                fee_config_id: resolvedFee.configId || null,
                fee_flow_code: resolvedFee.flowCode,
                transaction_type: normalizedTransactionType || metadata.transaction_type || null,
                provider_input: normalizedProviderInput || metadata.provider_input || null,
                counterparty_type: normalizedCounterpartyType || metadata.counterparty_type || null,
            },
        };
    }

    private async resolveInstitutionalAccount(
        lookup: InstitutionalAccountLookup,
        required: boolean = true,
    ) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        if (lookup.id) {
            const { data, error } = await sb
                .from('institutional_payment_accounts')
                .select('*')
                .eq('id', lookup.id)
                .eq('status', 'ACTIVE')
                .maybeSingle();

            if (error) throw new Error(error.message);
            if (data) return data;
        }

        let query = sb
            .from('institutional_payment_accounts')
            .select('*')
            .eq('role', lookup.role)
            .eq('currency', lookup.currency)
            .eq('status', 'ACTIVE')
            .order('is_primary', { ascending: false })
            .order('updated_at', { ascending: false })
            .limit(1);

        if (lookup.providerId) {
            const { data, error } = await query.eq('provider_id', lookup.providerId);
            if (error) throw new Error(error.message);
            if (data && data.length > 0) return data[0];
        }

        const fallbackQuery = lookup.providerId
            ? query.is('provider_id', null)
            : query;

        const { data: fallback, error: fallbackError } = await fallbackQuery;
        if (fallbackError) throw new Error(fallbackError.message);
        if (fallback && fallback.length > 0) return fallback[0];
        if (required) {
            throw new Error(`INSTITUTIONAL_ACCOUNT_NOT_CONFIGURED:${lookup.role}:${lookup.currency}`);
        }
        return null;
    }

    private buildLedgerEntries(preview: any, txId: string): LedgerEntry[] {
        const entries: LedgerEntry[] = [];
        const timestamp = new Date().toISOString();

        if (preview.direction === 'INTERNAL_TO_EXTERNAL') {
            if (!preview.sourceInternalWallet?.operatingWalletId || !preview.sourceInternalWallet?.paySafeWalletId) {
                throw new Error('PAYSafe_OPERATING_FLOW_REQUIRED');
            }
            entries.push({
                transactionId: txId,
                walletId: preview.sourceInternalWallet.operatingWalletId,
                type: 'DEBIT',
                amount: preview.grossAmount,
                currency: preview.currency,
                description: `${preview.description} - operating debit`,
                timestamp,
            });
            entries.push({
                transactionId: txId,
                walletId: preview.sourceInternalWallet.paySafeWalletId,
                type: 'CREDIT',
                amount: preview.amount,
                currency: preview.currency,
                description: `${preview.description} - PaySafe secure hold`,
                timestamp,
            });
            entries.push({
                transactionId: txId,
                walletId: preview.sourceInternalWallet.paySafeWalletId,
                type: 'DEBIT',
                amount: preview.amount,
                currency: preview.currency,
                description: `${preview.description} - PaySafe settlement release`,
                timestamp,
            });
            entries.push({
                transactionId: txId,
                walletId: preview.targetInstitutionalAccount.id,
                type: 'CREDIT',
                amount: preview.amount,
                currency: preview.currency,
                description: `${preview.description} - transfer savings`,
                timestamp,
            });
        } else if (preview.direction === 'EXTERNAL_TO_INTERNAL') {
            if (!preview.targetInternalWallet?.operatingWalletId || !preview.targetInternalWallet?.paySafeWalletId) {
                throw new Error('PAYSafe_OPERATING_FLOW_REQUIRED');
            }
            entries.push({
                transactionId: txId,
                walletId: preview.sourceInstitutionalAccount.id,
                type: 'DEBIT',
                amount: preview.grossAmount,
                currency: preview.currency,
                description: `${preview.description} - institutional collection debit`,
                timestamp,
            });
            entries.push({
                transactionId: txId,
                walletId: preview.targetInternalWallet.paySafeWalletId,
                type: 'CREDIT',
                amount: preview.grossAmount,
                currency: preview.currency,
                description: `${preview.description} - PaySafe receipt`,
                timestamp,
            });
            entries.push({
                transactionId: txId,
                walletId: preview.targetInternalWallet.paySafeWalletId,
                type: 'DEBIT',
                amount: preview.netAmount,
                currency: preview.currency,
                description: `${preview.description} - PaySafe settlement release`,
                timestamp,
            });
            entries.push({
                transactionId: txId,
                walletId: preview.targetInternalWallet.operatingWalletId,
                type: 'CREDIT',
                amount: preview.netAmount,
                currency: preview.currency,
                description: `${preview.description} - operating credit`,
                timestamp,
            });
        }

        if (preview.feeAmount > 0 && preview.feeAccount?.id) {
            const feeDebitWalletId = preview.direction === 'EXTERNAL_TO_INTERNAL'
                ? preview.targetInternalWallet?.paySafeWalletId
                : null;
            if (feeDebitWalletId) {
                entries.push({
                    transactionId: txId,
                    walletId: feeDebitWalletId,
                    type: 'DEBIT',
                    amount: preview.feeAmount,
                    currency: preview.currency,
                    description: `${preview.description} - PaySafe fee release`,
                    timestamp,
                });
            }
            entries.push({
                transactionId: txId,
                walletId: preview.feeAccount.id,
                type: 'CREDIT',
                amount: preview.feeAmount,
                currency: preview.currency,
                description: `${preview.description} - fee collection`,
                timestamp,
            });
        }

        if (preview.taxAmount > 0 && preview.taxAccount?.id) {
            const taxDebitWalletId = preview.direction === 'EXTERNAL_TO_INTERNAL'
                ? preview.targetInternalWallet?.paySafeWalletId
                : null;
            if (taxDebitWalletId) {
                entries.push({
                    transactionId: txId,
                    walletId: taxDebitWalletId,
                    type: 'DEBIT',
                    amount: preview.taxAmount,
                    currency: preview.currency,
                    description: `${preview.description} - PaySafe tax release`,
                    timestamp,
                });
            }
            entries.push({
                transactionId: txId,
                walletId: preview.taxAccount.id,
                type: 'CREDIT',
                amount: preview.taxAmount,
                currency: preview.currency,
                description: `${preview.description} - tax collection`,
                timestamp,
            });
        }

        return entries;
    }

    private requirePositiveAmount(value: number, errorCode: string) {
        const amount = this.parseAmount(value);
        if (amount <= 0) throw new Error(errorCode);
        return amount;
    }

    private parseAmount(value: any) {
        const parsed = Number(value || 0);
        if (!Number.isFinite(parsed)) {
            throw new Error('INVALID_AMOUNT');
        }
        return this.roundAmount(parsed);
    }

    private roundAmount(value: number) {
        return Math.round(value * 100) / 100;
    }

    private async resolveOperatingAndPaySafeWallets(userId: string, providedWalletId?: string) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const { data: vaults, error } = await sb
            .from('platform_vaults')
            .select('id, user_id, vault_role, name')
            .eq('user_id', userId)
            .in('vault_role', ['OPERATING', 'INTERNAL_TRANSFER']);

        if (error) throw new Error(error.message);

        const operating = (vaults || []).find((vault: any) => vault.vault_role === 'OPERATING');
        const paySafe = (vaults || []).find((vault: any) => vault.vault_role === 'INTERNAL_TRANSFER');

        if (!operating) throw new Error('OPERATING_WALLET_REQUIRED');
        if (!paySafe) throw new Error('PAYSafe_WALLET_REQUIRED');

        if (providedWalletId && String(providedWalletId) !== String(operating.id)) {
            const { data: wallet } = await sb
                .from('wallets')
                .select('id, user_id, type, is_primary')
                .eq('id', providedWalletId)
                .maybeSingle();

            const isOperatingWallet = !!wallet &&
                String(wallet.user_id) === String(userId) &&
                (String(wallet.type || '').toLowerCase() === 'operating' || wallet.is_primary === true);

            if (!isOperatingWallet) {
                throw new Error('OPERATING_WALLET_REQUIRED: External settlement must use the ORBI operating wallet.');
            }
        }

        return {
            operatingWalletId: String(operating.id),
            paySafeWalletId: String(paySafe.id),
        };
    }
}

export const institutionalFundsService = new InstitutionalFundsService();
