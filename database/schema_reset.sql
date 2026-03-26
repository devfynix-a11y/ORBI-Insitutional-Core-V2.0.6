DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff' AND column_name='address') THEN
        ALTER TABLE public.staff ADD COLUMN address TEXT;
    END IF;
END $$;
-- ORBI SOVEREIGN MASTER ARCHITECTURE V93.0 (ULTIMATE CONSOLIDATED RESET)
-- WARNING: THIS SCRIPT WILL DROP AND RECREATE ALL TABLES

-- 1. CLEANUP PHASE (Drop all existing objects)
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS public.handle_new_user() CASCADE;
DROP FUNCTION IF EXISTS public.post_transaction_v2(UUID, UUID, UUID, UUID, TEXT, TEXT, TEXT, TEXT, DATE, JSONB, JSONB) CASCADE;
DROP FUNCTION IF EXISTS public.append_ledger_entries_v1(UUID, JSONB) CASCADE;
DROP FUNCTION IF EXISTS public.update_wallet_balance(UUID, NUMERIC, TEXT) CASCADE;
DROP FUNCTION IF EXISTS public.delete_old_activity() CASCADE;
DROP FUNCTION IF EXISTS public.get_auth_role() CASCADE;

DROP TABLE IF EXISTS public.fee_correction_logs CASCADE;
DROP TABLE IF EXISTS public.fee_correction_rules CASCADE;
DROP TABLE IF EXISTS public.user_documents CASCADE;
DROP TABLE IF EXISTS public.user_devices CASCADE;
DROP TABLE IF EXISTS public.user_sessions CASCADE;
DROP TABLE IF EXISTS public.kyc_requests CASCADE;
DROP TABLE IF EXISTS public.transfer_tax_rules CASCADE;
DROP TABLE IF EXISTS public.regulatory_config CASCADE;
DROP TABLE IF EXISTS public.digital_merchants CASCADE;
DROP TABLE IF EXISTS public.financial_partners CASCADE;
DROP TABLE IF EXISTS public.external_fund_movements CASCADE;
DROP TABLE IF EXISTS public.institutional_payment_accounts CASCADE;
DROP TABLE IF EXISTS public.provider_routing_rules CASCADE;
DROP TABLE IF EXISTS public.outbound_sms_messages CASCADE;
DROP TABLE IF EXISTS public.offline_transaction_sessions CASCADE;
DROP TABLE IF EXISTS public.inbound_sms_messages CASCADE;
DROP TABLE IF EXISTS public.provider_anomalies CASCADE;
DROP TABLE IF EXISTS public.kms_keys CASCADE;
DROP TABLE IF EXISTS public.audit_trail CASCADE;
DROP TABLE IF EXISTS public.audit_logs CASCADE;
DROP TABLE IF EXISTS public.staff_messages CASCADE;
DROP TABLE IF EXISTS public.user_messages CASCADE;
DROP TABLE IF EXISTS public.aml_alerts CASCADE;
DROP TABLE IF EXISTS public.tasks CASCADE;
DROP TABLE IF EXISTS public.categories CASCADE;
DROP TABLE IF EXISTS public.goals CASCADE;
DROP TABLE IF EXISTS public.financial_ledger CASCADE;
DROP TABLE IF EXISTS public.transaction_events CASCADE;
DROP TABLE IF EXISTS public.financial_events CASCADE;
DROP TABLE IF EXISTS public.transactions CASCADE;
DROP TABLE IF EXISTS public.platform_vaults CASCADE;
DROP TABLE IF EXISTS public.wallets CASCADE;
DROP TABLE IF EXISTS public.staff CASCADE;
DROP TABLE IF EXISTS public.users CASCADE;
DROP TABLE IF EXISTS public.secrets CASCADE;
DROP TABLE IF EXISTS public.wal_logs CASCADE;
DROP TABLE IF EXISTS public.organizations CASCADE;
DROP TABLE IF EXISTS public.fee_collector_wallets CASCADE;
DROP TABLE IF EXISTS public.budget_alerts CASCADE;

-- Shadow Tables Cleanup
DROP TABLE IF EXISTS public.escrow_agreements CASCADE;
DROP TABLE IF EXISTS public.treasury_policies CASCADE;
DROP TABLE IF EXISTS public.treasury_approvers CASCADE;
DROP TABLE IF EXISTS public.fee_collector_wallets CASCADE;
DROP TABLE IF EXISTS public.merchant_fees CASCADE;
DROP TABLE IF EXISTS public.platform_fee_configs CASCADE;
DROP TABLE IF EXISTS public.merchant_settlements CASCADE;
DROP TABLE IF EXISTS public.service_commissions CASCADE;
DROP TABLE IF EXISTS public.service_access_requests CASCADE;
DROP TABLE IF EXISTS public.service_actor_customer_links CASCADE;
DROP TABLE IF EXISTS public.agent_transactions CASCADE;
DROP TABLE IF EXISTS public.merchant_transactions CASCADE;
DROP TABLE IF EXISTS public.agent_wallets CASCADE;
DROP TABLE IF EXISTS public.agents CASCADE;
DROP TABLE IF EXISTS public.merchant_wallets CASCADE;
DROP TABLE IF EXISTS public.merchants CASCADE;
DROP TABLE IF EXISTS public.app_registry CASCADE;
DROP TABLE IF EXISTS public.platform_configs CASCADE;
DROP TABLE IF EXISTS public.infra_snapshots CASCADE;
DROP TABLE IF EXISTS public.infra_tx_limits CASCADE;
DROP TABLE IF EXISTS public.infra_app_tokens CASCADE;
DROP TABLE IF EXISTS public.infra_system_matrix CASCADE;
DROP TABLE IF EXISTS public.legal_holds CASCADE;
DROP TABLE IF EXISTS public.approval_requests CASCADE;
DROP TABLE IF EXISTS public.staff_issues CASCADE;
DROP TABLE IF EXISTS public.support_tickets CASCADE;
DROP TABLE IF EXISTS public.security_rules CASCADE;
DROP TABLE IF EXISTS public.rule_violations CASCADE;
DROP TABLE IF EXISTS public.ai_reports CASCADE;
DROP TABLE IF EXISTS public.reported_issues CASCADE;
DROP TABLE IF EXISTS public.system_catalog CASCADE;
DROP TABLE IF EXISTS public.ctr_reports CASCADE;
DROP TABLE IF EXISTS public.transaction_status_logs CASCADE;
DROP TABLE IF EXISTS public.payment_metrics_snapshots CASCADE;
DROP TABLE IF EXISTS public.payment_reviews CASCADE;
DROP TABLE IF EXISTS public.chargeback_cases CASCADE;
DROP TABLE IF EXISTS public.system_nodes CASCADE;
DROP TABLE IF EXISTS public.organizations CASCADE;
DROP TABLE IF EXISTS public.budget_alerts CASCADE;
DROP TABLE IF EXISTS public.reconciliation_reports CASCADE;
DROP TABLE IF EXISTS public.item_reconciliation_audit CASCADE;
DROP TABLE IF EXISTS public.passkeys CASCADE;
DROP TABLE IF EXISTS public.device_fingerprints CASCADE;
DROP TABLE IF EXISTS public.behavioral_biometrics CASCADE;
DROP TABLE IF EXISTS public.ai_risk_logs CASCADE;
DROP TABLE IF EXISTS public.secure_enclave_keys CASCADE;

-- 2. CORE EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 3. TABLES DEFINITION

CREATE TABLE public.secrets (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.wal_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data TEXT NOT NULL,
    status TEXT DEFAULT 'PENDING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action TEXT NOT NULL,
    meta JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);


-- Identity & Staff
CREATE TABLE public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT,
    email TEXT UNIQUE NOT NULL,
    customer_id TEXT UNIQUE NOT NULL, 
    phone TEXT,
    nationality TEXT DEFAULT 'Tanzania',
    address TEXT,
    avatar_url TEXT,
    currency TEXT DEFAULT 'TZS',
    account_status TEXT DEFAULT 'active',
    registry_type TEXT DEFAULT 'CONSUMER',
    role TEXT DEFAULT 'USER',
    language TEXT DEFAULT 'en',
    app_origin TEXT DEFAULT 'OBI_INSTITUTIONAL_CORE_V25',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    kyc_level INTEGER DEFAULT 0,
    kyc_status TEXT DEFAULT 'unverified',
    id_type TEXT,
    id_number TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE public.staff (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER',
    account_status TEXT DEFAULT 'pending',
    customer_id TEXT UNIQUE NOT NULL,
    phone TEXT,
    avatar_url TEXT,
    nationality TEXT DEFAULT 'Tanzania',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Wealth Domain
CREATE TABLE public.wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    name TEXT NOT NULL, 
    balance NUMERIC DEFAULT 0, 
    currency TEXT DEFAULT 'TZS', 
    color TEXT, 
    icon TEXT, 
    management_tier TEXT DEFAULT 'linked', 
    type TEXT DEFAULT 'operating', 
    is_primary BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'active',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.platform_vaults (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    vault_role TEXT, 
    name TEXT,
    balance NUMERIC DEFAULT 0, 
    encrypted_balance TEXT, 
    currency TEXT DEFAULT 'TZS', 
    color TEXT, 
    icon TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reference_id TEXT UNIQUE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    wallet_id UUID,
    to_wallet_id UUID,
    amount TEXT NOT NULL,
    currency TEXT DEFAULT 'TZS',
    description TEXT NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('created', 'pending', 'authorized', 'processing', 'settled', 'completed', 'failed', 'cancelled', 'held_for_review', 'reversed', 'refunded')),
    status_notes TEXT,
    date DATE DEFAULT CURRENT_DATE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.financial_ledger (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    wallet_id UUID,
    entry_type TEXT NOT NULL,
    amount TEXT NOT NULL,
    balance_after TEXT NOT NULL,
    balance_after_encrypted TEXT,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.transaction_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    old_state TEXT,
    new_state TEXT NOT NULL,
    actor TEXT DEFAULT 'system',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.financial_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    aggregate_id UUID NOT NULL,
    payload JSONB NOT NULL,
    actor TEXT DEFAULT 'system',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_financial_events_aggregate ON public.financial_events(aggregate_id);
CREATE INDEX idx_financial_events_type ON public.financial_events(event_type);

CREATE TABLE public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    registration_number TEXT,
    tax_id TEXT,
    country TEXT,
    base_currency TEXT DEFAULT 'USD',
    status TEXT DEFAULT 'ACTIVE',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.escrow_agreements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID NOT NULL REFERENCES public.transactions(id) ON DELETE CASCADE,
    sender_id UUID NOT NULL REFERENCES auth.users(id),
    receiver_id UUID NOT NULL REFERENCES auth.users(id),
    amount NUMERIC NOT NULL,
    currency TEXT NOT NULL,
    conditions JSONB DEFAULT '{}'::jsonb,
    status TEXT DEFAULT 'HELD' CHECK (status IN ('HELD', 'RELEASED', 'DISPUTED', 'REFUNDED')),
    dispute_metadata JSONB DEFAULT '{}'::jsonb,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.treasury_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    min_approvals INTEGER DEFAULT 1,
    max_amount_per_tx NUMERIC,
    daily_limit NUMERIC,
    currency TEXT DEFAULT 'USD',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.treasury_approvers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'APPROVER',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

CREATE TABLE public.fee_collector_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fee_type TEXT NOT NULL UNIQUE,
    vault_id UUID REFERENCES public.platform_vaults(id) ON DELETE CASCADE,
    external_bank_account_id TEXT,
    balance NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Strategy Domain
CREATE TABLE public.goals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    name TEXT NOT NULL, 
    target NUMERIC NOT NULL, 
    current NUMERIC DEFAULT 0, 
    deadline TIMESTAMP WITH TIME ZONE, 
    color TEXT, 
    icon TEXT, 
    funding_strategy TEXT DEFAULT 'manual', 
    auto_allocation_enabled BOOLEAN DEFAULT FALSE, 
    linked_income_percentage NUMERIC,
    monthly_target NUMERIC,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    name TEXT NOT NULL, 
    budget TEXT, 
    color TEXT, 
    icon TEXT, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.budget_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id UUID REFERENCES public.categories(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE,
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    amount NUMERIC NOT NULL,
    alert_type TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    text TEXT NOT NULL, 
    completed BOOLEAN DEFAULT FALSE, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    due_date TIMESTAMP WITH TIME ZONE,
    linked_goal_id UUID REFERENCES public.goals(id) ON DELETE SET NULL,
    bounty NUMERIC DEFAULT 0
);

-- Communications
CREATE TABLE public.aml_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    risk_score NUMERIC NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.user_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    subject TEXT NOT NULL, 
    body TEXT NOT NULL, 
    category TEXT NOT NULL, 
    is_read BOOLEAN DEFAULT FALSE, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.staff_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    sender_id UUID REFERENCES auth.users(id) ON DELETE CASCADE, 
    recipient_id UUID REFERENCES auth.users(id) ON DELETE CASCADE, 
    sender_name TEXT, 
    content TEXT NOT NULL, 
    type TEXT DEFAULT 'staff', 
    is_flagged BOOLEAN DEFAULT FALSE, 
    target_role TEXT, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit & Security
CREATE TABLE public.kms_keys (
    key_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    wrapped_jwk TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.audit_trail (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    prev_hash TEXT, 
    hash TEXT NOT NULL, 
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(), 
    event_type TEXT NOT NULL, 
    actor_id TEXT, 
    transaction_id TEXT, 
    action TEXT NOT NULL, 
    metadata JSONB, 
    signature TEXT
);

CREATE TABLE public.provider_anomalies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE, 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    wallet_id UUID, 
    risk_score NUMERIC NOT NULL, 
    detection_flags TEXT[] NOT NULL, 
    status TEXT DEFAULT 'OPEN', 
    resolution_notes TEXT, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Infrastructure & Config
CREATE TABLE public.financial_partners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    name VARCHAR(50) NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (LOWER(type) IN ('mobile_money', 'bank', 'card', 'crypto')),
    icon TEXT,
    color TEXT,
    connection_secret VARCHAR(255),
    client_id TEXT,
    client_secret TEXT,
    api_base_url TEXT,
    webhook_secret TEXT,
    token_cache TEXT,
    token_expiry BIGINT,
    provider_metadata JSONB DEFAULT '{}'::jsonb,
    mapping_config JSONB DEFAULT '{}'::jsonb,
    logic_type TEXT DEFAULT 'REGISTRY',
    status VARCHAR(20) DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.institutional_payment_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role TEXT NOT NULL CHECK (role IN ('MAIN_COLLECTION', 'FEE_COLLECTION', 'TAX_COLLECTION', 'TRANSFER_SAVINGS')),
    provider_id UUID REFERENCES public.financial_partners(id) ON DELETE SET NULL,
    bank_name TEXT NOT NULL,
    account_name TEXT NOT NULL,
    account_number TEXT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'TZS',
    country_code TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
    is_primary BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.external_fund_movements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK (direction IN ('INTERNAL_TO_EXTERNAL', 'EXTERNAL_TO_INTERNAL', 'EXTERNAL_TO_EXTERNAL')),
    status TEXT NOT NULL DEFAULT 'initiated' CHECK (status IN ('previewed', 'initiated', 'processing', 'completed', 'failed', 'recorded', 'reversed')),
    provider_id UUID REFERENCES public.financial_partners(id) ON DELETE SET NULL,
    institutional_source_account_id UUID REFERENCES public.institutional_payment_accounts(id) ON DELETE SET NULL,
    institutional_target_account_id UUID REFERENCES public.institutional_payment_accounts(id) ON DELETE SET NULL,
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    source_wallet_id UUID,
    target_wallet_id UUID,
    gross_amount NUMERIC NOT NULL DEFAULT 0,
    net_amount NUMERIC NOT NULL DEFAULT 0,
    fee_amount NUMERIC NOT NULL DEFAULT 0,
    tax_amount NUMERIC NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'TZS',
    description TEXT,
    external_reference TEXT,
    source_external_ref TEXT,
    target_external_ref TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.provider_routing_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rail TEXT NOT NULL CHECK (rail IN ('MOBILE_MONEY', 'BANK', 'CARD_GATEWAY', 'CRYPTO', 'WALLET')),
    country_code TEXT,
    currency TEXT,
    operation_code TEXT NOT NULL,
    provider_id UUID NOT NULL REFERENCES public.financial_partners(id) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 100,
    conditions JSONB DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.inbound_sms_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    raw_message TEXT NOT NULL,
    normalized_message TEXT,
    message_type TEXT,
    request_id TEXT,
    carrier_ref TEXT,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL,
    parse_status TEXT,
    signature_status TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.offline_transaction_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id TEXT NOT NULL UNIQUE,
    tenant_id UUID,
    phone_number TEXT NOT NULL,
    user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    device_id TEXT,
    action TEXT NOT NULL,
    amount NUMERIC(20, 2),
    currency TEXT,
    source_wallet_id TEXT,
    budget_id TEXT,
    recipient_ref TEXT,
    status TEXT NOT NULL CHECK (status IN ('RECEIVED', 'PARSED', 'VALIDATED', 'PENDING_CONFIRMATION', 'FORWARDED_TO_ORBI', 'CHALLENGE_SENT', 'CONFIRMED', 'SUCCESS', 'FAILED', 'EXPIRED', 'REJECTED')),
    challenge_code TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    confirmed_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    failure_reason TEXT,
    correlation_id TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.outbound_sms_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id TEXT,
    phone_number TEXT NOT NULL,
    message_body TEXT NOT NULL,
    message_type TEXT,
    send_status TEXT,
    gateway_ref TEXT,
    sent_at TIMESTAMP WITH TIME ZONE,
    delivered_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.digital_merchants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    name TEXT NOT NULL,
    category TEXT,
    status TEXT DEFAULT 'ACTIVE',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Multi-Tenant Merchant Architecture
CREATE TABLE public.merchants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    business_name TEXT NOT NULL,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'pending', -- pending, active, suspended, closed
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.merchant_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    base_wallet_id UUID,
    name TEXT NOT NULL,
    wallet_type TEXT DEFAULT 'operating',
    is_primary BOOLEAN DEFAULT FALSE,
    balance NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'active',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.merchant_settlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE UNIQUE,
    bank_name TEXT NOT NULL,
    bank_account TEXT NOT NULL,
    settlement_schedule TEXT DEFAULT 'daily',
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.merchant_fees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE UNIQUE,
    transaction_fee_percent NUMERIC DEFAULT 0.01,
    fixed_fee NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_merchants_owner_reset ON public.merchants(owner_user_id);
CREATE INDEX idx_merchant_wallets_merchant_reset ON public.merchant_wallets(merchant_id);
CREATE INDEX idx_merchant_wallets_owner_user_reset ON public.merchant_wallets(owner_user_id);

CREATE TABLE public.agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    commission_enabled BOOLEAN DEFAULT TRUE,
    service_pay_number TEXT UNIQUE,
    cash_withdraw_till TEXT UNIQUE,
    service_wallet_id UUID,
    commission_wallet_id UUID,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.platform_fee_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    flow_code TEXT NOT NULL,
    transaction_type TEXT,
    operation_type TEXT,
    direction TEXT,
    rail TEXT,
    channel TEXT,
    provider_id UUID REFERENCES public.financial_partners(id) ON DELETE CASCADE,
    currency TEXT,
    country_code TEXT,
    percentage_rate NUMERIC NOT NULL DEFAULT 0,
    fixed_amount NUMERIC NOT NULL DEFAULT 0,
    minimum_fee NUMERIC NOT NULL DEFAULT 0,
    maximum_fee NUMERIC,
    tax_rate NUMERIC NOT NULL DEFAULT 0,
    gov_fee_rate NUMERIC NOT NULL DEFAULT 0,
    stamp_duty_fixed NUMERIC NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 100,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.agent_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES public.agents(id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    base_wallet_id UUID,
    name TEXT NOT NULL,
    wallet_type TEXT DEFAULT 'operating',
    is_primary BOOLEAN DEFAULT FALSE,
    balance NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'active',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.merchant_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID UNIQUE REFERENCES public.transactions(id) ON DELETE CASCADE,
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    merchant_wallet_id UUID REFERENCES public.merchant_wallets(id) ON DELETE SET NULL,
    customer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    direction TEXT DEFAULT 'inbound',
    amount NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'pending',
    service_type TEXT DEFAULT 'merchant_payment',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.agent_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID UNIQUE REFERENCES public.transactions(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES public.agents(id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    agent_wallet_id UUID REFERENCES public.agent_wallets(id) ON DELETE SET NULL,
    customer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    direction TEXT DEFAULT 'inbound',
    amount NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'pending',
    service_type TEXT DEFAULT 'agent_cash',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.service_actor_customer_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    actor_role TEXT NOT NULL,
    actor_registry_type TEXT,
    customer_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    customer_customer_id TEXT,
    relationship_type TEXT DEFAULT 'sponsored_registration',
    status TEXT DEFAULT 'active',
    commission_enabled BOOLEAN DEFAULT TRUE,
    commission_started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    commission_expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.service_commissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    actor_role TEXT NOT NULL,
    customer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    source_transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    payout_transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    commission_type TEXT NOT NULL,
    amount NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    rate NUMERIC DEFAULT 0,
    fixed_amount NUMERIC DEFAULT 0,
    status TEXT DEFAULT 'pending',
    effective_from TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    effective_until TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.service_access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    requested_role TEXT NOT NULL,
    requested_registry_type TEXT NOT NULL,
    current_user_role TEXT,
    current_user_registry_type TEXT,
    status TEXT DEFAULT 'pending',
    business_name TEXT,
    phone TEXT,
    submitted_via TEXT DEFAULT 'mobile_app',
    note TEXT,
    review_note TEXT,
    reviewed_by UUID REFERENCES public.staff(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    approved_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_service_actor_customer_unique_reset
    ON public.service_actor_customer_links(actor_user_id, customer_user_id);
CREATE INDEX idx_agents_user_reset ON public.agents(user_id);
CREATE INDEX idx_agent_wallets_agent_reset ON public.agent_wallets(agent_id);
CREATE INDEX idx_agent_wallets_owner_user_reset ON public.agent_wallets(owner_user_id);
CREATE UNIQUE INDEX idx_agents_service_pay_number_reset ON public.agents(service_pay_number) WHERE service_pay_number IS NOT NULL;
CREATE UNIQUE INDEX idx_agents_cash_withdraw_till_reset ON public.agents(cash_withdraw_till) WHERE cash_withdraw_till IS NOT NULL;
CREATE INDEX idx_merchant_transactions_owner_reset ON public.merchant_transactions(owner_user_id);
CREATE INDEX idx_merchant_transactions_customer_reset ON public.merchant_transactions(customer_user_id);
CREATE INDEX idx_agent_transactions_owner_reset ON public.agent_transactions(owner_user_id);
CREATE INDEX idx_agent_transactions_customer_reset ON public.agent_transactions(customer_user_id);
CREATE INDEX idx_service_links_actor_reset ON public.service_actor_customer_links(actor_user_id);
CREATE INDEX idx_service_links_customer_reset ON public.service_actor_customer_links(customer_user_id);
CREATE INDEX idx_service_commissions_actor_reset ON public.service_commissions(actor_user_id);
CREATE INDEX idx_service_commissions_source_tx_reset ON public.service_commissions(source_transaction_id);
CREATE INDEX idx_service_access_requests_user_reset ON public.service_access_requests(user_id);
CREATE INDEX idx_service_access_requests_status_reset ON public.service_access_requests(status);
CREATE INDEX idx_service_access_requests_role_reset ON public.service_access_requests(requested_role);

CREATE TABLE public.regulatory_config (
    id TEXT PRIMARY KEY, 
    vat_rate NUMERIC DEFAULT 0.05, 
    service_fee_rate NUMERIC DEFAULT 0.01, 
    gov_fee_rate NUMERIC DEFAULT 0.005, 
    stamp_duty_fixed NUMERIC DEFAULT 1.0, 
    is_active BOOLEAN DEFAULT TRUE, 
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), 
    updated_by TEXT
);

CREATE TABLE public.transfer_tax_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    rate NUMERIC NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Identity & Compliance
CREATE TABLE public.kyc_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    id_type TEXT NOT NULL CHECK (id_type IN ('NATIONAL_ID', 'DRIVER_LICENSE', 'VOTER_ID', 'PASSPORT')),
    id_number TEXT NOT NULL,
    document_url TEXT NOT NULL,
    selfie_url TEXT NOT NULL,
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    submitted_at TIMESTAMPTZ DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    reviewer_id UUID,
    rejection_reason TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE public.user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL,
    device_fingerprint TEXT,
    ip_address TEXT,
    user_agent TEXT,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_active_at TIMESTAMPTZ DEFAULT NOW(),
    replaced_by TEXT,
    is_trusted_device BOOLEAN DEFAULT FALSE
);

CREATE TABLE public.user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    device_fingerprint TEXT NOT NULL,
    device_name TEXT,
    device_type TEXT,
    user_agent TEXT,
    last_active_at TIMESTAMPTZ DEFAULT NOW(),
    is_trusted BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, device_fingerprint)
);

CREATE TABLE public.user_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    document_type TEXT NOT NULL,
    file_url TEXT NOT NULL,
    file_name TEXT,
    mime_type TEXT,
    size_bytes BIGINT,
    status TEXT DEFAULT 'pending',
    uploaded_at TIMESTAMPTZ DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    verified_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    rejection_reason TEXT,
    metadata JSONB DEFAULT '{}'
);

-- Shadow Tables
CREATE TABLE public.system_nodes (node_type TEXT PRIMARY KEY, vault_id UUID NOT NULL, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.chargeback_cases (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.payment_reviews (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.payment_metrics_snapshots (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.transaction_status_logs (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.ctr_reports (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.system_catalog (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.reported_issues (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.ai_reports (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.rule_violations (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.security_rules (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.support_tickets (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.staff_issues (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.approval_requests (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), type TEXT NOT NULL, target_id UUID NOT NULL, requester_id UUID REFERENCES auth.users(id) ON DELETE CASCADE, status TEXT DEFAULT 'PENDING', metadata JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.legal_holds (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), target_type TEXT NOT NULL, target_id UUID NOT NULL, reason TEXT, active BOOLEAN DEFAULT TRUE, issued_by TEXT, issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), released_at TIMESTAMP WITH TIME ZONE);
CREATE TABLE public.infra_system_matrix (config_key TEXT PRIMARY KEY, config_data JSONB NOT NULL, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), updated_by TEXT);
CREATE TABLE public.infra_app_tokens (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, app_id TEXT UNIQUE NOT NULL, app_token TEXT NOT NULL, tier TEXT NOT NULL, status TEXT DEFAULT 'ACTIVE', created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.infra_tx_limits (id TEXT PRIMARY KEY, max_per_transaction NUMERIC, max_daily_total NUMERIC, max_monthly_total NUMERIC, category_limits JSONB, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), updated_by TEXT);
CREATE TABLE public.infra_snapshots (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), actor_id TEXT, snapshot_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE public.platform_configs (config_key TEXT PRIMARY KEY, config_data JSONB NOT NULL, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), updated_by TEXT);
CREATE TABLE public.app_registry (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, app_id TEXT UNIQUE NOT NULL, app_token TEXT NOT NULL, tier TEXT NOT NULL, status TEXT DEFAULT 'ACTIVE', developer_id TEXT, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());

CREATE TABLE public.fee_correction_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_name TEXT NOT NULL,
    description TEXT,
    transaction_type TEXT, 
    fee_type TEXT, 
    correction_formula TEXT, 
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.fee_correction_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id),
    original_fee_amount NUMERIC,
    corrected_fee_amount NUMERIC,
    correction_rule_id UUID REFERENCES public.fee_correction_rules(id),
    reason TEXT,
    corrected_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.item_reconciliation_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id UUID REFERENCES public.platform_vaults(id) ON DELETE CASCADE,
    partner_id TEXT,
    internal_balance NUMERIC DEFAULT 0,
    external_balance NUMERIC DEFAULT 0,
    discrepancy NUMERIC DEFAULT 0,
    status TEXT DEFAULT 'MATCHED',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.reconciliation_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL, -- INTERNAL, SYSTEM, EXTERNAL
    expected_balance NUMERIC NOT NULL,
    actual_balance NUMERIC NOT NULL,
    difference NUMERIC NOT NULL,
    status TEXT NOT NULL, -- MATCHED, MISMATCH, INVESTIGATING
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. CORE FUNCTIONS
CREATE OR REPLACE FUNCTION public.get_auth_role()
RETURNS TEXT AS $$
DECLARE
  r TEXT;
BEGIN
  SELECT role INTO r FROM public.staff WHERE id = auth.uid();
  IF r IS NULL THEN
    SELECT role INTO r FROM public.users WHERE id = auth.uid();
  END IF;
  RETURN COALESCE(r, 'USER');
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.update_wallet_balance(target_wallet_id UUID, new_balance NUMERIC, new_encrypted TEXT)
RETURNS void AS $$
BEGIN
    UPDATE public.wallets SET balance = new_balance WHERE id = target_wallet_id;
    UPDATE public.platform_vaults SET balance = new_balance, encrypted_balance = new_encrypted WHERE id = target_wallet_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.delete_old_activity()
RETURNS void AS $$
BEGIN
    DELETE FROM public.audit_trail WHERE timestamp < NOW() - INTERVAL '1 year';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Atomic Banking RPC
CREATE OR REPLACE FUNCTION public.post_transaction_v2(
    p_tx_id UUID,
    p_user_id UUID,
    p_wallet_id UUID,
    p_to_wallet_id UUID,
    p_amount TEXT,
    p_description TEXT,
    p_type TEXT,
    p_status TEXT,
    p_date DATE,
    p_metadata JSONB,
    p_category_id UUID,
    p_legs JSONB,
    p_reference_id TEXT DEFAULT NULL
)
RETURNS void AS $$
DECLARE
    leg JSONB;
BEGIN
    INSERT INTO public.transactions (
        id, user_id, wallet_id, to_wallet_id, amount, description, type, status, date, metadata, category_id, reference_id
    ) VALUES (
        p_tx_id, p_user_id, p_wallet_id, p_to_wallet_id, p_amount, p_description, p_type, p_status, p_date, p_metadata, p_category_id, p_reference_id
    )
    ON CONFLICT (id) DO NOTHING;

    FOR leg IN SELECT * FROM jsonb_array_elements(p_legs)
    LOOP
        INSERT INTO public.financial_ledger (
            id, transaction_id, user_id, wallet_id, entry_type, amount, balance_after, balance_after_encrypted, description
        ) VALUES (
            gen_random_uuid(), p_tx_id, p_user_id, 
            (leg->>'wallet_id')::UUID, 
            leg->>'entry_type', 
            leg->>'amount', 
            (leg->>'balance_after')::TEXT, 
            leg->>'balance_after_encrypted', 
            leg->>'description'
        );

        UPDATE public.wallets 
        SET balance = (leg->>'balance_after')::NUMERIC 
        WHERE id = (leg->>'wallet_id')::UUID;

        UPDATE public.platform_vaults 
        SET balance = (leg->>'balance_after')::NUMERIC, 
            encrypted_balance = leg->>'balance_after_encrypted' 
        WHERE id = (leg->>'wallet_id')::UUID;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Atomic Append Ledger Legs RPC
CREATE OR REPLACE FUNCTION public.append_ledger_entries_v1(
    p_tx_id UUID,
    p_legs JSONB
)
RETURNS void AS $$
DECLARE
    leg JSONB;
BEGIN
    FOR leg IN SELECT * FROM jsonb_array_elements(p_legs)
    LOOP
        INSERT INTO public.financial_ledger (
            id, transaction_id, user_id, wallet_id, entry_type, amount, balance_after, balance_after_encrypted, description
        ) VALUES (
            gen_random_uuid(), p_tx_id, 
            (SELECT user_id FROM public.transactions WHERE id = p_tx_id),
            (leg->>'wallet_id')::UUID, 
            leg->>'entry_type', 
            leg->>'amount', 
            (leg->>'balance_after')::TEXT, 
            leg->>'balance_after_encrypted', 
            leg->>'description'
        );

        UPDATE public.wallets 
        SET balance = (leg->>'balance_after')::NUMERIC 
        WHERE id = (leg->>'wallet_id')::UUID;

        UPDATE public.platform_vaults 
        SET balance = (leg->>'balance_after')::NUMERIC, 
            encrypted_balance = leg->>'balance_after_encrypted' 
        WHERE id = (leg->>'wallet_id')::UUID;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- User Registration Handler
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
DECLARE
    new_user_id UUID;
    new_customer_id TEXT;
    encrypted_zero TEXT;
    wallet1_id UUID;
    wallet2_id UUID;
    meta_customer_id TEXT;
BEGIN
    new_user_id := NEW.id;
    meta_customer_id := NEW.raw_user_meta_data->>'customer_id';
    
    IF meta_customer_id IS NOT NULL THEN
        new_customer_id := meta_customer_id;
    ELSE
        new_customer_id := 'OB' || to_char(NOW(), 'YY') || '-' || 
                           (floor(random() * 9000 + 1000)::text) || '-' || 
                           (floor(random() * 9000 + 1000)::text);
    END IF;
    
    encrypted_zero := 'ENCRYPTED_ZERO_PLACEHOLDER'; 
    
    wallet1_id := md5(new_user_id::text || 'Orbi')::uuid;
    wallet2_id := md5(new_user_id::text || 'PaySafe')::uuid;

    INSERT INTO public.users (
        id, email, full_name, customer_id, phone, nationality, currency, registry_type, role, language, app_origin, metadata
    )
    VALUES (
        new_user_id,
        NEW.email,
        NEW.raw_user_meta_data->>'full_name',
        new_customer_id,
        NEW.raw_user_meta_data->>'phone',
        COALESCE(NEW.raw_user_meta_data->>'nationality', 'Tanzania'),
        'TZS',
        COALESCE(NEW.raw_user_meta_data->>'registry_type', 'CONSUMER'),
        COALESCE(NEW.raw_user_meta_data->>'role', 'USER'),
        COALESCE(NEW.raw_user_meta_data->>'language', 'en'),
        COALESCE(NEW.raw_user_meta_data->>'app_origin', 'OBI_INSTITUTIONAL_CORE_V25'),
        jsonb_build_object('transfer_card', jsonb_build_object(
            'holder_name', NEW.raw_user_meta_data->>'full_name',
            'card_number_masked', new_customer_id,
            'brand', 'mastercard_style',
            'status', 'ready',
            'provisioned_at', NOW(),
            'product_name', 'Orbi'
        ))
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        full_name = COALESCE(EXCLUDED.full_name, public.users.full_name),
        customer_id = COALESCE(public.users.customer_id, EXCLUDED.customer_id),
        metadata = public.users.metadata || EXCLUDED.metadata;

    INSERT INTO public.platform_vaults (
        id, user_id, vault_role, name, balance, encrypted_balance, currency, color, icon, metadata
    )
    VALUES (
        wallet1_id, new_user_id, 'OPERATING', 'Orbi', 0, encrypted_zero, 'TZS', '#10B981', 'credit-card',
        jsonb_build_object(
            'linked_customer_id', new_customer_id,
            'account_number', new_customer_id,
            'display_name', NEW.raw_user_meta_data->>'full_name',
            'card_type', 'Virtual Master'
        )
    )
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.platform_vaults (
        id, user_id, vault_role, name, balance, encrypted_balance, currency, color, icon, metadata
    )
    VALUES (
        wallet2_id, new_user_id, 'INTERNAL_TRANSFER', 'PaySafe', 0, encrypted_zero, 'TZS', '#6366F1', 'shield-check',
        jsonb_build_object(
            'is_secure_escrow', true,
            'slogan', 'Secure Internal Transfers',
            'display_mode', 'mask',
            'account_number', 'ESC-' || new_customer_id
        )
    )
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.user_messages (
        user_id, subject, body, category, is_read
    )
    VALUES (
        new_user_id,
        'Welcome to ORBI: Your Sovereign Financial Node',
        'Welcome to the future of money. Your sovereign vault is active and ready.

We are here to support your financial journey. If you need assistance, please reach out to our platform team:

• Email: support@orbi.io
• Phone: +255 700 000 000
• Help Center: help.orbi.io

Stay Sovereign,
The ORBI Team',
        'system',
        FALSE
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- 5. TRIGGERS
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 6. RLS POLICIES
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.financial_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.financial_partners ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.institutional_payment_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.external_fund_movements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.provider_routing_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inbound_sms_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.offline_transaction_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.outbound_sms_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.system_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chargeback_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payment_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payment_metrics_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transaction_status_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ctr_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.digital_merchants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.system_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reported_issues ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rule_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff_issues ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_trail ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.legal_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.infra_system_matrix ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.infra_app_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.infra_tx_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.regulatory_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transfer_tax_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.platform_vaults ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.goals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.infra_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.platform_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.provider_anomalies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.kyc_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fee_correction_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fee_correction_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.item_reconciliation_audit ENABLE ROW LEVEL SECURITY;

-- ==========================================
-- NEXT-GEN SECURITY ARCHITECTURE (V26)
-- ==========================================

-- Layer 1: Passkeys (WebAuthn)
CREATE TABLE public.passkeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    counter BIGINT DEFAULT 0,
    transports JSONB DEFAULT '[]'::jsonb,
    device_type TEXT,
    backed_up BOOLEAN DEFAULT FALSE,
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_passkey_user ON public.passkeys(user_id);

-- Layer 2: Device Fingerprinting
CREATE TABLE public.device_fingerprints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    device_hash TEXT NOT NULL,
    platform TEXT,
    os_version TEXT,
    browser TEXT,
    ip_address TEXT,
    is_trusted BOOLEAN DEFAULT FALSE,
    risk_score NUMERIC DEFAULT 0,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, device_hash)
);
CREATE INDEX idx_device_fp_user ON public.device_fingerprints(user_id);

-- Layer 3: Behavioral Biometrics
CREATE TABLE public.behavioral_biometrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    session_id TEXT,
    typing_speed NUMERIC,
    swipe_velocity NUMERIC,
    touch_pressure NUMERIC,
    anomaly_score NUMERIC DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_behavior_user ON public.behavioral_biometrics(user_id);

-- Layer 5 & 6: AI Fraud & Risk Logs
CREATE TABLE public.ai_risk_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    risk_score NUMERIC NOT NULL,
    ai_confidence NUMERIC,
    features JSONB DEFAULT '{}'::jsonb,
    action_taken TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_ai_risk_user ON public.ai_risk_logs(user_id);

-- Layer 8: Hardware Security Modules (HSM) / Secure Enclave
CREATE TABLE public.secure_enclave_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES public.device_fingerprints(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    attestation_token TEXT,
    status TEXT DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_enclave_user ON public.secure_enclave_keys(user_id);

ALTER TABLE public.passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.behavioral_biometrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_risk_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.secure_enclave_keys ENABLE ROW LEVEL SECURITY;

-- Audit Trail
CREATE POLICY "Forensic Ledger Read" ON public.audit_trail FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT'));
CREATE POLICY "Audit WORM Write" ON public.audit_trail FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);
CREATE POLICY "Service role audit bypass" ON public.audit_trail FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Transactions
CREATE POLICY "Users create transactions" ON public.transactions FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users view own transactions" ON public.transactions FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Service role transaction bypass" ON public.transactions FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Admin manage institutional accounts" ON public.institutional_payment_accounts FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE')) WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'));
CREATE POLICY "Service role institutional account bypass" ON public.institutional_payment_accounts FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Users view own external fund movements" ON public.external_fund_movements FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users create own external fund movements" ON public.external_fund_movements FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Admin view external fund movements" ON public.external_fund_movements FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT', 'FINANCE'));
CREATE POLICY "Service role external fund movement bypass" ON public.external_fund_movements FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Admin manage provider routing rules" ON public.provider_routing_rules FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE')) WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'));
CREATE POLICY "Service role provider routing bypass" ON public.provider_routing_rules FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Service role inbound sms bypass" ON public.inbound_sms_messages FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Service role offline session bypass" ON public.offline_transaction_sessions FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Service role outbound sms bypass" ON public.outbound_sms_messages FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Identity
CREATE POLICY "Workforce Consumer Access" ON public.users FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'CUSTOMER_CARE'));
CREATE POLICY "Consumer Self Management" ON public.users FOR SELECT USING (auth.uid() = id);

-- Staff
CREATE POLICY "Admins manage workforce" ON public.staff FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN'));
CREATE POLICY "Staff visible to themselves" ON public.staff FOR SELECT USING (auth.uid() = id);

-- Wallets & Vaults
CREATE POLICY "Users manage own wallets" ON public.wallets FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users manage own vaults" ON public.platform_vaults FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Service role vault bypass" ON public.platform_vaults FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Messages
CREATE POLICY "Users view own messages" ON public.user_messages FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users update own messages" ON public.user_messages FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users delete own messages" ON public.user_messages FOR DELETE USING (auth.uid() = user_id);
CREATE POLICY "Staff view messages" ON public.staff_messages FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'CUSTOMER_CARE', 'AUDIT'));

-- Infrastructure
CREATE POLICY "Admin Node Management" ON public.infra_system_matrix FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'IT'));
CREATE POLICY "Admin App Registry" ON public.infra_app_tokens FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'IT'));
CREATE POLICY "Admin Risk Calibration" ON public.infra_tx_limits FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT'));
CREATE POLICY "Admin manage regulatory" ON public.regulatory_config FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT'));
CREATE POLICY "Admin manage partners" ON public.financial_partners FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT'));
CREATE POLICY "Admin manage merchants" ON public.digital_merchants FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT'));

-- KYC
CREATE POLICY "Users can view own KYC requests" ON public.kyc_requests FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can submit KYC requests" ON public.kyc_requests FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Admins manage KYC requests" ON public.kyc_requests FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'CUSTOMER_CARE'));

-- Devices & Documents
CREATE POLICY "Users view own devices" ON public.user_devices FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users manage own devices" ON public.user_devices FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users view own documents" ON public.user_documents FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users upload own documents" ON public.user_documents FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Governance
CREATE POLICY "Workflow Visibility" ON public.approval_requests FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT'));
CREATE POLICY "Hold Visibility" ON public.legal_holds FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT'));
CREATE POLICY "Admin view snapshots" ON public.infra_snapshots FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'IT'));
CREATE POLICY "Admin manage configs" ON public.platform_configs FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'IT'));
CREATE POLICY "Admin manage apps" ON public.app_registry FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'IT'));
CREATE POLICY "Admin view anomalies" ON public.provider_anomalies FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT', 'FRAUD'));

-- Strategy
CREATE POLICY "Users manage own goals" ON public.goals FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users manage own categories" ON public.categories FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users manage own tasks" ON public.tasks FOR ALL USING (auth.uid() = user_id);

-- Fee Correction
CREATE POLICY "Admins manage fee rules" ON public.fee_correction_rules FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'FINANCE'));
CREATE POLICY "Admins view fee logs" ON public.fee_correction_logs FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'FINANCE', 'AUDIT'));

CREATE POLICY "Admins view reconciliation audits" ON public.item_reconciliation_audit FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT'));
CREATE POLICY "Admins insert reconciliation audits" ON public.item_reconciliation_audit FOR INSERT WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'AUDIT'));
CREATE POLICY "Service role insert reconciliation" ON public.item_reconciliation_audit FOR INSERT TO service_role WITH CHECK (true);
CREATE POLICY "Service role select reconciliation" ON public.item_reconciliation_audit FOR SELECT TO service_role USING (true);

-- Reconciliation Reports
CREATE POLICY "Admins view reconciliation reports" ON public.reconciliation_reports 
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT'));

CREATE POLICY "System manage reconciliation reports" ON public.reconciliation_reports 
    FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Security Tables
CREATE POLICY "Users manage own passkeys" ON public.passkeys FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users view own device fingerprints" ON public.device_fingerprints FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users view own behavioral biometrics" ON public.behavioral_biometrics FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users view own ai risk logs" ON public.ai_risk_logs FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users manage own secure enclave keys" ON public.secure_enclave_keys FOR ALL USING (auth.uid() = user_id);

-- System bypass for security tables
CREATE POLICY "Service role passkeys bypass" ON public.passkeys FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Service role device fingerprints bypass" ON public.device_fingerprints FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Service role behavioral biometrics bypass" ON public.behavioral_biometrics FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Service role ai risk logs bypass" ON public.ai_risk_logs FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Service role secure enclave keys bypass" ON public.secure_enclave_keys FOR ALL TO service_role USING (true) WITH CHECK (true);

-- 7. INDEXES
CREATE INDEX IF NOT EXISTS idx_tx_user_date ON public.transactions(user_id, date);
CREATE INDEX IF NOT EXISTS idx_ledger_tx ON public.financial_ledger(transaction_id);
CREATE INDEX IF NOT EXISTS idx_transactions_user_wallet ON public.transactions(user_id, wallet_id);
CREATE INDEX IF NOT EXISTS idx_institutional_payment_accounts_role ON public.institutional_payment_accounts(role, currency, status);
CREATE INDEX IF NOT EXISTS idx_institutional_payment_accounts_provider ON public.institutional_payment_accounts(provider_id);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_user_date ON public.external_fund_movements(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_transaction ON public.external_fund_movements(transaction_id);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_provider_status ON public.external_fund_movements(provider_id, status);
CREATE INDEX IF NOT EXISTS idx_provider_routing_rules_lookup ON public.provider_routing_rules(rail, operation_code, status, priority);
CREATE INDEX IF NOT EXISTS idx_inbound_sms_request_id ON public.inbound_sms_messages(request_id);
CREATE INDEX IF NOT EXISTS idx_offline_transaction_sessions_request_id ON public.offline_transaction_sessions(request_id);
CREATE INDEX IF NOT EXISTS idx_offline_transaction_sessions_status ON public.offline_transaction_sessions(status, created_at);
CREATE INDEX IF NOT EXISTS idx_outbound_sms_request_id ON public.outbound_sms_messages(request_id);
CREATE INDEX IF NOT EXISTS idx_wallets_user ON public.wallets(user_id);
CREATE INDEX IF NOT EXISTS idx_goals_user ON public.goals(user_id);
CREATE INDEX IF NOT EXISTS idx_categories_user ON public.categories(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_user ON public.tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_user_messages_user_read ON public.user_messages(user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_kyc_requests_user_id ON public.kyc_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_kyc_requests_status ON public.kyc_requests(status);
CREATE INDEX IF NOT EXISTS idx_user_devices_user ON public.user_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_user_documents_user ON public.user_documents(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON public.user_sessions(user_id);
