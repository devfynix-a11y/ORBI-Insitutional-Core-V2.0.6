DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff' AND column_name='address') THEN
        ALTER TABLE public.staff ADD COLUMN address TEXT;
    END IF;
END $$;
-- ORBI SOVEREIGN MASTER SCHEMA V93.0 (IDEMPOTENT MASTER KEY)
-- This script is designed to be run multiple times without data loss.
-- It adds missing columns, tables, and updates functions to the latest version.
-- V93.0: Added append_ledger_entries_v1 for atomic ledger updates and enhanced reconciliation support.
DROP FUNCTION IF EXISTS public.card_settle_v1(TEXT, UUID, UUID, NUMERIC) CASCADE;
DROP FUNCTION IF EXISTS public.bill_reserve_adjust_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB, NUMERIC) CASCADE;

-- 1. CORE EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. TABLES DEFINITION (IDEMPOTENT)
                                                                                                                                                                                                                                                                                                                                       
CREATE TABLE IF NOT EXISTS public.secrets (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.wal_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data TEXT NOT NULL,
    status TEXT DEFAULT 'PENDING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action TEXT NOT NULL,
    meta JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
COMMENT ON TABLE public.audit_logs IS 'LEGACY / NON-AUTHORITATIVE. Do not use for production-critical financial, settlement, webhook, or privileged repair auditing. Use audit_trail, transaction_events, financial_events, provider_webhook_events, and settlement_lifecycle instead.';

CREATE TABLE IF NOT EXISTS public.users (
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
    app_origin TEXT DEFAULT 'OBI_INSTITUTIONAL_CORE_V25',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    kyc_level INTEGER DEFAULT 0,
    kyc_status TEXT DEFAULT 'unverified',
    id_type TEXT,
    id_number TEXT,
    language TEXT DEFAULT 'en',
    notif_security BOOLEAN DEFAULT TRUE,
    notif_financial BOOLEAN DEFAULT TRUE,
    notif_budget BOOLEAN DEFAULT TRUE,
    notif_marketing BOOLEAN DEFAULT FALSE,
    fcm_token TEXT,
    security_tx_pin_hash TEXT,
    security_tx_pin_enabled BOOLEAN DEFAULT FALSE,
    security_biometric_enabled BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Enforce unique phone numbers among users (NULL allowed multiple times)
CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique
ON public.users (phone)
WHERE phone IS NOT NULL;

-- Compatibility View for user_profiles
CREATE OR REPLACE VIEW public.user_profiles AS SELECT * FROM public.users;

CREATE TABLE IF NOT EXISTS public.staff (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER',
    account_status TEXT DEFAULT 'pending',
    customer_id TEXT UNIQUE NOT NULL,
    phone TEXT,
    avatar_url TEXT,
    address TEXT,
    nationality TEXT DEFAULT 'Tanzania',
    language TEXT DEFAULT 'en',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='staff' AND column_name='address'
    ) THEN
        ALTER TABLE public.staff ADD COLUMN address TEXT;
    END IF;
END $$;

-- Enforce unique phone numbers among staff (NULL allowed multiple times)
CREATE UNIQUE INDEX IF NOT EXISTS staff_phone_unique
ON public.staff (phone)
WHERE phone IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.wallets (
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
    is_locked BOOLEAN DEFAULT FALSE,
    locked_at TIMESTAMP WITH TIME ZONE,
    lock_reason TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.platform_vaults (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    vault_role TEXT, 
    name TEXT,
    balance NUMERIC DEFAULT 0, 
    encrypted_balance TEXT, 
    currency TEXT DEFAULT 'TZS', 
    color TEXT, 
    icon TEXT,
    status TEXT DEFAULT 'active',
    is_locked BOOLEAN DEFAULT FALSE,
    locked_at TIMESTAMP WITH TIME ZONE,
    lock_reason TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='wallets' AND column_name='is_locked'
    ) THEN
        ALTER TABLE public.wallets ADD COLUMN is_locked BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='wallets' AND column_name='locked_at'
    ) THEN
        ALTER TABLE public.wallets ADD COLUMN locked_at TIMESTAMP WITH TIME ZONE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='wallets' AND column_name='lock_reason'
    ) THEN
        ALTER TABLE public.wallets ADD COLUMN lock_reason TEXT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='platform_vaults' AND column_name='status'
    ) THEN
        ALTER TABLE public.platform_vaults ADD COLUMN status TEXT DEFAULT 'active';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='platform_vaults' AND column_name='is_locked'
    ) THEN
        ALTER TABLE public.platform_vaults ADD COLUMN is_locked BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='platform_vaults' AND column_name='locked_at'
    ) THEN
        ALTER TABLE public.platform_vaults ADD COLUMN locked_at TIMESTAMP WITH TIME ZONE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='platform_vaults' AND column_name='lock_reason'
    ) THEN
        ALTER TABLE public.platform_vaults ADD COLUMN lock_reason TEXT;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.transactions (
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

CREATE TABLE IF NOT EXISTS public.transaction_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    old_state TEXT,
    new_state TEXT NOT NULL,
    actor TEXT DEFAULT 'system',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Ensure category_id exists in transactions
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='category_id') THEN
        ALTER TABLE public.transactions ADD COLUMN category_id UUID;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='reference_id') THEN
        ALTER TABLE public.transactions ADD COLUMN reference_id TEXT UNIQUE;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='currency') THEN
        ALTER TABLE public.transactions ADD COLUMN currency TEXT DEFAULT 'TZS';
    END IF;

    -- Add User Setting Columns
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='language') THEN
        ALTER TABLE public.users ADD COLUMN language TEXT DEFAULT 'en';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='notif_security') THEN
        ALTER TABLE public.users ADD COLUMN notif_security BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='notif_financial') THEN
        ALTER TABLE public.users ADD COLUMN notif_financial BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='notif_budget') THEN
        ALTER TABLE public.users ADD COLUMN notif_budget BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='notif_marketing') THEN
        ALTER TABLE public.users ADD COLUMN notif_marketing BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='security_tx_pin_hash') THEN
        ALTER TABLE public.users ADD COLUMN security_tx_pin_hash TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='security_tx_pin_enabled') THEN
        ALTER TABLE public.users ADD COLUMN security_tx_pin_enabled BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='security_biometric_enabled') THEN
        ALTER TABLE public.users ADD COLUMN security_biometric_enabled BOOLEAN DEFAULT FALSE;
    END IF;

    -- Add language to staff
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff' AND column_name='language') THEN
        ALTER TABLE public.staff ADD COLUMN language TEXT DEFAULT 'en';
    END IF;
END $$;

DO $$
DECLARE
    tx_constraint RECORD;
BEGIN
    FOR tx_constraint IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'transactions'
          AND c.contype = 'c'
          AND pg_get_constraintdef(c.oid) LIKE '%status%'
          AND pg_get_constraintdef(c.oid) NOT LIKE '%settled%'
    LOOP
        EXECUTE format(
            'ALTER TABLE public.transactions DROP CONSTRAINT %I',
            tx_constraint.conname
        );
    END LOOP;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'transactions'
          AND c.conname = 'transactions_status_check_v2'
    ) THEN
        ALTER TABLE public.transactions
            ADD CONSTRAINT transactions_status_check_v2
            CHECK (
                status IN (
                    'created',
                    'pending',
                    'authorized',
                    'processing',
                    'settled',
                    'completed',
                    'failed',
                    'cancelled',
                    'held_for_review',
                    'reversed',
                    'refunded'
                )
            );
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.financial_ledger (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    wallet_id UUID,
    shared_pot_id UUID,
    bill_reserve_id UUID,
    bucket_type TEXT,
    entry_side TEXT,
    entry_type TEXT NOT NULL,
    amount TEXT NOT NULL,
    balance_after TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Ensure balance_after_encrypted exists in financial_ledger
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_ledger' AND column_name='balance_after_encrypted') THEN
        ALTER TABLE public.financial_ledger ADD COLUMN balance_after_encrypted TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_ledger' AND column_name='shared_pot_id') THEN
        ALTER TABLE public.financial_ledger ADD COLUMN shared_pot_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_ledger' AND column_name='bill_reserve_id') THEN
        ALTER TABLE public.financial_ledger ADD COLUMN bill_reserve_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_ledger' AND column_name='bucket_type') THEN
        ALTER TABLE public.financial_ledger ADD COLUMN bucket_type TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_ledger' AND column_name='entry_side') THEN
        ALTER TABLE public.financial_ledger ADD COLUMN entry_side TEXT;
    END IF;
END $$;


CREATE TABLE IF NOT EXISTS public.ledger_append_markers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID NOT NULL REFERENCES public.transactions(id) ON DELETE CASCADE,
    append_key TEXT,
    append_phase TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_append_markers_append_key
    ON public.ledger_append_markers(append_key)
    WHERE append_key IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_append_markers_tx_phase
    ON public.ledger_append_markers(transaction_id, append_phase)
    WHERE append_phase IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.goals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    name TEXT NOT NULL, 
    target NUMERIC NOT NULL, 
    current NUMERIC DEFAULT 0, 
    source_wallet_id UUID REFERENCES public.wallets(id),
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

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='goals' AND column_name='source_wallet_id'
    ) THEN
        ALTER TABLE public.goals ADD COLUMN source_wallet_id UUID REFERENCES public.wallets(id);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.goal_auto_allocation_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    goal_id UUID REFERENCES public.goals(id) ON DELETE CASCADE,
    source_transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    source_reference_id TEXT,
    source_wallet_id UUID,
    source_amount NUMERIC DEFAULT 0,
    allocated_amount NUMERIC DEFAULT 0,
    trigger_type TEXT NOT NULL CHECK (trigger_type IN ('DEPOSIT', 'SALARY', 'REMITTANCE', 'CARD_DEPOSIT', 'EXTERNAL_DEPOSIT', 'AGENT_CASH_DEPOSIT', 'MANUAL_REPLAY')),
    status TEXT NOT NULL DEFAULT 'PROCESSING' CHECK (status IN ('PROCESSING', 'COMPLETED', 'SKIPPED', 'FAILED')),
    reason TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_goal_auto_allocation_goal_tx
    ON public.goal_auto_allocation_events(goal_id, source_transaction_id);
CREATE INDEX IF NOT EXISTS idx_goal_auto_allocation_user_created
    ON public.goal_auto_allocation_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_goal_auto_allocation_goal_created
    ON public.goal_auto_allocation_events(goal_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    name TEXT NOT NULL, 
    budget TEXT, 
    color TEXT, 
    icon TEXT, 
    budget_period TEXT DEFAULT 'MONTHLY',
    budget_interval TEXT DEFAULT 'MONTHLY',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ORBI WEALTH: structured money planning for everyday users, businesses,
-- enterprises, and premium users.
CREATE TABLE IF NOT EXISTS public.wealth_buckets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    bucket_type TEXT NOT NULL CHECK (bucket_type IN ('OPERATING', 'PLANNED', 'PROTECTED', 'GROWING')),
    wallet_id UUID,
    currency TEXT DEFAULT 'TZS',
    ledger_balance NUMERIC DEFAULT 0,
    available_balance NUMERIC DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (user_id, bucket_type, currency)
);

CREATE TABLE IF NOT EXISTS public.allocation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    trigger_type TEXT NOT NULL CHECK (trigger_type IN ('DEPOSIT', 'SALARY', 'ROUNDUP', 'REMITTANCE', 'MANUAL')),
    source_wallet_id UUID,
    target_type TEXT NOT NULL CHECK (target_type IN ('GOAL', 'BUDGET', 'BILL_RESERVE', 'SHARED_POT', 'WEALTH_BUCKET')),
    target_id UUID,
    mode TEXT NOT NULL DEFAULT 'PERCENT' CHECK (mode IN ('FIXED', 'PERCENT')),
    fixed_amount NUMERIC,
    percentage NUMERIC,
    priority INTEGER DEFAULT 1,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.shared_pots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    purpose TEXT,
    currency TEXT DEFAULT 'TZS',
    target_amount NUMERIC,
    current_amount NUMERIC DEFAULT 0,
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'COMPLETED', 'ARCHIVED')),
    access_model TEXT DEFAULT 'INVITE' CHECK (access_model IN ('INVITE', 'PRIVATE', 'ORG')),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.shared_pot_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pot_id UUID REFERENCES public.shared_pots(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'CONTRIBUTOR' CHECK (role IN ('OWNER', 'MANAGER', 'CONTRIBUTOR', 'VIEWER')),
    contribution_target NUMERIC,
    contributed_amount NUMERIC DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (pot_id, user_id)
);

CREATE TABLE IF NOT EXISTS public.shared_pot_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pot_id UUID REFERENCES public.shared_pots(id) ON DELETE CASCADE,
    inviter_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    invitee_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    invitee_identifier TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'CONTRIBUTOR' CHECK (role IN ('MANAGER', 'CONTRIBUTOR', 'VIEWER')),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'CANCELLED', 'EXPIRED')),
    message TEXT,
    responded_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS public.shared_budgets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    purpose TEXT,
    currency TEXT DEFAULT 'TZS',
    budget_limit NUMERIC NOT NULL,
    spent_amount NUMERIC DEFAULT 0,
    period_type TEXT DEFAULT 'MONTHLY' CHECK (period_type IN ('WEEKLY', 'MONTHLY', 'CUSTOM')),
    approval_mode TEXT DEFAULT 'AUTO' CHECK (approval_mode IN ('AUTO', 'REVIEW')),
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'ARCHIVED')),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.shared_budget_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    budget_id UUID REFERENCES public.shared_budgets(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'SPENDER' CHECK (role IN ('OWNER', 'MANAGER', 'SPENDER', 'VIEWER')),
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'REMOVED')),
    member_limit NUMERIC,
    spent_amount NUMERIC DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (budget_id, user_id)
);

CREATE TABLE IF NOT EXISTS public.shared_budget_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    budget_id UUID REFERENCES public.shared_budgets(id) ON DELETE CASCADE,
    inviter_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    invitee_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    invitee_identifier TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'SPENDER' CHECK (role IN ('MANAGER', 'SPENDER', 'VIEWER')),
    member_limit NUMERIC,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'CANCELLED', 'EXPIRED')),
    message TEXT,
    responded_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.shared_budget_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shared_budget_id UUID REFERENCES public.shared_budgets(id) ON DELETE CASCADE,
    member_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    source_wallet_id UUID,
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    merchant_name TEXT,
    provider TEXT,
    category TEXT,
    amount NUMERIC NOT NULL,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'COMPLETED' CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED', 'REVERSED')),
    note TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.shared_budget_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shared_budget_id UUID REFERENCES public.shared_budgets(id) ON DELETE CASCADE,
    requester_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    reviewer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    amount NUMERIC NOT NULL,
    currency TEXT DEFAULT 'TZS',
    provider TEXT,
    bill_category TEXT,
    reference TEXT,
    note TEXT,
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED')),
    metadata JSONB DEFAULT '{}'::jsonb,
    responded_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.bill_reserves (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    provider_name TEXT NOT NULL,
    bill_type TEXT NOT NULL,
    source_wallet_id UUID,
    currency TEXT DEFAULT 'TZS',
    due_pattern TEXT DEFAULT 'MONTHLY',
    due_day INTEGER,
    reserve_mode TEXT DEFAULT 'FIXED' CHECK (reserve_mode IN ('FIXED', 'PERCENT')),
    reserve_amount NUMERIC DEFAULT 0,
    locked_balance NUMERIC DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'ARCHIVED')),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.wealth_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
    currency TEXT DEFAULT 'TZS',
    operating_balance NUMERIC DEFAULT 0,
    planned_balance NUMERIC DEFAULT 0,
    protected_balance NUMERIC DEFAULT 0,
    growing_balance NUMERIC DEFAULT 0,
    net_position NUMERIC DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (user_id, snapshot_date, currency)
);

CREATE TABLE IF NOT EXISTS public.wealth_insights (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    insight_type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    severity TEXT DEFAULT 'INFO' CHECK (severity IN ('INFO', 'SUCCESS', 'WARNING', 'CRITICAL')),
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISMISSED', 'RESOLVED')),
    action_label TEXT,
    action_route TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='transactions' AND column_name='wealth_impact_type'
    ) THEN
        ALTER TABLE public.transactions ADD COLUMN wealth_impact_type TEXT DEFAULT 'OPERATING';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='transactions' AND column_name='protection_state'
    ) THEN
        ALTER TABLE public.transactions ADD COLUMN protection_state TEXT DEFAULT 'OPEN';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='transactions' AND column_name='allocation_source'
    ) THEN
        ALTER TABLE public.transactions ADD COLUMN allocation_source TEXT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='goals' AND column_name='shared_pot_id'
    ) THEN
        ALTER TABLE public.goals ADD COLUMN shared_pot_id UUID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='bill_reserves' AND column_name='status'
    ) THEN
        ALTER TABLE public.bill_reserves ADD COLUMN status TEXT DEFAULT 'ACTIVE';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='shared_pot_members' AND column_name='contributed_amount'
    ) THEN
        ALTER TABLE public.shared_pot_members ADD COLUMN contributed_amount NUMERIC DEFAULT 0;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='shared_pot_invitations' AND column_name='message'
    ) THEN
        ALTER TABLE public.shared_pot_invitations ADD COLUMN message TEXT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='financial_ledger' AND column_name='shared_budget_id'
    ) THEN
        ALTER TABLE public.financial_ledger ADD COLUMN shared_budget_id UUID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='transactions' AND column_name='shared_budget_id'
    ) THEN
        ALTER TABLE public.transactions ADD COLUMN shared_budget_id UUID;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_wealth_buckets_user_type
    ON public.wealth_buckets (user_id, bucket_type);
CREATE INDEX IF NOT EXISTS idx_allocation_rules_user_active
    ON public.allocation_rules (user_id, is_active, trigger_type);
CREATE INDEX IF NOT EXISTS idx_bill_reserves_user_active
    ON public.bill_reserves (user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_shared_pots_owner
    ON public.shared_pots (owner_user_id, status);
CREATE INDEX IF NOT EXISTS idx_shared_pot_invites_pot
    ON public.shared_pot_invitations (pot_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_pot_invites_invitee
    ON public.shared_pot_invitations (invitee_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budgets_owner
    ON public.shared_budgets (owner_user_id, status);
CREATE INDEX IF NOT EXISTS idx_shared_budget_members_budget
    ON public.shared_budget_members (budget_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_members_user
    ON public.shared_budget_members (user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_invites_budget
    ON public.shared_budget_invitations (budget_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_invites_invitee
    ON public.shared_budget_invitations (invitee_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_transactions_budget
    ON public.shared_budget_transactions (shared_budget_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_transactions_member
    ON public.shared_budget_transactions (member_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_approvals_budget
    ON public.shared_budget_approvals (shared_budget_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_wealth_snapshots_user_date
    ON public.wealth_snapshots (user_id, snapshot_date DESC);
CREATE INDEX IF NOT EXISTS idx_wealth_insights_user_status
    ON public.wealth_insights (user_id, status, severity);

-- ENTERPRISE UPGRADE: Organizations & B2B Multi-Tenancy
CREATE TABLE IF NOT EXISTS public.organizations (
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

-- TRUSTBRIDGE: Escrow Agreements
CREATE TABLE IF NOT EXISTS public.escrow_agreements (
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

-- TREASURY: Multi-Sig Policies & Approvers
CREATE TABLE IF NOT EXISTS public.treasury_policies (
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

CREATE TABLE IF NOT EXISTS public.treasury_approvers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'APPROVER',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='organization_id') THEN
        ALTER TABLE public.users ADD COLUMN organization_id UUID REFERENCES public.organizations(id);
        ALTER TABLE public.users ADD COLUMN org_role TEXT;
    END IF;
END $$;

DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='goals' AND column_name='organization_id') THEN
        ALTER TABLE public.goals ADD COLUMN organization_id UUID REFERENCES public.organizations(id);
        ALTER TABLE public.goals ADD COLUMN currency TEXT DEFAULT 'TZS';
        ALTER TABLE public.goals ADD COLUMN status TEXT DEFAULT 'ACTIVE';
        ALTER TABLE public.goals ADD COLUMN is_corporate BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='goals' AND column_name='linked_income_percentage') THEN
        ALTER TABLE public.goals ADD COLUMN linked_income_percentage NUMERIC;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='goals' AND column_name='monthly_target') THEN
        ALTER TABLE public.goals ADD COLUMN monthly_target NUMERIC;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='categories' AND column_name='organization_id') THEN
        ALTER TABLE public.categories ADD COLUMN organization_id UUID REFERENCES public.organizations(id);
        ALTER TABLE public.categories ADD COLUMN currency TEXT DEFAULT 'TZS';
        ALTER TABLE public.categories ADD COLUMN period TEXT DEFAULT 'MONTHLY';
        ALTER TABLE public.categories ADD COLUMN hard_limit BOOLEAN DEFAULT FALSE;
        ALTER TABLE public.categories ADD COLUMN is_corporate BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='categories' AND column_name='budget_interval') THEN
        ALTER TABLE public.categories ADD COLUMN budget_interval TEXT DEFAULT 'MONTHLY';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='categories' AND column_name='budget_period') THEN
        ALTER TABLE public.categories ADD COLUMN budget_period TEXT DEFAULT 'MONTHLY';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.budget_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id UUID REFERENCES public.categories(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE,
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    amount NUMERIC NOT NULL,
    alert_type TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.background_jobs (
    id UUID PRIMARY KEY,
    type TEXT NOT NULL,
    payload JSONB,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS public.tasks (
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

CREATE TABLE IF NOT EXISTS public.aml_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    risk_score NUMERIC NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.user_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    subject TEXT NOT NULL, 
    body TEXT NOT NULL, 
    category TEXT NOT NULL, 
    is_read BOOLEAN DEFAULT FALSE, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.staff_messages (
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

CREATE TABLE IF NOT EXISTS public.kms_keys (
    key_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    wrapped_jwk TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.audit_trail (
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

CREATE TABLE IF NOT EXISTS public.provider_anomalies (
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

CREATE TABLE IF NOT EXISTS public.financial_partners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    name VARCHAR(50) NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (LOWER(type) IN ('mobile_money', 'bank', 'card', 'crypto')),
    supported_currencies TEXT[] DEFAULT ARRAY['TZS']::TEXT[],
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

CREATE TABLE IF NOT EXISTS public.institutional_payment_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role TEXT NOT NULL,
    provider_id UUID REFERENCES public.financial_partners(id) ON DELETE SET NULL,
    bank_name TEXT NOT NULL,
    account_name TEXT NOT NULL,
    account_number TEXT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'TZS',
    country_code TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    is_primary BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.external_fund_movements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    direction TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'initiated',
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
    settlement_lifecycle_id UUID REFERENCES public.settlement_lifecycle(id) ON DELETE SET NULL,
    provider_event_id TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.provider_routing_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rail TEXT NOT NULL,
    country_code TEXT,
    currency TEXT,
    operation_code TEXT NOT NULL,
    provider_id UUID NOT NULL REFERENCES public.financial_partners(id) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 100,
    conditions JSONB DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.platform_fee_configs (
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

CREATE TABLE IF NOT EXISTS public.inbound_sms_messages (
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

CREATE TABLE IF NOT EXISTS public.offline_transaction_sessions (
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
    status TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS public.outbound_sms_messages (
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

DO $$
DECLARE
    partner_constraint RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='supported_currencies') THEN
        ALTER TABLE public.financial_partners ADD COLUMN supported_currencies TEXT[] DEFAULT ARRAY['TZS']::TEXT[];
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='client_id') THEN
        ALTER TABLE public.financial_partners ADD COLUMN client_id TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='client_secret') THEN
        ALTER TABLE public.financial_partners ADD COLUMN client_secret TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='api_base_url') THEN
        ALTER TABLE public.financial_partners ADD COLUMN api_base_url TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='webhook_secret') THEN
        ALTER TABLE public.financial_partners ADD COLUMN webhook_secret TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='token_cache') THEN
        ALTER TABLE public.financial_partners ADD COLUMN token_cache TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='token_expiry') THEN
        ALTER TABLE public.financial_partners ADD COLUMN token_expiry BIGINT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='logic_type') THEN
        ALTER TABLE public.financial_partners ADD COLUMN logic_type TEXT DEFAULT 'REGISTRY';
    END IF;

    BEGIN
        ALTER TABLE public.financial_partners ALTER COLUMN connection_secret DROP NOT NULL;
    EXCEPTION
        WHEN others THEN NULL;
    END;

    UPDATE public.financial_partners
    SET type = LOWER(type)
    WHERE type IS NOT NULL
      AND type <> LOWER(type);

    FOR partner_constraint IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'financial_partners'
          AND c.contype = 'c'
          AND pg_get_constraintdef(c.oid) LIKE '%type%'
    LOOP
        EXECUTE format(
            'ALTER TABLE public.financial_partners DROP CONSTRAINT %I',
            partner_constraint.conname
        );
    END LOOP;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'financial_partners'
          AND c.conname = 'financial_partners_type_check_v2'
    ) THEN
        ALTER TABLE public.financial_partners
            ADD CONSTRAINT financial_partners_type_check_v2
            CHECK (LOWER(type) IN ('mobile_money', 'bank', 'card', 'crypto'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'financial_partners'
          AND c.conname = 'financial_partners_logic_type_check'
    ) THEN
        ALTER TABLE public.financial_partners
            ADD CONSTRAINT financial_partners_logic_type_check
            CHECK (logic_type IN ('REGISTRY', 'GENERIC_REST', 'SPECIALIZED'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'institutional_payment_accounts'
          AND c.conname = 'institutional_payment_accounts_role_check'
    ) THEN
        ALTER TABLE public.institutional_payment_accounts
            ADD CONSTRAINT institutional_payment_accounts_role_check
            CHECK (role IN ('MAIN_COLLECTION', 'FEE_COLLECTION', 'TAX_COLLECTION', 'TRANSFER_SAVINGS'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'institutional_payment_accounts'
          AND c.conname = 'institutional_payment_accounts_status_check'
    ) THEN
        ALTER TABLE public.institutional_payment_accounts
            ADD CONSTRAINT institutional_payment_accounts_status_check
            CHECK (status IN ('ACTIVE', 'INACTIVE'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'external_fund_movements'
          AND c.conname = 'external_fund_movements_direction_check'
    ) THEN
        ALTER TABLE public.external_fund_movements
            ADD CONSTRAINT external_fund_movements_direction_check
            CHECK (direction IN ('INTERNAL_TO_EXTERNAL', 'EXTERNAL_TO_INTERNAL', 'EXTERNAL_TO_EXTERNAL'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'external_fund_movements'
          AND c.conname = 'external_fund_movements_status_check'
    ) THEN
        ALTER TABLE public.external_fund_movements
            ADD CONSTRAINT external_fund_movements_status_check
            CHECK (status IN ('previewed', 'initiated', 'processing', 'completed', 'failed', 'recorded', 'reversed'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'provider_routing_rules'
          AND c.conname = 'provider_routing_rules_rail_check'
    ) THEN
        ALTER TABLE public.provider_routing_rules
            ADD CONSTRAINT provider_routing_rules_rail_check
            CHECK (rail IN ('MOBILE_MONEY', 'BANK', 'CARD_GATEWAY', 'CRYPTO', 'WALLET'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'provider_routing_rules'
          AND c.conname = 'provider_routing_rules_status_check'
    ) THEN
        ALTER TABLE public.provider_routing_rules
            ADD CONSTRAINT provider_routing_rules_status_check
            CHECK (status IN ('ACTIVE', 'INACTIVE'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'platform_fee_configs'
          AND c.conname = 'platform_fee_configs_status_check'
    ) THEN
        ALTER TABLE public.platform_fee_configs
            ADD CONSTRAINT platform_fee_configs_status_check
            CHECK (status IN ('ACTIVE', 'INACTIVE'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'offline_transaction_sessions'
          AND c.conname = 'offline_transaction_sessions_status_check'
    ) THEN
        ALTER TABLE public.offline_transaction_sessions
            ADD CONSTRAINT offline_transaction_sessions_status_check
            CHECK (status IN ('RECEIVED', 'PARSED', 'VALIDATED', 'PENDING_CONFIRMATION', 'FORWARDED_TO_ORBI', 'CHALLENGE_SENT', 'CONFIRMED', 'SUCCESS', 'FAILED', 'EXPIRED', 'REJECTED'));
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.enforce_financial_partner_activation_readiness()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_status TEXT := UPPER(COALESCE(NEW.status, ''));
    v_provider_code TEXT := BTRIM(COALESCE(NEW.provider_metadata->>'provider_code', ''));
    v_rail TEXT := BTRIM(COALESCE(NEW.provider_metadata->>'rail', ''));
    v_operations_count INTEGER := COALESCE(jsonb_array_length(COALESCE(NEW.provider_metadata->'operations', '[]'::jsonb)), 0);
    v_mapping_operations_count INTEGER := COALESCE((
        SELECT COUNT(*)
        FROM jsonb_each(COALESCE(NEW.mapping_config->'operations', '{}'::jsonb))
    ), 0);
    v_supports_webhooks BOOLEAN := COALESCE((NEW.provider_metadata->>'supports_webhooks')::BOOLEAN, FALSE);
    v_has_callback BOOLEAN := COALESCE(NEW.mapping_config ? 'callback', FALSE);
    v_callback_reference TEXT := BTRIM(COALESCE(NEW.mapping_config->'callback'->>'reference_field', ''));
    v_callback_status TEXT := BTRIM(COALESCE(NEW.mapping_config->'callback'->>'status_field', ''));
BEGIN
    IF v_status <> 'ACTIVE' THEN
        RETURN NEW;
    END IF;

    IF COALESCE(NEW.mapping_config, '{}'::jsonb) = '{}'::jsonb THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_MAPPING_CONFIG_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF BTRIM(COALESCE(NEW.mapping_config->>'service_root', '')) = ''
       AND COALESCE((
            SELECT COUNT(*)
            FROM jsonb_each(COALESCE(NEW.mapping_config->'service_roots', '{}'::jsonb))
        ), 0) = 0 THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_SERVICE_ROOT_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF v_mapping_operations_count = 0
       AND NOT (COALESCE(NEW.mapping_config ? 'stk_push', FALSE)
             OR COALESCE(NEW.mapping_config ? 'disbursement', FALSE)
             OR COALESCE(NEW.mapping_config ? 'balance', FALSE)
             OR COALESCE(NEW.mapping_config ? 'check_status', FALSE)) THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_OPERATION_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF v_provider_code = '' THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_PROVIDER_CODE_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF v_rail = '' THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_RAIL_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF v_operations_count = 0 THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_OPERATIONS_METADATA_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF v_supports_webhooks OR v_has_callback OR EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(COALESCE(NEW.provider_metadata->'operations', '[]'::jsonb)) AS operation_name
        WHERE UPPER(operation_name) = 'WEBHOOK_VERIFY'
    ) THEN
        IF NOT v_has_callback THEN
            RAISE EXCEPTION 'PROVIDER_ACTIVATION_CALLBACK_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
        END IF;
        IF v_callback_reference = '' THEN
            RAISE EXCEPTION 'PROVIDER_ACTIVATION_CALLBACK_REFERENCE_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
        END IF;
        IF v_callback_status = '' THEN
            RAISE EXCEPTION 'PROVIDER_ACTIVATION_CALLBACK_STATUS_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_financial_partner_activation_readiness ON public.financial_partners;
CREATE TRIGGER trg_financial_partner_activation_readiness
BEFORE INSERT OR UPDATE ON public.financial_partners
FOR EACH ROW
EXECUTE FUNCTION public.enforce_financial_partner_activation_readiness();

CREATE TABLE IF NOT EXISTS public.digital_merchants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    name TEXT NOT NULL,
    category TEXT,
    status TEXT DEFAULT 'ACTIVE',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Multi-Tenant Merchant Architecture
CREATE TABLE IF NOT EXISTS public.merchants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    business_name TEXT NOT NULL,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'pending', -- pending, active, suspended, closed
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.merchant_wallets (
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

CREATE TABLE IF NOT EXISTS public.merchant_settlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE UNIQUE,
    bank_name TEXT NOT NULL,
    bank_account TEXT NOT NULL,
    settlement_schedule TEXT DEFAULT 'daily',
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);



-- Settlement Lifecycle
CREATE TABLE IF NOT EXISTS public.provider_webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id UUID NOT NULL REFERENCES public.financial_partners(id) ON DELETE CASCADE,
    provider_event_id TEXT,
    dedupe_key TEXT NOT NULL,
    replay_key TEXT NOT NULL,
    reference TEXT,
    normalized_status TEXT,
    raw_status TEXT,
    event_timestamp TIMESTAMP WITH TIME ZONE,
    timestamp_source TEXT,
    signature_status TEXT NOT NULL DEFAULT 'pending',
    freshness_status TEXT NOT NULL DEFAULT 'missing',
    verification_status TEXT NOT NULL DEFAULT 'pending',
    application_status TEXT NOT NULL DEFAULT 'received',
    payload_sha256 TEXT NOT NULL,
    payload JSONB DEFAULT '{}'::jsonb,
    raw_headers JSONB DEFAULT '{}'::jsonb,
    source_ip TEXT,
    failure_code TEXT,
    failure_message TEXT,
    applied_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT provider_webhook_events_status_check CHECK (
        application_status IN ('received', 'processing', 'applied', 'rejected', 'failed')
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_webhook_events_partner_dedupe
    ON public.provider_webhook_events(partner_id, dedupe_key);
CREATE INDEX IF NOT EXISTS idx_provider_webhook_events_provider_event
    ON public.provider_webhook_events(provider_event_id);
CREATE INDEX IF NOT EXISTS idx_provider_webhook_events_reference
    ON public.provider_webhook_events(reference);

CREATE TABLE IF NOT EXISTS public.settlement_lifecycle (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    external_movement_id UUID REFERENCES public.external_fund_movements(id) ON DELETE SET NULL,
    merchant_settlement_id UUID REFERENCES public.merchant_settlements(id) ON DELETE SET NULL,
    provider_id UUID REFERENCES public.financial_partners(id) ON DELETE SET NULL,

    lifecycle_key TEXT UNIQUE,
    settlement_batch_id TEXT,
    provider_reference TEXT,
    provider_status TEXT,

    rail TEXT,
    direction TEXT,
    operation_type TEXT,
    currency TEXT DEFAULT 'TZS',

    gross_amount NUMERIC NOT NULL DEFAULT 0,
    fee_amount NUMERIC NOT NULL DEFAULT 0,
    tax_amount NUMERIC NOT NULL DEFAULT 0,
    net_amount NUMERIC NOT NULL DEFAULT 0,

    stage TEXT NOT NULL DEFAULT 'INITIATED',
    status TEXT NOT NULL DEFAULT 'ACTIVE',

    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,

    initiated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    queued_at TIMESTAMP WITH TIME ZONE,
    processing_at TIMESTAMP WITH TIME ZONE,
    sent_to_provider_at TIMESTAMP WITH TIME ZONE,
    provider_confirmed_at TIMESTAMP WITH TIME ZONE,
    settled_at TIMESTAMP WITH TIME ZONE,
    reconciled_at TIMESTAMP WITH TIME ZONE,
    failed_at TIMESTAMP WITH TIME ZONE,
    reversed_at TIMESTAMP WITH TIME ZONE,

    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
DECLARE
    settlement_constraint RECORD;
BEGIN
    FOR settlement_constraint IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'settlement_lifecycle'
          AND c.contype = 'c'
          AND (
              pg_get_constraintdef(c.oid) LIKE '%stage%'
              OR pg_get_constraintdef(c.oid) LIKE '%status%'
          )
    LOOP
        EXECUTE format(
            'ALTER TABLE public.settlement_lifecycle DROP CONSTRAINT %I',
            settlement_constraint.conname
        );
    END LOOP;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'settlement_lifecycle'
          AND c.conname = 'settlement_lifecycle_stage_check_v1'
    ) THEN
        ALTER TABLE public.settlement_lifecycle
            ADD CONSTRAINT settlement_lifecycle_stage_check_v1
            CHECK (
                stage IN (
                    'INITIATED',
                    'QUEUED',
                    'PROCESSING',
                    'SENT_TO_PROVIDER',
                    'PROVIDER_CONFIRMED',
                    'SETTLED',
                    'RECONCILED',
                    'FAILED',
                    'REVERSED'
                )
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'settlement_lifecycle'
          AND c.conname = 'settlement_lifecycle_status_check_v1'
    ) THEN
        ALTER TABLE public.settlement_lifecycle
            ADD CONSTRAINT settlement_lifecycle_status_check_v1
            CHECK (
                status IN (
                    'ACTIVE',
                    'COMPLETED',
                    'FAILED',
                    'CANCELLED',
                    'REVERSED'
                )
            );
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.set_settlement_lifecycle_updated_at()
RETURNS trigger AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_settlement_lifecycle_updated_at ON public.settlement_lifecycle;
CREATE TRIGGER trg_settlement_lifecycle_updated_at
BEFORE UPDATE ON public.settlement_lifecycle
FOR EACH ROW
EXECUTE FUNCTION public.set_settlement_lifecycle_updated_at();

CREATE OR REPLACE FUNCTION public.claim_internal_transfer_settlement(
    p_tx_id UUID,
    p_worker_id TEXT,
    p_worker_claim_id TEXT DEFAULT NULL
)
RETURNS TABLE (
    transaction_id UUID,
    lifecycle_id UUID,
    append_key TEXT,
    append_phase TEXT,
    worker_claim_id TEXT,
    transaction_status TEXT,
    lifecycle_stage TEXT,
    lifecycle_status TEXT,
    append_already_applied BOOLEAN,
    already_completed BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tx public.transactions%ROWTYPE;
    v_lifecycle public.settlement_lifecycle%ROWTYPE;
    v_now TIMESTAMP WITH TIME ZONE := NOW();
    v_claim_id TEXT := COALESCE(NULLIF(BTRIM(p_worker_claim_id), ''), gen_random_uuid()::TEXT);
    v_lifecycle_key TEXT := 'INTERNAL_TRANSFER:' || p_tx_id::TEXT || ':PAYSAFE_SETTLEMENT';
    v_append_key TEXT := 'settlement:' || p_tx_id::TEXT || ':paysafe_release:v2';
    v_append_phase TEXT := 'PAYSAFE_SETTLEMENT';
    v_existing_claim_id TEXT;
    v_append_applied BOOLEAN := FALSE;
BEGIN
    IF NULLIF(BTRIM(p_worker_id), '') IS NULL THEN
        RAISE EXCEPTION 'WORKER_ID_REQUIRED: claim_internal_transfer_settlement requires a worker identifier';
    END IF;

    SELECT * INTO v_tx
    FROM public.transactions
    WHERE id = p_tx_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Transaction % was not found for settlement claim', p_tx_id;
    END IF;

    INSERT INTO public.settlement_lifecycle (
        transaction_id,
        lifecycle_key,
        rail,
        direction,
        operation_type,
        currency,
        stage,
        status,
        initiated_at,
        metadata
    )
    VALUES (
        p_tx_id,
        v_lifecycle_key,
        'SOVEREIGN_LEDGER',
        'INTERNAL',
        'INTERNAL_TRANSFER',
        COALESCE(v_tx.currency, 'TZS'),
        'INITIATED',
        'ACTIVE',
        v_now,
        jsonb_build_object(
            'settlement_model', 'INTERNAL_PAYSAFE_VAULT',
            'append_key', v_append_key,
            'append_phase', v_append_phase
        )
    )
    ON CONFLICT (lifecycle_key) DO NOTHING;

    SELECT * INTO v_lifecycle
    FROM public.settlement_lifecycle
    WHERE lifecycle_key = v_lifecycle_key
    FOR UPDATE;

    SELECT EXISTS (
        SELECT 1
        FROM public.ledger_append_markers lam
        WHERE lam.append_key = v_append_key
           OR (lam.transaction_id = p_tx_id AND lam.append_phase = v_append_phase)
    ) INTO v_append_applied;

    IF LOWER(COALESCE(v_tx.status, '')) = 'completed'
       OR COALESCE(v_lifecycle.status, '') = 'COMPLETED'
       OR COALESCE(v_lifecycle.stage, '') = 'SETTLED' THEN
        UPDATE public.settlement_lifecycle
        SET
            stage = 'SETTLED',
            status = 'COMPLETED',
            settled_at = COALESCE(settled_at, v_now),
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                'append_key', v_append_key,
                'append_phase', v_append_phase,
                'append_applied', v_append_applied,
                'last_completion_check_at', v_now
            )
        WHERE id = v_lifecycle.id;

        RETURN QUERY
        SELECT
            p_tx_id,
            v_lifecycle.id,
            v_append_key,
            v_append_phase,
            COALESCE(v_lifecycle.metadata->>'worker_claim_id', v_claim_id),
            v_tx.status,
            'SETTLED',
            'COMPLETED',
            v_append_applied,
            TRUE;
        RETURN;
    END IF;

    IF LOWER(COALESCE(v_tx.status, '')) <> 'processing' THEN
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Transaction % is %, expected processing under settlement lock', p_tx_id, v_tx.status;
    END IF;

    v_existing_claim_id := NULLIF(v_lifecycle.metadata->>'worker_claim_id', '');
    IF COALESCE(v_lifecycle.stage, '') = 'PROCESSING'
       AND v_existing_claim_id IS NOT NULL
       AND v_existing_claim_id <> v_claim_id
       AND v_lifecycle.processing_at IS NOT NULL
       AND v_lifecycle.processing_at > (v_now - INTERVAL '5 minutes') THEN
        RAISE EXCEPTION 'CONCURRENCY_CONFLICT: Settlement % is already claimed by another worker', p_tx_id;
    END IF;

    UPDATE public.settlement_lifecycle
    SET
        transaction_id = p_tx_id,
        rail = 'SOVEREIGN_LEDGER',
        direction = 'INTERNAL',
        operation_type = 'INTERNAL_TRANSFER',
        currency = COALESCE(v_lifecycle.currency, v_tx.currency, 'TZS'),
        stage = 'PROCESSING',
        status = 'ACTIVE',
        processing_at = v_now,
        last_error = NULL,
        metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
            'worker_id', p_worker_id,
            'worker_claim_id', v_claim_id,
            'worker_claimed_at', v_now,
            'append_key', v_append_key,
            'append_phase', v_append_phase,
            'append_applied', v_append_applied,
            'settlement_model', 'INTERNAL_PAYSAFE_VAULT',
            'preconditions_verified_at', v_now,
            'tx_status_verified_under_lock', v_tx.status
        )
    WHERE id = v_lifecycle.id;

    RETURN QUERY
    SELECT
        p_tx_id,
        v_lifecycle.id,
        v_append_key,
        v_append_phase,
        v_claim_id,
        v_tx.status,
        'PROCESSING',
        'ACTIVE',
        v_append_applied,
        FALSE;
END;
$$;

COMMENT ON FUNCTION public.claim_internal_transfer_settlement(UUID, TEXT, TEXT)
IS 'Claims an internal transfer settlement under a transaction row lock, records a durable worker claim/idempotency marker, verifies the transaction is still processing, and checks whether the settlement append marker was already applied. Enterprise repair/worker path only; not for client-facing flow.';

CREATE OR REPLACE FUNCTION public.complete_internal_transfer_settlement(
    p_tx_id UUID,
    p_worker_claim_id TEXT,
    p_result TEXT DEFAULT 'COMPLETED',
    p_result_note TEXT DEFAULT NULL,
    p_zero_sum_valid BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    transaction_id UUID,
    previous_status TEXT,
    final_status TEXT,
    lifecycle_stage TEXT,
    lifecycle_status TEXT,
    already_finalized BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tx public.transactions%ROWTYPE;
    v_lifecycle public.settlement_lifecycle%ROWTYPE;
    v_now TIMESTAMP WITH TIME ZONE := NOW();
    v_result TEXT := UPPER(COALESCE(NULLIF(BTRIM(p_result), ''), 'COMPLETED'));
    v_lifecycle_key TEXT := 'INTERNAL_TRANSFER:' || p_tx_id::TEXT || ':PAYSAFE_SETTLEMENT';
    v_append_key TEXT := 'settlement:' || p_tx_id::TEXT || ':paysafe_release:v2';
    v_append_phase TEXT := 'PAYSAFE_SETTLEMENT';
BEGIN
    IF NULLIF(BTRIM(p_worker_claim_id), '') IS NULL THEN
        RAISE EXCEPTION 'WORKER_CLAIM_REQUIRED: complete_internal_transfer_settlement requires the active worker claim id';
    END IF;

    SELECT * INTO v_tx
    FROM public.transactions
    WHERE id = p_tx_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Transaction % was not found for settlement completion', p_tx_id;
    END IF;

    SELECT * INTO v_lifecycle
    FROM public.settlement_lifecycle
    WHERE lifecycle_key = v_lifecycle_key
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Settlement lifecycle % was not found', v_lifecycle_key;
    END IF;

    IF LOWER(COALESCE(v_tx.status, '')) = 'completed'
       OR COALESCE(v_lifecycle.status, '') = 'COMPLETED'
       OR COALESCE(v_lifecycle.stage, '') = 'SETTLED' THEN
        UPDATE public.settlement_lifecycle
        SET
            stage = 'SETTLED',
            status = 'COMPLETED',
            settled_at = COALESCE(settled_at, v_now),
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                'append_key', v_append_key,
                'append_phase', v_append_phase,
                'append_applied', TRUE,
                'completed_at', v_now
            )
        WHERE id = v_lifecycle.id;

        RETURN QUERY
        SELECT
            p_tx_id,
            v_tx.status,
            'completed',
            'SETTLED',
            'COMPLETED',
            TRUE;
        RETURN;
    END IF;

    IF COALESCE(v_lifecycle.metadata->>'worker_claim_id', '') <> p_worker_claim_id THEN
        RAISE EXCEPTION 'CONCURRENCY_CONFLICT: Settlement % completion attempted with stale worker claim', p_tx_id;
    END IF;

    IF COALESCE(v_lifecycle.stage, '') <> 'PROCESSING' THEN
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Settlement % is %, expected PROCESSING before completion', p_tx_id, v_lifecycle.stage;
    END IF;

    IF v_result = 'COMPLETED' AND NOT p_zero_sum_valid THEN
        v_result := 'HELD_FOR_REVIEW';
    END IF;

    IF v_result = 'COMPLETED' THEN
        IF LOWER(COALESCE(v_tx.status, '')) <> 'processing' THEN
            RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Transaction % is %, expected processing before settlement completion', p_tx_id, v_tx.status;
        END IF;

        UPDATE public.transactions
        SET
            status = 'completed',
            status_notes = COALESCE(NULLIF(BTRIM(p_result_note), ''), 'Settlement finalized by processor.'),
            updated_at = v_now
        WHERE id = p_tx_id;

        UPDATE public.settlement_lifecycle
        SET
            stage = 'SETTLED',
            status = 'COMPLETED',
            settled_at = v_now,
            last_error = NULL,
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                'append_key', v_append_key,
                'append_phase', v_append_phase,
                'append_applied', TRUE,
                'completed_at', v_now,
                'completion_result', 'COMPLETED'
            )
        WHERE id = v_lifecycle.id;

        RETURN QUERY
        SELECT
            p_tx_id,
            v_tx.status,
            'completed',
            'SETTLED',
            'COMPLETED',
            FALSE;
        RETURN;
    ELSIF v_result = 'HELD_FOR_REVIEW' THEN
        IF LOWER(COALESCE(v_tx.status, '')) = 'processing' THEN
            UPDATE public.transactions
            SET
                status = 'held_for_review',
                status_notes = COALESCE(NULLIF(BTRIM(p_result_note), ''), 'Settlement moved to held_for_review.'),
                updated_at = v_now
            WHERE id = p_tx_id;
        END IF;

        UPDATE public.settlement_lifecycle
        SET
            stage = 'FAILED',
            status = 'FAILED',
            failed_at = v_now,
            last_error = COALESCE(NULLIF(BTRIM(p_result_note), ''), 'HELD_FOR_REVIEW'),
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                'append_key', v_append_key,
                'append_phase', v_append_phase,
                'completion_result', 'HELD_FOR_REVIEW',
                'held_for_review_at', v_now,
                'zero_sum_valid', FALSE
            )
        WHERE id = v_lifecycle.id;

        RETURN QUERY
        SELECT
            p_tx_id,
            v_tx.status,
            'held_for_review',
            'FAILED',
            'FAILED',
            FALSE;
        RETURN;
    ELSE
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Unsupported settlement completion result %', v_result;
    END IF;
END;
$$;

COMMENT ON FUNCTION public.complete_internal_transfer_settlement(UUID, TEXT, TEXT, TEXT, BOOLEAN)
IS 'Completes an internal transfer settlement under lock using the active worker claim id. It finalizes transaction status only after append/idempotency preconditions were established and records durable lifecycle metadata. Worker path only.';

CREATE TABLE IF NOT EXISTS public.merchant_fees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE UNIQUE,
    transaction_fee_percent NUMERIC DEFAULT 0.01,
    fixed_fee NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchants' AND column_name='owner_user_id') THEN
        ALTER TABLE public.merchants ADD COLUMN owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_wallets' AND column_name='owner_user_id') THEN
        ALTER TABLE public.merchant_wallets ADD COLUMN owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_wallets' AND column_name='base_wallet_id') THEN
        ALTER TABLE public.merchant_wallets ADD COLUMN base_wallet_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_wallets' AND column_name='wallet_type') THEN
        ALTER TABLE public.merchant_wallets ADD COLUMN wallet_type TEXT DEFAULT 'operating';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_wallets' AND column_name='is_primary') THEN
        ALTER TABLE public.merchant_wallets ADD COLUMN is_primary BOOLEAN DEFAULT FALSE;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.agents (
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

CREATE TABLE IF NOT EXISTS public.agent_wallets (
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

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agents' AND column_name='service_pay_number') THEN
        ALTER TABLE public.agents ADD COLUMN service_pay_number TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agents' AND column_name='cash_withdraw_till') THEN
        ALTER TABLE public.agents ADD COLUMN cash_withdraw_till TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agents' AND column_name='service_wallet_id') THEN
        ALTER TABLE public.agents ADD COLUMN service_wallet_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agents' AND column_name='commission_wallet_id') THEN
        ALTER TABLE public.agents ADD COLUMN commission_wallet_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_wallets' AND column_name='owner_user_id') THEN
        ALTER TABLE public.agent_wallets ADD COLUMN owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_wallets' AND column_name='base_wallet_id') THEN
        ALTER TABLE public.agent_wallets ADD COLUMN base_wallet_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_wallets' AND column_name='wallet_type') THEN
        ALTER TABLE public.agent_wallets ADD COLUMN wallet_type TEXT DEFAULT 'operating';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_wallets' AND column_name='is_primary') THEN
        ALTER TABLE public.agent_wallets ADD COLUMN is_primary BOOLEAN DEFAULT FALSE;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_service_pay_number
    ON public.agents(service_pay_number)
    WHERE service_pay_number IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_cash_withdraw_till
    ON public.agents(cash_withdraw_till)
    WHERE cash_withdraw_till IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.merchant_transactions (
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

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_transactions' AND column_name='owner_user_id') THEN
        ALTER TABLE public.merchant_transactions ADD COLUMN owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_transactions' AND column_name='customer_user_id') THEN
        ALTER TABLE public.merchant_transactions ADD COLUMN customer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.agent_transactions (
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

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_transactions' AND column_name='owner_user_id') THEN
        ALTER TABLE public.agent_transactions ADD COLUMN owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_transactions' AND column_name='customer_user_id') THEN
        ALTER TABLE public.agent_transactions ADD COLUMN customer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.service_actor_customer_links (
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

CREATE TABLE IF NOT EXISTS public.service_commissions (
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

CREATE TABLE IF NOT EXISTS public.service_access_requests (
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

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'service_access_requests'
          AND column_name = 'current_role'
    ) THEN
        ALTER TABLE public.service_access_requests
            RENAME COLUMN "current_role" TO current_user_role;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'service_access_requests'
          AND column_name = 'current_registry_type'
    ) THEN
        ALTER TABLE public.service_access_requests
            RENAME COLUMN "current_registry_type" TO current_user_registry_type;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'service_access_requests'
          AND column_name = 'current_user_role'
    ) THEN
        ALTER TABLE public.service_access_requests
            ADD COLUMN current_user_role TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'service_access_requests'
          AND column_name = 'current_user_registry_type'
    ) THEN
        ALTER TABLE public.service_access_requests
            ADD COLUMN current_user_registry_type TEXT;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_merchants_owner ON public.merchants(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_merchant_wallets_merchant ON public.merchant_wallets(merchant_id);
CREATE INDEX IF NOT EXISTS idx_merchant_wallets_owner_user ON public.merchant_wallets(owner_user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_service_actor_customer_unique
    ON public.service_actor_customer_links(actor_user_id, customer_user_id);
CREATE INDEX IF NOT EXISTS idx_agents_user ON public.agents(user_id);
CREATE INDEX IF NOT EXISTS idx_agent_wallets_agent ON public.agent_wallets(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_wallets_owner_user ON public.agent_wallets(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_merchant_transactions_owner ON public.merchant_transactions(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_merchant_transactions_customer ON public.merchant_transactions(customer_user_id);
CREATE INDEX IF NOT EXISTS idx_agent_transactions_owner ON public.agent_transactions(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_agent_transactions_customer ON public.agent_transactions(customer_user_id);
CREATE INDEX IF NOT EXISTS idx_service_links_actor ON public.service_actor_customer_links(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_service_links_customer ON public.service_actor_customer_links(customer_user_id);
CREATE INDEX IF NOT EXISTS idx_service_commissions_actor ON public.service_commissions(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_service_commissions_source_tx ON public.service_commissions(source_transaction_id);
CREATE INDEX IF NOT EXISTS idx_service_access_requests_user ON public.service_access_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_service_access_requests_status ON public.service_access_requests(status);
CREATE INDEX IF NOT EXISTS idx_service_access_requests_role ON public.service_access_requests(requested_role);

CREATE TABLE IF NOT EXISTS public.regulatory_config (
    id TEXT PRIMARY KEY, 
    vat_rate NUMERIC DEFAULT 0.05, 
    service_fee_rate NUMERIC DEFAULT 0.01, 
    gov_fee_rate NUMERIC DEFAULT 0.005, 
    stamp_duty_fixed NUMERIC DEFAULT 1.0, 
    is_active BOOLEAN DEFAULT TRUE, 
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), 
    updated_by TEXT
);

CREATE TABLE IF NOT EXISTS public.transfer_tax_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    rate NUMERIC NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.kyc_requests (
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

CREATE TABLE IF NOT EXISTS public.user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL,
    -- Stable device fingerprint for password and biometric/passkey sessions.
    device_fingerprint TEXT,
    ip_address TEXT,
    -- Canonical synthesized device/user-agent label used by security analytics.
    user_agent TEXT,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_active_at TIMESTAMPTZ DEFAULT NOW(),
    replaced_by TEXT,
    is_trusted_device BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS public.user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    -- Stable hardware-ish fingerprint. Do not derive from locale/app version.
    device_fingerprint TEXT NOT NULL,
    -- Human-readable device name shown in security views and alerts.
    device_name TEXT,
    -- Expected values include mobile / android / ios / web / desktop.
    device_type TEXT,
    -- Canonical synthesized device/user-agent label used by security analytics.
    user_agent TEXT,
    last_active_at TIMESTAMPTZ DEFAULT NOW(),
    is_trusted BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, device_fingerprint)
);

-- Biometric/passkey and password-login compatibility hardening for existing databases.
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS device_name TEXT;
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS device_type TEXT;
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS is_trusted BOOLEAN DEFAULT FALSE;
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';

ALTER TABLE public.user_sessions
    ADD COLUMN IF NOT EXISTS device_fingerprint TEXT;
ALTER TABLE public.user_sessions
    ADD COLUMN IF NOT EXISTS ip_address TEXT;
ALTER TABLE public.user_sessions
    ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE public.user_sessions
    ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE public.user_sessions
    ADD COLUMN IF NOT EXISTS is_trusted_device BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS public.user_pin_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    device_fingerprint TEXT NOT NULL,
    pin_hash TEXT NOT NULL,
    parent_type TEXT DEFAULT 'biometric',
    source TEXT DEFAULT 'enroll',
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_biometric_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, device_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_user_pin_credentials_user
    ON public.user_pin_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_user_pin_credentials_user_device
    ON public.user_pin_credentials(user_id, device_fingerprint);

CREATE TABLE IF NOT EXISTS public.user_documents (
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

CREATE TABLE IF NOT EXISTS public.fee_collector_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fee_type TEXT NOT NULL UNIQUE,
    vault_id UUID REFERENCES public.platform_vaults(id) ON DELETE CASCADE,
    external_bank_account_id TEXT,
    balance NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.system_nodes (node_type TEXT PRIMARY KEY, vault_id UUID NOT NULL, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.chargeback_cases (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.payment_reviews (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.payment_metrics_snapshots (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.transaction_status_logs (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.ctr_reports (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.system_catalog (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.reported_issues (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.ai_reports (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.rule_violations (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.security_rules (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.support_tickets (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.staff_issues (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.approval_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    type TEXT NOT NULL, 
    target_id UUID NOT NULL, 
    requester_id UUID REFERENCES auth.users(id) ON DELETE CASCADE, 
    organization_id UUID REFERENCES public.organizations(id),
    policy_id UUID REFERENCES public.treasury_policies(id),
    status TEXT DEFAULT 'PENDING', 
    metadata JSONB, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS public.legal_holds (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), target_type TEXT NOT NULL, target_id UUID NOT NULL, reason TEXT, active BOOLEAN DEFAULT TRUE, issued_by TEXT, issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), released_at TIMESTAMP WITH TIME ZONE);
CREATE TABLE IF NOT EXISTS public.infra_system_matrix (config_key TEXT PRIMARY KEY, config_data JSONB NOT NULL, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), updated_by TEXT);
CREATE TABLE IF NOT EXISTS public.infra_app_tokens (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, app_id TEXT UNIQUE NOT NULL, app_token TEXT NOT NULL, tier TEXT NOT NULL, status TEXT DEFAULT 'ACTIVE', created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.infra_tx_limits (id TEXT PRIMARY KEY, max_per_transaction NUMERIC, max_daily_total NUMERIC, max_monthly_total NUMERIC, category_limits JSONB, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), updated_by TEXT);
CREATE TABLE IF NOT EXISTS public.infra_snapshots (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), actor_id TEXT, snapshot_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.platform_configs (config_key TEXT PRIMARY KEY, config_data JSONB NOT NULL, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), updated_by TEXT);
CREATE TABLE IF NOT EXISTS public.app_registry (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, app_id TEXT UNIQUE NOT NULL, app_token TEXT NOT NULL, tier TEXT NOT NULL, status TEXT DEFAULT 'ACTIVE', developer_id TEXT, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());

CREATE TABLE IF NOT EXISTS public.fee_correction_rules (
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

CREATE TABLE IF NOT EXISTS public.fee_correction_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id),
    original_fee_amount NUMERIC,
    corrected_fee_amount NUMERIC,
    correction_rule_id UUID REFERENCES public.fee_correction_rules(id),
    reason TEXT,
    corrected_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.item_reconciliation_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id UUID REFERENCES public.platform_vaults(id) ON DELETE CASCADE,
    partner_id TEXT,
    internal_balance NUMERIC DEFAULT 0,
    external_balance NUMERIC DEFAULT 0,
    discrepancy NUMERIC DEFAULT 0,
    status TEXT DEFAULT 'MATCHED',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.reconciliation_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL, -- INTERNAL, SYSTEM, EXTERNAL
    expected_balance NUMERIC NOT NULL,
    actual_balance NUMERIC NOT NULL,
    difference NUMERIC NOT NULL,
    status TEXT NOT NULL, -- MATCHED, MISMATCH, INVESTIGATING
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. CORE FUNCTIONS (REPLACEABLE)
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

CREATE OR REPLACE FUNCTION public.repair_wallet_balance_emergency(
    target_wallet_id UUID,
    new_balance NUMERIC,
    new_encrypted TEXT,
    repair_actor_id TEXT,
    repair_reason TEXT
)
RETURNS TABLE(entity_type TEXT, previous_balance NUMERIC, repaired_balance NUMERIC) AS $$
DECLARE
    resolved_role TEXT;
    previous_amount NUMERIC;
BEGIN
    IF new_balance IS NULL THEN
        RAISE EXCEPTION 'BALANCE_REQUIRED: repair_wallet_balance_emergency requires a numeric balance';
    END IF;

    IF NULLIF(BTRIM(COALESCE(repair_actor_id, '')), '') IS NULL THEN
        RAISE EXCEPTION 'REPAIR_ACTOR_REQUIRED: repair_wallet_balance_emergency requires an actor id';
    END IF;

    IF NULLIF(BTRIM(COALESCE(repair_reason, '')), '') IS NULL THEN
        RAISE EXCEPTION 'REPAIR_REASON_REQUIRED: repair_wallet_balance_emergency requires a human-readable reason';
    END IF;

    SELECT COALESCE(NULLIF(auth.role(), ''), public.get_auth_role()) INTO resolved_role;
    IF resolved_role IS NULL OR resolved_role NOT IN ('service_role', 'SUPER_ADMIN', 'ADMIN', 'AUDIT') THEN
        RAISE EXCEPTION 'PRIVILEGED_REPAIR_ONLY: repair_wallet_balance_emergency is restricted to emergency reconciliation and incident repair';
    END IF;

    SELECT w.balance
      INTO previous_amount
      FROM public.wallets w
     WHERE w.id = target_wallet_id
       AND NOT (
            COALESCE(w.is_locked, FALSE)
            OR lower(COALESCE(w.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
       )
     FOR UPDATE;

    IF FOUND THEN
        UPDATE public.wallets
           SET balance = new_balance
         WHERE id = target_wallet_id;

        INSERT INTO public.audit_trail (
            event_type,
            actor_id,
            transaction_id,
            action,
            metadata,
            hash,
            signature
        )
        VALUES (
            'FINANCIAL',
            repair_actor_id,
            target_wallet_id::TEXT,
            'EMERGENCY_BALANCE_REPAIR',
            jsonb_build_object(
                'tool', 'repair_wallet_balance_emergency',
                'entity_type', 'wallet',
                'target_wallet_id', target_wallet_id,
                'previous_balance', previous_amount,
                'new_balance', new_balance,
                'reason', repair_reason,
                'warning', 'Privileged repair-only reconciliation. Never call from normal financial flow.'
            ),
            md5(gen_random_uuid()::TEXT || clock_timestamp()::TEXT),
            'repair_tool'
        );

        RETURN QUERY SELECT 'wallet'::TEXT, previous_amount, new_balance;
        RETURN;
    END IF;

    SELECT pv.balance
      INTO previous_amount
      FROM public.platform_vaults pv
     WHERE pv.id = target_wallet_id
       AND NOT (
            COALESCE(pv.is_locked, FALSE)
            OR lower(COALESCE(pv.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
       )
     FOR UPDATE;

    IF FOUND THEN
        UPDATE public.platform_vaults
           SET balance = new_balance,
               encrypted_balance = COALESCE(new_encrypted, encrypted_balance)
         WHERE id = target_wallet_id;

        INSERT INTO public.audit_trail (
            event_type,
            actor_id,
            transaction_id,
            action,
            metadata,
            hash,
            signature
        )
        VALUES (
            'FINANCIAL',
            repair_actor_id,
            target_wallet_id::TEXT,
            'EMERGENCY_BALANCE_REPAIR',
            jsonb_build_object(
                'tool', 'repair_wallet_balance_emergency',
                'entity_type', 'platform_vault',
                'target_wallet_id', target_wallet_id,
                'previous_balance', previous_amount,
                'new_balance', new_balance,
                'reason', repair_reason,
                'warning', 'Privileged repair-only reconciliation. Never call from normal financial flow.'
            ),
            md5(gen_random_uuid()::TEXT || clock_timestamp()::TEXT),
            'repair_tool'
        );

        RETURN QUERY SELECT 'platform_vault'::TEXT, previous_amount, new_balance;
        RETURN;
    END IF;

    SELECT g.current
      INTO previous_amount
      FROM public.goals g
     WHERE g.id = target_wallet_id
     FOR UPDATE;

    IF FOUND THEN
        UPDATE public.goals
           SET current = new_balance,
               updated_at = NOW()
         WHERE id = target_wallet_id;

        INSERT INTO public.audit_trail (
            event_type,
            actor_id,
            transaction_id,
            action,
            metadata,
            hash,
            signature
        )
        VALUES (
            'FINANCIAL',
            repair_actor_id,
            target_wallet_id::TEXT,
            'EMERGENCY_BALANCE_REPAIR',
            jsonb_build_object(
                'tool', 'repair_wallet_balance_emergency',
                'entity_type', 'goal',
                'target_wallet_id', target_wallet_id,
                'previous_balance', previous_amount,
                'new_balance', new_balance,
                'reason', repair_reason,
                'warning', 'Privileged repair-only reconciliation. Never call from normal financial flow.'
            ),
            md5(gen_random_uuid()::TEXT || clock_timestamp()::TEXT),
            'repair_tool'
        );

        RETURN QUERY SELECT 'goal'::TEXT, previous_amount, new_balance;
        RETURN;
    END IF;

    RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not found or is locked', target_wallet_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

COMMENT ON FUNCTION public.repair_wallet_balance_emergency(UUID, NUMERIC, TEXT, TEXT, TEXT)
IS 'EMERGENCY REPAIR TOOL ONLY. Allowed only for privileged reconciliation, incident repair, or auditor-approved cache repair after ledger truth is independently verified. Requires actor id and human-readable reason. Must never be called from normal payment, transfer, settlement, wealth, or wallet mutation flows.';

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
    v_lock_target RECORD;
    v_update_target RECORD;
    v_leg_wallet_id UUID;
    v_leg_entity_type TEXT;
    v_leg_amount NUMERIC;
    v_current_balance NUMERIC;
    v_next_balance NUMERIC;
    v_total_credits NUMERIC := 0;
    v_total_debits NUMERIC := 0;
    v_balance_map JSONB := '{}'::jsonb;
    v_entity_type_map JSONB := '{}'::jsonb;
    v_effective_reference_id TEXT;
BEGIN
    IF p_legs IS NULL OR jsonb_typeof(p_legs) <> 'array' OR jsonb_array_length(p_legs) = 0 THEN
        RAISE EXCEPTION 'LEDGER_LEGS_REQUIRED: post_transaction_v2 requires at least one ledger leg';
    END IF;

    v_effective_reference_id := COALESCE(NULLIF(BTRIM(p_reference_id), ''), p_tx_id::TEXT);

    FOR v_lock_target IN
        WITH leg_ids AS (
            SELECT DISTINCT (leg_item->>'wallet_id')::UUID AS entity_id
            FROM jsonb_array_elements(p_legs) AS leg_item
            WHERE NULLIF(leg_item->>'wallet_id', '') IS NOT NULL
        ),
        header_ids AS (
            SELECT DISTINCT x.entity_id
            FROM (
                SELECT p_wallet_id AS entity_id
                UNION ALL
                SELECT p_to_wallet_id AS entity_id
            ) x
            WHERE x.entity_id IS NOT NULL
              AND (
                    EXISTS (SELECT 1 FROM public.wallets w WHERE w.id = x.entity_id)
                 OR EXISTS (SELECT 1 FROM public.platform_vaults pv WHERE pv.id = x.entity_id)
                 OR EXISTS (SELECT 1 FROM public.goals g WHERE g.id = x.entity_id)
              )
        ),
        raw_ids AS (
            SELECT entity_id FROM leg_ids
            UNION
            SELECT entity_id FROM header_ids
        ),
        resolved AS (
            SELECT
                r.entity_id,
                CASE
                    WHEN w.id IS NOT NULL THEN 'wallet'
                    WHEN pv.id IS NOT NULL THEN 'vault'
                    WHEN g.id IS NOT NULL THEN 'goal'
                    ELSE NULL
                END AS entity_type,
                (CASE WHEN w.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN pv.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN g.id IS NOT NULL THEN 1 ELSE 0 END) AS match_count
            FROM raw_ids r
            LEFT JOIN public.wallets w ON w.id = r.entity_id
            LEFT JOIN public.platform_vaults pv ON pv.id = r.entity_id
            LEFT JOIN public.goals g ON g.id = r.entity_id
        )
        SELECT entity_id, entity_type, match_count
        FROM resolved
        ORDER BY entity_type, entity_id
    LOOP
        IF v_lock_target.match_count = 0 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not found', v_lock_target.entity_id;
        END IF;

        IF v_lock_target.match_count > 1 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_AMBIGUOUS: Internal entity % resolves to multiple tables', v_lock_target.entity_id;
        END IF;

        IF v_lock_target.entity_type = 'wallet' THEN
            SELECT balance
              INTO v_current_balance
              FROM public.wallets w
             WHERE w.id = v_lock_target.entity_id
               AND NOT (
                    COALESCE(w.is_locked, FALSE)
                    OR lower(COALESCE(w.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
               )
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'WALLET_LOCKED: Wallet % is locked or unavailable', v_lock_target.entity_id;
            END IF;
        ELSIF v_lock_target.entity_type = 'vault' THEN
            SELECT balance
              INTO v_current_balance
              FROM public.platform_vaults pv
             WHERE pv.id = v_lock_target.entity_id
               AND NOT (
                    COALESCE(pv.is_locked, FALSE)
                    OR lower(COALESCE(pv.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
               )
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'WALLET_LOCKED: Vault % is locked or unavailable', v_lock_target.entity_id;
            END IF;
        ELSIF v_lock_target.entity_type = 'goal' THEN
            SELECT current
              INTO v_current_balance
              FROM public.goals g
             WHERE g.id = v_lock_target.entity_id
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'GOAL_MISSING: Goal % is unavailable', v_lock_target.entity_id;
            END IF;
        ELSE
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not found', v_lock_target.entity_id;
        END IF;

        v_balance_map := jsonb_set(
            v_balance_map,
            ARRAY[v_lock_target.entity_id::TEXT],
            to_jsonb(COALESCE(v_current_balance, 0)),
            TRUE
        );
        v_entity_type_map := jsonb_set(
            v_entity_type_map,
            ARRAY[v_lock_target.entity_id::TEXT],
            to_jsonb(v_lock_target.entity_type),
            TRUE
        );
    END LOOP;

    BEGIN
        INSERT INTO public.transactions (
            id,
            reference_id,
            user_id,
            wallet_id,
            to_wallet_id,
            amount,
            description,
            type,
            status,
            date,
            metadata,
            category_id
        ) VALUES (
            p_tx_id,
            v_effective_reference_id,
            p_user_id,
            p_wallet_id,
            p_to_wallet_id,
            p_amount,
            p_description,
            p_type,
            p_status,
            p_date,
            COALESCE(p_metadata, '{}'::jsonb),
            p_category_id
        );
    EXCEPTION
        WHEN unique_violation THEN
            IF EXISTS (
                SELECT 1
                FROM public.transactions t
                WHERE t.reference_id = v_effective_reference_id
            ) THEN
                RAISE EXCEPTION 'IDEMPOTENCY_VIOLATION: Transaction with reference % already exists', v_effective_reference_id;
            END IF;
            RAISE;
    END;

    -- Compatibility note:
    --   * leg.balance_before is ignored as authoritative; SQL re-reads the locked row state.
    --   * leg.balance_after is ignored; SQL computes the next balance internally.
    --   * leg.balance_after_encrypted is ignored; SQL writes SQL-computed plaintext balance_after.
    --   * leg.amount remains the stored payload for financial_ledger.amount.
    --   * leg.amount_plain is the authoritative arithmetic input when supplied. If absent,
    --     SQL only accepts leg.amount when it is already a numeric plaintext value.
    FOR leg IN SELECT * FROM jsonb_array_elements(p_legs)
    LOOP
        v_leg_wallet_id := (leg->>'wallet_id')::UUID;

        IF v_leg_wallet_id IS NULL THEN
            RAISE EXCEPTION 'LEDGER_LEG_WALLET_REQUIRED: Each leg must include wallet_id';
        END IF;

        v_leg_entity_type := v_entity_type_map->>v_leg_wallet_id::TEXT;
        IF v_leg_entity_type IS NULL THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not locked for this transaction', v_leg_wallet_id;
        END IF;

        IF NULLIF(BTRIM(leg->>'amount_plain'), '') IS NOT NULL THEN
            v_leg_amount := (leg->>'amount_plain')::NUMERIC;
        ELSIF NULLIF(BTRIM(leg->>'amount'), '') ~ '^-?[0-9]+(\.[0-9]+)?$' THEN
            v_leg_amount := (leg->>'amount')::NUMERIC;
        ELSE
            RAISE EXCEPTION 'LEG_AMOUNT_REQUIRED: Leg for % must include numeric amount_plain when amount is encrypted', v_leg_wallet_id;
        END IF;

        IF v_leg_amount <= 0 THEN
            RAISE EXCEPTION 'LEG_AMOUNT_INVALID: Leg for % must have a positive amount', v_leg_wallet_id;
        END IF;

        v_current_balance := COALESCE((v_balance_map->>v_leg_wallet_id::TEXT)::NUMERIC, 0);

        CASE UPPER(COALESCE(leg->>'entry_type', ''))
            WHEN 'CREDIT' THEN
                v_next_balance := ROUND((v_current_balance + v_leg_amount)::NUMERIC, 4);
                v_total_credits := v_total_credits + v_leg_amount;
            WHEN 'DEBIT' THEN
                v_next_balance := ROUND((v_current_balance - v_leg_amount)::NUMERIC, 4);
                v_total_debits := v_total_debits + v_leg_amount;
                IF v_next_balance < 0 THEN
                    RAISE EXCEPTION 'INSUFFICIENT_FUNDS: Internal entity % would go negative', v_leg_wallet_id;
                END IF;
            ELSE
                RAISE EXCEPTION 'LEDGER_ENTRY_TYPE_INVALID: Leg for % must be CREDIT or DEBIT', v_leg_wallet_id;
        END CASE;

        INSERT INTO public.financial_ledger (
            id,
            transaction_id,
            user_id,
            wallet_id,
            entry_type,
            amount,
            balance_after,
            balance_after_encrypted,
            description
        ) VALUES (
            gen_random_uuid(),
            p_tx_id,
            p_user_id,
            v_leg_wallet_id,
            UPPER(leg->>'entry_type'),
            leg->>'amount',
            v_next_balance::TEXT,
            NULL,
            leg->>'description'
        );

        v_balance_map := jsonb_set(
            v_balance_map,
            ARRAY[v_leg_wallet_id::TEXT],
            to_jsonb(v_next_balance),
            TRUE
        );
    END LOOP;

    IF ROUND(ABS(v_total_credits - v_total_debits)::NUMERIC, 4) <> 0 THEN
        RAISE EXCEPTION 'LEDGER_OUT_OF_BALANCE: credits % do not equal debits %', v_total_credits, v_total_debits;
    END IF;

    FOR v_update_target IN
        WITH leg_ids AS (
            SELECT DISTINCT (leg_item->>'wallet_id')::UUID AS entity_id
            FROM jsonb_array_elements(p_legs) AS leg_item
            WHERE NULLIF(leg_item->>'wallet_id', '') IS NOT NULL
        ),
        header_ids AS (
            SELECT DISTINCT x.entity_id
            FROM (
                SELECT p_wallet_id AS entity_id
                UNION ALL
                SELECT p_to_wallet_id AS entity_id
            ) x
            WHERE x.entity_id IS NOT NULL
              AND (
                    EXISTS (SELECT 1 FROM public.wallets w WHERE w.id = x.entity_id)
                 OR EXISTS (SELECT 1 FROM public.platform_vaults pv WHERE pv.id = x.entity_id)
                 OR EXISTS (SELECT 1 FROM public.goals g WHERE g.id = x.entity_id)
              )
        ),
        raw_ids AS (
            SELECT entity_id FROM leg_ids
            UNION
            SELECT entity_id FROM header_ids
        ),
        resolved AS (
            SELECT
                r.entity_id,
                CASE
                    WHEN w.id IS NOT NULL THEN 'wallet'
                    WHEN pv.id IS NOT NULL THEN 'vault'
                    WHEN g.id IS NOT NULL THEN 'goal'
                    ELSE NULL
                END AS entity_type,
                (CASE WHEN w.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN pv.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN g.id IS NOT NULL THEN 1 ELSE 0 END) AS match_count
            FROM raw_ids r
            LEFT JOIN public.wallets w ON w.id = r.entity_id
            LEFT JOIN public.platform_vaults pv ON pv.id = r.entity_id
            LEFT JOIN public.goals g ON g.id = r.entity_id
        )
        SELECT entity_id, entity_type, match_count
        FROM resolved
        ORDER BY entity_type, entity_id
    LOOP
        IF v_update_target.match_count <> 1 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_AMBIGUOUS: Internal entity % resolves to % matches', v_update_target.entity_id, v_update_target.match_count;
        END IF;

        IF v_update_target.entity_type = 'wallet' THEN
            UPDATE public.wallets
               SET balance = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, balance)
             WHERE id = v_update_target.entity_id;
        ELSIF v_update_target.entity_type = 'vault' THEN
            UPDATE public.platform_vaults
               SET balance = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, balance)
             WHERE id = v_update_target.entity_id;
        ELSIF v_update_target.entity_type = 'goal' THEN
            UPDATE public.goals
               SET current = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, current),
                   updated_at = NOW()
             WHERE id = v_update_target.entity_id;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Atomic Append Ledger Legs RPC
CREATE OR REPLACE FUNCTION public.append_ledger_entries_v1(
    p_tx_id UUID,
    p_legs JSONB,
    p_append_key TEXT DEFAULT NULL,
    p_append_phase TEXT DEFAULT NULL
)
RETURNS void AS $$
DECLARE
    leg JSONB;
    v_lock_target RECORD;
    v_update_target RECORD;
    v_leg_wallet_id UUID;
    v_leg_entity_type TEXT;
    v_leg_amount NUMERIC;
    v_current_balance NUMERIC;
    v_next_balance NUMERIC;
    v_total_credits NUMERIC := 0;
    v_total_debits NUMERIC := 0;
    v_balance_map JSONB := '{}'::jsonb;
    v_entity_type_map JSONB := '{}'::jsonb;
    v_tx_user_id UUID;
BEGIN
    IF p_legs IS NULL OR jsonb_typeof(p_legs) <> 'array' OR jsonb_array_length(p_legs) = 0 THEN
        RAISE EXCEPTION 'LEDGER_LEGS_REQUIRED: append_ledger_entries_v1 requires at least one ledger leg';
    END IF;

    SELECT t.user_id
      INTO v_tx_user_id
      FROM public.transactions t
     WHERE t.id = p_tx_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'TRANSACTION_MISSING: Transaction % was not found', p_tx_id;
    END IF;

    IF NULLIF(BTRIM(COALESCE(p_append_key, '')), '') IS NOT NULL
       OR NULLIF(BTRIM(COALESCE(p_append_phase, '')), '') IS NOT NULL THEN
        BEGIN
            INSERT INTO public.ledger_append_markers (
                transaction_id,
                append_key,
                append_phase,
                metadata
            ) VALUES (
                p_tx_id,
                NULLIF(BTRIM(p_append_key), ''),
                NULLIF(BTRIM(p_append_phase), ''),
                jsonb_build_object(
                    'leg_count', jsonb_array_length(p_legs),
                    'registered_at', NOW(),
                    'append_phase', NULLIF(BTRIM(p_append_phase), ''),
                    'append_key', NULLIF(BTRIM(p_append_key), '')
                )
            );
        EXCEPTION
            WHEN unique_violation THEN
                RAISE EXCEPTION 'APPEND_ALREADY_APPLIED: transaction %, append_key %, append_phase %',
                    p_tx_id,
                    COALESCE(NULLIF(BTRIM(p_append_key), ''), '<null>'),
                    COALESCE(NULLIF(BTRIM(p_append_phase), ''), '<null>');
        END;
    END IF;

    FOR v_lock_target IN
        WITH leg_ids AS (
            SELECT DISTINCT (leg_item->>'wallet_id')::UUID AS entity_id
            FROM jsonb_array_elements(p_legs) AS leg_item
            WHERE NULLIF(leg_item->>'wallet_id', '') IS NOT NULL
        ),
        resolved AS (
            SELECT
                r.entity_id,
                CASE
                    WHEN w.id IS NOT NULL THEN 'wallet'
                    WHEN pv.id IS NOT NULL THEN 'vault'
                    WHEN g.id IS NOT NULL THEN 'goal'
                    ELSE NULL
                END AS entity_type,
                (CASE WHEN w.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN pv.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN g.id IS NOT NULL THEN 1 ELSE 0 END) AS match_count
            FROM leg_ids r
            LEFT JOIN public.wallets w ON w.id = r.entity_id
            LEFT JOIN public.platform_vaults pv ON pv.id = r.entity_id
            LEFT JOIN public.goals g ON g.id = r.entity_id
        )
        SELECT entity_id, entity_type, match_count
        FROM resolved
        ORDER BY entity_type, entity_id
    LOOP
        IF v_lock_target.match_count = 0 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not found', v_lock_target.entity_id;
        END IF;

        IF v_lock_target.match_count > 1 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_AMBIGUOUS: Internal entity % resolves to multiple tables', v_lock_target.entity_id;
        END IF;

        IF v_lock_target.entity_type = 'wallet' THEN
            SELECT balance
              INTO v_current_balance
              FROM public.wallets w
             WHERE w.id = v_lock_target.entity_id
               AND NOT (
                    COALESCE(w.is_locked, FALSE)
                    OR lower(COALESCE(w.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
               )
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'WALLET_LOCKED: Wallet % is locked or unavailable', v_lock_target.entity_id;
            END IF;
        ELSIF v_lock_target.entity_type = 'vault' THEN
            SELECT balance
              INTO v_current_balance
              FROM public.platform_vaults pv
             WHERE pv.id = v_lock_target.entity_id
               AND NOT (
                    COALESCE(pv.is_locked, FALSE)
                    OR lower(COALESCE(pv.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
               )
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'WALLET_LOCKED: Vault % is locked or unavailable', v_lock_target.entity_id;
            END IF;
        ELSIF v_lock_target.entity_type = 'goal' THEN
            SELECT current
              INTO v_current_balance
              FROM public.goals g
             WHERE g.id = v_lock_target.entity_id
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'GOAL_MISSING: Goal % is unavailable', v_lock_target.entity_id;
            END IF;
        ELSE
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not found', v_lock_target.entity_id;
        END IF;

        v_balance_map := jsonb_set(
            v_balance_map,
            ARRAY[v_lock_target.entity_id::TEXT],
            to_jsonb(COALESCE(v_current_balance, 0)),
            TRUE
        );
        v_entity_type_map := jsonb_set(
            v_entity_type_map,
            ARRAY[v_lock_target.entity_id::TEXT],
            to_jsonb(v_lock_target.entity_type),
            TRUE
        );
    END LOOP;

    -- Compatibility note:
    --   * leg.balance_before is ignored as authoritative; SQL re-reads the locked row state.
    --   * leg.balance_after is ignored; SQL computes the next balance internally.
    --   * leg.balance_after_encrypted is ignored; SQL writes SQL-computed plaintext balance_after.
    --   * leg.amount remains the stored payload for financial_ledger.amount.
    --   * leg.amount_plain is the authoritative arithmetic input when supplied. If absent,
    --     SQL only accepts leg.amount when it is already a numeric plaintext value.
    FOR leg IN SELECT * FROM jsonb_array_elements(p_legs)
    LOOP
        v_leg_wallet_id := (leg->>'wallet_id')::UUID;

        IF v_leg_wallet_id IS NULL THEN
            RAISE EXCEPTION 'LEDGER_LEG_WALLET_REQUIRED: Each leg must include wallet_id';
        END IF;

        v_leg_entity_type := v_entity_type_map->>v_leg_wallet_id::TEXT;
        IF v_leg_entity_type IS NULL THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not locked for this append', v_leg_wallet_id;
        END IF;

        IF NULLIF(BTRIM(leg->>'amount_plain'), '') IS NOT NULL THEN
            v_leg_amount := (leg->>'amount_plain')::NUMERIC;
        ELSIF NULLIF(BTRIM(leg->>'amount'), '') ~ '^-?[0-9]+(\.[0-9]+)?$' THEN
            v_leg_amount := (leg->>'amount')::NUMERIC;
        ELSE
            RAISE EXCEPTION 'LEG_AMOUNT_REQUIRED: Leg for % must include numeric amount_plain when amount is encrypted', v_leg_wallet_id;
        END IF;

        IF v_leg_amount <= 0 THEN
            RAISE EXCEPTION 'LEG_AMOUNT_INVALID: Leg for % must have a positive amount', v_leg_wallet_id;
        END IF;

        v_current_balance := COALESCE((v_balance_map->>v_leg_wallet_id::TEXT)::NUMERIC, 0);

        CASE UPPER(COALESCE(leg->>'entry_type', ''))
            WHEN 'CREDIT' THEN
                v_next_balance := ROUND((v_current_balance + v_leg_amount)::NUMERIC, 4);
                v_total_credits := v_total_credits + v_leg_amount;
            WHEN 'DEBIT' THEN
                v_next_balance := ROUND((v_current_balance - v_leg_amount)::NUMERIC, 4);
                v_total_debits := v_total_debits + v_leg_amount;
                IF v_next_balance < 0 THEN
                    RAISE EXCEPTION 'INSUFFICIENT_FUNDS: Internal entity % would go negative', v_leg_wallet_id;
                END IF;
            ELSE
                RAISE EXCEPTION 'LEDGER_ENTRY_TYPE_INVALID: Leg for % must be CREDIT or DEBIT', v_leg_wallet_id;
        END CASE;

        INSERT INTO public.financial_ledger (
            id,
            transaction_id,
            user_id,
            wallet_id,
            entry_type,
            amount,
            balance_after,
            balance_after_encrypted,
            description
        ) VALUES (
            gen_random_uuid(),
            p_tx_id,
            v_tx_user_id,
            v_leg_wallet_id,
            UPPER(leg->>'entry_type'),
            leg->>'amount',
            v_next_balance::TEXT,
            NULL,
            leg->>'description'
        );

        v_balance_map := jsonb_set(
            v_balance_map,
            ARRAY[v_leg_wallet_id::TEXT],
            to_jsonb(v_next_balance),
            TRUE
        );
    END LOOP;

    IF ROUND(ABS(v_total_credits - v_total_debits)::NUMERIC, 4) <> 0 THEN
        RAISE EXCEPTION 'LEDGER_OUT_OF_BALANCE: credits % do not equal debits %', v_total_credits, v_total_debits;
    END IF;

    FOR v_update_target IN
        WITH leg_ids AS (
            SELECT DISTINCT (leg_item->>'wallet_id')::UUID AS entity_id
            FROM jsonb_array_elements(p_legs) AS leg_item
            WHERE NULLIF(leg_item->>'wallet_id', '') IS NOT NULL
        ),
        resolved AS (
            SELECT
                r.entity_id,
                CASE
                    WHEN w.id IS NOT NULL THEN 'wallet'
                    WHEN pv.id IS NOT NULL THEN 'vault'
                    WHEN g.id IS NOT NULL THEN 'goal'
                    ELSE NULL
                END AS entity_type,
                (CASE WHEN w.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN pv.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN g.id IS NOT NULL THEN 1 ELSE 0 END) AS match_count
            FROM leg_ids r
            LEFT JOIN public.wallets w ON w.id = r.entity_id
            LEFT JOIN public.platform_vaults pv ON pv.id = r.entity_id
            LEFT JOIN public.goals g ON g.id = r.entity_id
        )
        SELECT entity_id, entity_type, match_count
        FROM resolved
        ORDER BY entity_type, entity_id
    LOOP
        IF v_update_target.match_count <> 1 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_AMBIGUOUS: Internal entity % resolves to % matches', v_update_target.entity_id, v_update_target.match_count;
        END IF;

        IF v_update_target.entity_type = 'wallet' THEN
            UPDATE public.wallets
               SET balance = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, balance)
             WHERE id = v_update_target.entity_id;
        ELSIF v_update_target.entity_type = 'vault' THEN
            UPDATE public.platform_vaults
               SET balance = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, balance)
             WHERE id = v_update_target.entity_id;
        ELSIF v_update_target.entity_type = 'goal' THEN
            UPDATE public.goals
               SET current = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, current),
                   updated_at = NOW()
             WHERE id = v_update_target.entity_id;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.card_settle_v1(
    p_card_transaction_id TEXT,
    p_target_wallet_id UUID,
    p_fee_wallet_id UUID,
    p_fee_amount NUMERIC DEFAULT 0
)
RETURNS JSONB AS $$
DECLARE
    v_card_tx public.card_transactions%ROWTYPE;
    v_target_wallet public.wallets%ROWTYPE;
    v_fee_wallet public.wallets%ROWTYPE;
    v_fee_vault public.platform_vaults%ROWTYPE;
    v_financial_tx public.transactions%ROWTYPE;
    v_target_balance_after NUMERIC;
    v_fee_balance_before NUMERIC := 0;
    v_fee_balance_after NUMERIC := 0;
    v_reference_id TEXT;
BEGIN
    IF p_card_transaction_id IS NULL OR trim(p_card_transaction_id) = '' THEN
        RAISE EXCEPTION 'CARD_TRANSACTION_REQUIRED';
    END IF;
    IF p_target_wallet_id IS NULL THEN
        RAISE EXCEPTION 'TARGET_WALLET_REQUIRED';
    END IF;

    SELECT * INTO v_card_tx
      FROM public.card_transactions
     WHERE id = p_card_transaction_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'CARD_TRANSACTION_NOT_FOUND';
    END IF;
    IF upper(COALESCE(v_card_tx.status, '')) <> 'AUTHORIZED' THEN
        RAISE EXCEPTION 'CARD_TRANSACTION_NOT_AUTHORIZED';
    END IF;

    SELECT * INTO v_target_wallet
      FROM public.wallets
     WHERE id = p_target_wallet_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'TARGET_WALLET_NOT_FOUND';
    END IF;

    IF COALESCE(v_card_tx.amount, 0) <= 0 THEN
        RAISE EXCEPTION 'INVALID_CARD_SETTLEMENT_AMOUNT';
    END IF;
    IF COALESCE(p_fee_amount, 0) < 0 THEN
        RAISE EXCEPTION 'INVALID_FEE_AMOUNT';
    END IF;

    IF COALESCE(p_fee_amount, 0) > 0 THEN
        IF p_fee_wallet_id IS NULL THEN
            RAISE EXCEPTION 'SYSTEM_FEE_WALLET_REQUIRED';
        END IF;

        SELECT * INTO v_fee_wallet
          FROM public.wallets
         WHERE id = p_fee_wallet_id
         FOR UPDATE;

        IF NOT FOUND THEN
            SELECT * INTO v_fee_vault
              FROM public.platform_vaults
             WHERE id = p_fee_wallet_id
             FOR UPDATE;
        END IF;

        IF v_fee_wallet.id IS NULL AND v_fee_vault.id IS NULL THEN
            RAISE EXCEPTION 'SYSTEM_FEE_WALLET_NOT_FOUND';
        END IF;

        v_fee_balance_before := COALESCE(v_fee_wallet.balance, v_fee_vault.balance, 0);
        v_fee_balance_after := v_fee_balance_before + p_fee_amount;
    END IF;

    v_target_balance_after := COALESCE(v_target_wallet.balance, 0) + COALESCE(v_card_tx.amount, 0);
    v_reference_id := 'card_' || trim(p_card_transaction_id);

    INSERT INTO public.transactions (
        id, reference_id, user_id, wallet_id, to_wallet_id, amount, currency, description, type, status, date, metadata
    ) VALUES (
        gen_random_uuid(),
        v_reference_id,
        COALESCE(v_target_wallet.user_id, v_card_tx.user_id),
        NULL,
        v_target_wallet.id,
        v_card_tx.amount::text,
        upper(COALESCE(NULLIF(trim(v_card_tx.currency), ''), 'TZS')),
        'Card payment settlement - ' || p_card_transaction_id,
        'deposit',
        'completed',
        CURRENT_DATE,
        jsonb_build_object(
            'card_transaction_id', p_card_transaction_id,
            'source_wallet_type', 'EXTERNAL',
            'target_wallet_type', COALESCE(v_target_wallet.wallet_type, 'INTERNAL'),
            'settlement_path', 'SOVEREIGN_LEDGER',
            'fee_wallet_id', p_fee_wallet_id
        )
    )
    RETURNING * INTO v_financial_tx;

    INSERT INTO public.financial_ledger (
        id, transaction_id, user_id, wallet_id, entry_type, amount, balance_after, description
    ) VALUES (
        gen_random_uuid(),
        v_financial_tx.id,
        COALESCE(v_target_wallet.user_id, v_card_tx.user_id),
        v_target_wallet.id,
        'CREDIT',
        v_card_tx.amount::text,
        v_target_balance_after::text,
        'Card deposit - ' || p_card_transaction_id
    );

    IF COALESCE(p_fee_amount, 0) > 0 THEN
        INSERT INTO public.financial_ledger (
            id, transaction_id, user_id, wallet_id, entry_type, amount, balance_after, description
        ) VALUES (
            gen_random_uuid(),
            v_financial_tx.id,
            COALESCE(v_target_wallet.user_id, v_card_tx.user_id),
            COALESCE(v_fee_wallet.id, v_fee_vault.id),
            'CREDIT',
            p_fee_amount::text,
            v_fee_balance_after::text,
            'Card processor fee - ' || p_card_transaction_id
        );
    END IF;

    UPDATE public.wallets
       SET balance = v_target_balance_after,
           updated_at = NOW()
     WHERE id = v_target_wallet.id;

    IF COALESCE(p_fee_amount, 0) > 0 THEN
        IF v_fee_wallet.id IS NOT NULL THEN
            UPDATE public.wallets
               SET balance = v_fee_balance_after,
                   updated_at = NOW()
             WHERE id = v_fee_wallet.id;
        ELSE
            UPDATE public.platform_vaults
               SET balance = v_fee_balance_after,
                   updated_at = NOW()
             WHERE id = v_fee_vault.id;
        END IF;
    END IF;

    UPDATE public.card_transactions
       SET status = 'SETTLED',
           settled_at = NOW(),
           updated_at = NOW()
     WHERE id = p_card_transaction_id;

    RETURN jsonb_build_object(
        'success', true,
        'settlement_id', v_financial_tx.id,
        'transaction_id', p_card_transaction_id,
        'amount', COALESCE(v_card_tx.amount, 0),
        'fee', COALESCE(p_fee_amount, 0),
        'target_balance_after', v_target_balance_after,
        'fee_balance_after', v_fee_balance_after,
        'status', 'COMPLETED'
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.bill_reserve_adjust_v1(
    p_user_id UUID,
    p_reserve_id UUID,
    p_source_wallet_id UUID,
    p_amount NUMERIC,
    p_action TEXT,
    p_currency TEXT DEFAULT 'TZS',
    p_description TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb,
    p_desired_locked_balance NUMERIC DEFAULT NULL
)
RETURNS JSONB AS $$
DECLARE
    v_reserve public.bill_reserves%ROWTYPE;
    v_source_wallet public.wallets%ROWTYPE;
    v_source_vault public.platform_vaults%ROWTYPE;
    v_source_table TEXT;
    v_source_balance_before NUMERIC;
    v_source_balance_after NUMERIC;
    v_locked_balance_before NUMERIC;
    v_locked_balance_after NUMERIC;
    v_action TEXT := upper(COALESCE(trim(p_action), ''));
    v_tx public.transactions%ROWTYPE;
    v_reference_id TEXT := 'wealth_' || extract(epoch from now())::bigint || '_' || substr(md5(random()::text), 1, 8);
    v_source_wallet_role TEXT;
BEGIN
    IF p_reserve_id IS NULL THEN RAISE EXCEPTION 'BILL_RESERVE_REQUIRED'; END IF;
    IF p_source_wallet_id IS NULL THEN RAISE EXCEPTION 'SOURCE_WALLET_REQUIRED'; END IF;
    IF p_amount IS NULL OR p_amount < 0 THEN RAISE EXCEPTION 'INVALID_AMOUNT'; END IF;
    IF v_action NOT IN ('LOCK', 'RELEASE') THEN RAISE EXCEPTION 'INVALID_BILL_RESERVE_ACTION'; END IF;

    SELECT * INTO v_reserve
      FROM public.bill_reserves
     WHERE id = p_reserve_id
       AND user_id = p_user_id
     FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'BILL_RESERVE_NOT_FOUND'; END IF;

    SELECT * INTO v_source_wallet
      FROM public.wallets
     WHERE id = p_source_wallet_id
       AND user_id = p_user_id
     FOR UPDATE;

    IF FOUND THEN
        v_source_table := 'wallets';
        v_source_balance_before := COALESCE(v_source_wallet.balance, 0);
        v_source_wallet_role := COALESCE(v_source_wallet.type, NULL);
    ELSE
        SELECT * INTO v_source_vault
          FROM public.platform_vaults
         WHERE id = p_source_wallet_id
           AND user_id = p_user_id
         FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'SOURCE_WALLET_NOT_FOUND'; END IF;
        v_source_table := 'platform_vaults';
        v_source_balance_before := COALESCE(v_source_vault.balance, 0);
        v_source_wallet_role := COALESCE(v_source_vault.vault_role, NULL);
    END IF;

    v_locked_balance_before := COALESCE(v_reserve.locked_balance, 0);
    v_locked_balance_after := COALESCE(p_desired_locked_balance,
      CASE WHEN v_action = 'LOCK' THEN v_locked_balance_before + p_amount
      ELSE GREATEST(v_locked_balance_before - p_amount, 0) END);

    IF v_action = 'LOCK' THEN
        IF v_source_balance_before < p_amount THEN RAISE EXCEPTION 'INSUFFICIENT_FUNDS'; END IF;
        v_source_balance_after := v_source_balance_before - p_amount;
    ELSE
        IF v_locked_balance_before < p_amount THEN RAISE EXCEPTION 'BILL_RESERVE_INSUFFICIENT_BALANCE'; END IF;
        v_source_balance_after := v_source_balance_before + p_amount;
    END IF;

    INSERT INTO public.transactions (
        id, reference_id, user_id, wallet_id, amount, currency, description, type, status, date,
        wealth_impact_type, protection_state, allocation_source, metadata
    ) VALUES (
        gen_random_uuid(),
        v_reference_id,
        p_user_id,
        p_source_wallet_id,
        p_amount::text,
        upper(COALESCE(NULLIF(trim(p_currency), ''), 'TZS')),
        COALESCE(NULLIF(trim(p_description), ''), 'Bill reserve adjustment'),
        COALESCE(NULLIF(trim(p_metadata->>'transaction_type'), ''), 'internal_transfer'),
        COALESCE(NULLIF(trim(p_metadata->>'transaction_status'), ''), 'completed'),
        CURRENT_DATE,
        COALESCE(NULLIF(trim(p_metadata->>'wealth_impact_type'), ''), 'PLANNED'),
        'OPEN',
        NULLIF(trim(COALESCE(p_metadata->>'allocation_source', '')), ''),
        p_metadata
    )
    RETURNING * INTO v_tx;

    IF v_source_table = 'wallets' THEN
        UPDATE public.wallets SET balance = v_source_balance_after, updated_at = NOW()
         WHERE id = p_source_wallet_id AND user_id = p_user_id;
    ELSE
        UPDATE public.platform_vaults SET balance = v_source_balance_after, updated_at = NOW()
         WHERE id = p_source_wallet_id AND user_id = p_user_id;
    END IF;

    UPDATE public.bill_reserves
       SET locked_balance = v_locked_balance_after,
           source_wallet_id = p_source_wallet_id,
           updated_at = NOW()
     WHERE id = p_reserve_id
       AND user_id = p_user_id
    RETURNING * INTO v_reserve;

    INSERT INTO public.financial_ledger (
        id, transaction_id, user_id, wallet_id, bill_reserve_id, bucket_type, entry_side, entry_type, amount, balance_after, description
    ) VALUES
    (
        gen_random_uuid(), v_tx.id, p_user_id, p_source_wallet_id, p_reserve_id, 'OPERATING',
        CASE WHEN v_action = 'LOCK' THEN 'DEBIT' ELSE 'CREDIT' END,
        CASE WHEN v_action = 'LOCK' THEN 'DEBIT' ELSE 'CREDIT' END,
        p_amount::text, v_source_balance_after::text,
        CASE WHEN v_action = 'LOCK' THEN 'Bill reserve funding debit' ELSE 'Bill reserve release credit' END
    ),
    (
        gen_random_uuid(), v_tx.id, p_user_id, p_source_wallet_id, p_reserve_id, 'PLANNED',
        CASE WHEN v_action = 'LOCK' THEN 'CREDIT' ELSE 'DEBIT' END,
        CASE WHEN v_action = 'LOCK' THEN 'CREDIT' ELSE 'DEBIT' END,
        p_amount::text, v_locked_balance_after::text,
        CASE WHEN v_action = 'LOCK' THEN 'Bill reserve protected balance credit' ELSE 'Bill reserve protected balance release' END
    );

    RETURN jsonb_build_object(
        'success', true,
        'transaction_id', v_tx.id,
        'reference_id', v_reference_id,
        'source_balance_after', v_source_balance_after,
        'reserve', to_jsonb(v_reserve),
        'source_table', v_source_table,
        'source_wallet_role', v_source_wallet_role,
        'atomic_commit', true
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.settle_bill_payment_from_reserve_v1(
    p_user_id UUID,
    p_reserve_id UUID,
    p_amount NUMERIC,
    p_currency TEXT DEFAULT 'TZS',
    p_provider TEXT DEFAULT NULL,
    p_bill_category TEXT DEFAULT NULL,
    p_reference TEXT DEFAULT NULL,
    p_description TEXT DEFAULT NULL
)
RETURNS JSONB AS $$
DECLARE
    v_reserve public.bill_reserves%ROWTYPE;
    v_transaction public.transactions%ROWTYPE;
    v_source_wallet_id UUID;
    v_source_wallet_role TEXT;
    v_source_metadata JSONB := '{}'::jsonb;
    v_source_kind TEXT;
    v_locked_balance NUMERIC;
    v_reserve_balance_after NUMERIC;
    v_reference_id TEXT := 'billreserve_' || extract(epoch from now())::bigint || '_' || substr(md5(random()::text), 1, 8);
    v_provider_key TEXT;
    v_reserve_provider_key TEXT;
    v_category_key TEXT;
    v_reserve_category_key TEXT;
    v_reference_key TEXT;
    v_reserve_reference_key TEXT;
    v_updated_reserve JSONB;
BEGIN
    IF p_amount IS NULL OR p_amount <= 0 THEN
        RAISE EXCEPTION 'INVALID_AMOUNT';
    END IF;

    SELECT *
      INTO v_reserve
      FROM public.bill_reserves
     WHERE id = p_reserve_id
       AND user_id = p_user_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'BILL_RESERVE_NOT_FOUND';
    END IF;

    IF COALESCE(v_reserve.is_active, TRUE) = FALSE
       OR upper(COALESCE(v_reserve.status, 'ACTIVE')) <> 'ACTIVE' THEN
        RAISE EXCEPTION 'BILL_RESERVE_INACTIVE';
    END IF;

    v_provider_key := regexp_replace(replace(lower(trim(COALESCE(p_provider, ''))), '&', 'and'), '[^a-z0-9]+', ' ', 'g');
    v_reserve_provider_key := regexp_replace(replace(lower(trim(COALESCE(v_reserve.provider_name, ''))), '&', 'and'), '[^a-z0-9]+', ' ', 'g');
    IF v_provider_key <> '' AND v_reserve_provider_key <> ''
       AND v_provider_key <> v_reserve_provider_key
       AND strpos(v_provider_key, v_reserve_provider_key) = 0
       AND strpos(v_reserve_provider_key, v_provider_key) = 0 THEN
        RAISE EXCEPTION 'BILL_RESERVE_PROVIDER_MISMATCH';
    END IF;

    v_category_key := regexp_replace(replace(lower(trim(COALESCE(p_bill_category, ''))), '&', 'and'), '[^a-z0-9]+', ' ', 'g');
    v_reserve_category_key := regexp_replace(replace(lower(trim(COALESCE(v_reserve.bill_type, ''))), '&', 'and'), '[^a-z0-9]+', ' ', 'g');
    IF v_category_key <> '' AND v_reserve_category_key <> ''
       AND v_category_key <> v_reserve_category_key
       AND strpos(v_category_key, v_reserve_category_key) = 0
       AND strpos(v_reserve_category_key, v_category_key) = 0 THEN
        RAISE EXCEPTION 'BILL_RESERVE_CATEGORY_MISMATCH';
    END IF;

    v_reference_key := regexp_replace(replace(lower(trim(COALESCE(p_reference, ''))), '&', 'and'), '[^a-z0-9]+', ' ', 'g');
    v_reserve_reference_key := regexp_replace(
        replace(
            lower(
                trim(
                    COALESCE(
                        v_reserve.metadata->>'reference',
                        v_reserve.metadata->>'bill_reference',
                        v_reserve.metadata->>'account_number',
                        v_reserve.metadata->>'meter_number',
                        v_reserve.metadata->>'customer_number',
                        ''
                    )
                )
            ),
            '&',
            'and'
        ),
        '[^a-z0-9]+',
        ' ',
        'g'
    );
    IF v_reference_key <> '' AND v_reserve_reference_key <> ''
       AND v_reference_key <> v_reserve_reference_key
       AND strpos(v_reference_key, v_reserve_reference_key) = 0
       AND strpos(v_reserve_reference_key, v_reference_key) = 0 THEN
        RAISE EXCEPTION 'BILL_RESERVE_REFERENCE_MISMATCH';
    END IF;

    v_locked_balance := COALESCE(v_reserve.locked_balance, v_reserve.reserve_amount, 0);
    IF v_locked_balance < p_amount THEN
        RAISE EXCEPTION 'BILL_RESERVE_INSUFFICIENT_BALANCE';
    END IF;

    v_source_wallet_id := v_reserve.source_wallet_id;

    IF v_source_wallet_id IS NOT NULL THEN
        SELECT id, vault_role, COALESCE(metadata, '{}'::jsonb)
          INTO v_source_wallet_id, v_source_wallet_role, v_source_metadata
          FROM public.platform_vaults
         WHERE id = v_reserve.source_wallet_id
           AND user_id = p_user_id
         LIMIT 1;

        IF v_source_wallet_id IS NULL THEN
            SELECT id, type, COALESCE(metadata, '{}'::jsonb)
              INTO v_source_wallet_id, v_source_wallet_role, v_source_metadata
              FROM public.wallets
             WHERE id = v_reserve.source_wallet_id
               AND user_id = p_user_id
             LIMIT 1;
        END IF;
    END IF;

    v_source_kind := lower(
        COALESCE(
            v_source_metadata->>'source_kind',
            v_source_metadata->>'sourceKind',
            v_source_metadata->>'wallet_kind',
            v_source_wallet_role,
            ''
        )
    );
    IF strpos(v_source_kind, 'goal') > 0
       OR v_source_metadata ? 'goal_id'
       OR v_source_metadata ? 'goalId' THEN
        RAISE EXCEPTION 'GOAL_FUNDS_BILL_PAYMENT_NOT_ALLOWED';
    END IF;

    v_reserve_balance_after := v_locked_balance - p_amount;

    INSERT INTO public.transactions (
        id,
        reference_id,
        user_id,
        wallet_id,
        amount,
        currency,
        description,
        type,
        status,
        date,
        metadata,
        wealth_impact_type,
        protection_state,
        allocation_source
    ) VALUES (
        gen_random_uuid(),
        v_reference_id,
        p_user_id,
        v_source_wallet_id,
        p_amount::text,
        upper(COALESCE(NULLIF(trim(p_currency), ''), v_reserve.currency, 'TZS')),
        COALESCE(NULLIF(trim(p_description), ''), 'Bill payment from reserve: ' || COALESCE(p_provider, v_reserve.provider_name, 'Provider')),
        'bill_payment',
        'completed',
        CURRENT_DATE,
        jsonb_strip_nulls(jsonb_build_object(
            'bill_reserve_id', v_reserve.id,
            'service_context', 'BILL_PAYMENT',
            'funding_mode', 'RESERVE',
            'bill_provider', COALESCE(p_provider, v_reserve.provider_name),
            'bill_category', COALESCE(p_bill_category, v_reserve.bill_type),
            'bill_reference', COALESCE(NULLIF(trim(p_reference), ''), NULLIF(trim(v_reserve.metadata->>'reference'), ''), NULLIF(trim(v_reserve.metadata->>'bill_reference'), '')),
            'source_wallet_role', v_source_wallet_role,
            'source_kind', NULLIF(v_source_kind, ''),
            'reserve_balance_before', v_locked_balance,
            'reserve_balance_after', v_reserve_balance_after
        )),
        'PLANNED',
        'PROTECTED',
        'BILL_RESERVE_PAYMENT'
    )
    RETURNING * INTO v_transaction;

    UPDATE public.bill_reserves
       SET locked_balance = v_reserve_balance_after,
           updated_at = NOW()
     WHERE id = v_reserve.id
       AND user_id = p_user_id
    RETURNING to_jsonb(bill_reserves.*) INTO v_updated_reserve;

    INSERT INTO public.financial_ledger (
        id,
        transaction_id,
        user_id,
        wallet_id,
        bill_reserve_id,
        bucket_type,
        entry_side,
        entry_type,
        amount,
        balance_after,
        description
    ) VALUES (
        gen_random_uuid(),
        v_transaction.id,
        p_user_id,
        v_source_wallet_id,
        v_reserve.id,
        'PLANNED',
        'DEBIT',
        'DEBIT',
        p_amount::text,
        v_reserve_balance_after::text,
        'Bill reserve payment debit: ' || COALESCE(p_provider, v_reserve.provider_name, 'Provider')
    );

    RETURN jsonb_build_object(
        'success', true,
        'transaction', to_jsonb(v_transaction),
        'reserve', v_updated_reserve,
        'funding_mode', 'RESERVE',
        'reserve_balance', v_reserve_balance_after
    );
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
    
    encrypted_zero := 'enc_v2_eyJ2ZXJzaW9uIjoxLCJpdiI6IkFBQUFBQUFBQUFBQSIsImNpcGhlcnRleHQiOiJBQUFBQUFBQUFBQUEiLCJ0YWciOiJBQUFBQUFBQUFBQUEiLCJ0aW1lc3RhbXAiOjAsImtleUlkIjoicC1ub2RlLWFjdGl2ZSIsImFsZ29yaXRobSI6IkFFUy1HQ00tMjU2In0='; 
    
    wallet1_id := md5(new_user_id::text || 'Orbi')::uuid;
    wallet2_id := md5(new_user_id::text || 'PaySafe')::uuid;

    INSERT INTO public.users (
        id, email, full_name, customer_id, phone, nationality, currency, registry_type, role, app_origin, metadata
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
    )
    ON CONFLICT DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- 4. TRIGGERS
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 5. RLS POLICIES (IDEMPOTENT)
DO $$ 
BEGIN
    -- Enable RLS for all tables
    ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.staff ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.financial_ledger ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.financial_partners ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.institutional_payment_accounts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.external_fund_movements ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.settlement_lifecycle ENABLE ROW LEVEL SECURITY;
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
    ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.escrow_agreements ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.treasury_policies ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.treasury_approvers ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.budget_alerts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.reconciliation_reports ENABLE ROW LEVEL SECURITY;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- Drop and Recreate Policies to ensure latest logic
DROP POLICY IF EXISTS "Users view own organization" ON public.organizations;
CREATE POLICY "Users view own organization" ON public.organizations 
    FOR SELECT USING (id IN (SELECT organization_id FROM public.users WHERE id = auth.uid()));

DROP POLICY IF EXISTS "Users view corporate goals" ON public.goals;
DROP POLICY IF EXISTS "Users manage own goals" ON public.goals;
CREATE POLICY "Users view corporate goals" ON public.goals 
    FOR SELECT USING (
        user_id = auth.uid() OR 
        (is_corporate = true AND organization_id IN (SELECT organization_id FROM public.users WHERE id = auth.uid()))
    );

CREATE POLICY "Users manage own goals" ON public.goals
    FOR ALL
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users view corporate budgets" ON public.categories;
CREATE POLICY "Users view corporate budgets" ON public.categories 
    FOR SELECT USING (
        user_id = auth.uid() OR 
        (is_corporate = true AND organization_id IN (SELECT organization_id FROM public.users WHERE id = auth.uid()))
    );

DROP POLICY IF EXISTS "Forensic Ledger Read" ON public.audit_trail;
CREATE POLICY "Forensic Ledger Read" ON public.audit_trail FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT'));

DROP POLICY IF EXISTS "Audit WORM Write" ON public.audit_trail;
CREATE POLICY "Audit WORM Write" ON public.audit_trail FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);

-- SYSTEM BYPASS: Ensure service_role (Admin Client) can always manage audit trails
DROP POLICY IF EXISTS "System bypass audit trail" ON public.audit_trail;
CREATE POLICY "System bypass audit trail" ON public.audit_trail FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Users create transactions" ON public.transactions;
CREATE POLICY "Users create transactions" ON public.transactions FOR INSERT WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users view own transactions" ON public.transactions;
CREATE POLICY "Users view own transactions" ON public.transactions FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role transaction bypass" ON public.transactions;
CREATE POLICY "Service role transaction bypass" ON public.transactions FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admin manage institutional accounts" ON public.institutional_payment_accounts;
CREATE POLICY "Admin manage institutional accounts" ON public.institutional_payment_accounts
    FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'))
    WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'));

DROP POLICY IF EXISTS "Service role institutional account bypass" ON public.institutional_payment_accounts;
CREATE POLICY "Service role institutional account bypass" ON public.institutional_payment_accounts
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Users view own external fund movements" ON public.external_fund_movements;
CREATE POLICY "Users view own external fund movements" ON public.external_fund_movements
    FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users create own external fund movements" ON public.external_fund_movements;
CREATE POLICY "Users create own external fund movements" ON public.external_fund_movements
    FOR INSERT WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Admin view external fund movements" ON public.external_fund_movements;
CREATE POLICY "Admin view external fund movements" ON public.external_fund_movements
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT', 'FINANCE'));

DROP POLICY IF EXISTS "Service role external fund movement bypass" ON public.external_fund_movements;
CREATE POLICY "Service role external fund movement bypass" ON public.external_fund_movements
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Users view own settlement lifecycle" ON public.settlement_lifecycle;
CREATE POLICY "Users view own settlement lifecycle"
ON public.settlement_lifecycle
FOR SELECT
USING (
    EXISTS (
        SELECT 1
        FROM public.transactions t
        WHERE t.id = settlement_lifecycle.transaction_id
          AND t.user_id = auth.uid()
    )
    OR EXISTS (
        SELECT 1
        FROM public.external_fund_movements efm
        WHERE efm.id = settlement_lifecycle.external_movement_id
          AND efm.user_id = auth.uid()
    )
);

DROP POLICY IF EXISTS "Admin view settlement lifecycle" ON public.settlement_lifecycle;
CREATE POLICY "Admin view settlement lifecycle"
ON public.settlement_lifecycle
FOR SELECT
USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT', 'FINANCE'));

DROP POLICY IF EXISTS "Service role settlement lifecycle bypass" ON public.settlement_lifecycle;
CREATE POLICY "Service role settlement lifecycle bypass"
ON public.settlement_lifecycle
FOR ALL TO service_role
USING (true)
WITH CHECK (true);


DROP POLICY IF EXISTS "Admin manage provider routing rules" ON public.provider_routing_rules;
CREATE POLICY "Admin manage provider routing rules" ON public.provider_routing_rules
    FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'))
    WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'));

DROP POLICY IF EXISTS "Service role provider routing bypass" ON public.provider_routing_rules;
CREATE POLICY "Service role provider routing bypass" ON public.provider_routing_rules
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role inbound sms bypass" ON public.inbound_sms_messages;
CREATE POLICY "Service role inbound sms bypass" ON public.inbound_sms_messages
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role offline session bypass" ON public.offline_transaction_sessions;
CREATE POLICY "Service role offline session bypass" ON public.offline_transaction_sessions
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role outbound sms bypass" ON public.outbound_sms_messages;
CREATE POLICY "Service role outbound sms bypass" ON public.outbound_sms_messages
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Workforce Consumer Access" ON public.users;
CREATE POLICY "Workforce Consumer Access" ON public.users FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'CUSTOMER_CARE'));

DROP POLICY IF EXISTS "Consumer Self Management" ON public.users;
CREATE POLICY "Consumer Self Management" ON public.users FOR SELECT USING (auth.uid() = id);

DROP POLICY IF EXISTS "Admins manage workforce" ON public.staff;
CREATE POLICY "Admins manage workforce" ON public.staff FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN'));

DROP POLICY IF EXISTS "Staff visible to themselves" ON public.staff;
CREATE POLICY "Staff visible to themselves" ON public.staff FOR SELECT USING (auth.uid() = id);

DROP POLICY IF EXISTS "Users manage own wallets" ON public.wallets;
CREATE POLICY "Users manage own wallets" ON public.wallets FOR ALL USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users manage own vaults" ON public.platform_vaults;
CREATE POLICY "Users manage own vaults" ON public.platform_vaults FOR ALL USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role vault bypass" ON public.platform_vaults;
CREATE POLICY "Service role vault bypass" ON public.platform_vaults FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Users view own messages" ON public.user_messages;
CREATE POLICY "Users view own messages" ON public.user_messages FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Staff view messages" ON public.staff_messages;
CREATE POLICY "Staff view messages" ON public.staff_messages FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'CUSTOMER_CARE', 'AUDIT'));

DROP POLICY IF EXISTS "Admin Node Management" ON public.infra_system_matrix;
CREATE POLICY "Admin Node Management" ON public.infra_system_matrix FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'IT'));

DROP POLICY IF EXISTS "Admin manage regulatory" ON public.regulatory_config;
CREATE POLICY "Admin manage regulatory" ON public.regulatory_config FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT'));

DROP POLICY IF EXISTS "Admins manage KYC requests" ON public.kyc_requests;
CREATE POLICY "Admins manage KYC requests" ON public.kyc_requests FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'CUSTOMER_CARE'));

DROP POLICY IF EXISTS "Admins view fee logs" ON public.fee_correction_logs;
CREATE POLICY "Admins view fee logs" ON public.fee_correction_logs FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'FINANCE', 'AUDIT'));

DROP POLICY IF EXISTS "Admins view reconciliation audits" ON public.item_reconciliation_audit;
CREATE POLICY "Admins view reconciliation audits" ON public.item_reconciliation_audit FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT'));

DROP POLICY IF EXISTS "Admins insert reconciliation audits" ON public.item_reconciliation_audit;
CREATE POLICY "Admins insert reconciliation audits" ON public.item_reconciliation_audit FOR INSERT WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'AUDIT'));

-- SYSTEM BYPASS: Ensure service_role (Admin Client) can always manage reconciliation logs
DROP POLICY IF EXISTS "System bypass reconciliation" ON public.item_reconciliation_audit;
CREATE POLICY "System bypass reconciliation" ON public.item_reconciliation_audit FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admins view reconciliation reports" ON public.reconciliation_reports;
CREATE POLICY "Admins view reconciliation reports" ON public.reconciliation_reports 
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT'));

DROP POLICY IF EXISTS "System manage reconciliation reports" ON public.reconciliation_reports;
CREATE POLICY "System manage reconciliation reports" ON public.reconciliation_reports 
    FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ==========================================
-- NEXT-GEN SECURITY ARCHITECTURE (V26)
-- ==========================================

-- Layer 1: Passkeys (WebAuthn)
CREATE TABLE IF NOT EXISTS public.passkeys (
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
CREATE INDEX IF NOT EXISTS idx_passkey_user ON public.passkeys(user_id);

-- Layer 2: Device Fingerprinting
CREATE TABLE IF NOT EXISTS public.device_fingerprints (
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
CREATE INDEX IF NOT EXISTS idx_device_fp_user ON public.device_fingerprints(user_id);

-- Layer 3: Behavioral Biometrics
CREATE TABLE IF NOT EXISTS public.behavioral_biometrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    session_id TEXT,
    typing_speed NUMERIC,
    swipe_velocity NUMERIC,
    touch_pressure NUMERIC,
    anomaly_score NUMERIC DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_behavior_user ON public.behavioral_biometrics(user_id);

-- Layer 5 & 6: AI Fraud & Risk Logs
CREATE TABLE IF NOT EXISTS public.ai_risk_logs (
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
CREATE INDEX IF NOT EXISTS idx_ai_risk_user ON public.ai_risk_logs(user_id);

-- Layer 8: Hardware Security Modules (HSM) / Secure Enclave
CREATE TABLE IF NOT EXISTS public.secure_enclave_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES public.device_fingerprints(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    attestation_token TEXT,
    status TEXT DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_enclave_user ON public.secure_enclave_keys(user_id);

-- Security Tables
ALTER TABLE public.passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.behavioral_biometrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_risk_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.secure_enclave_keys ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users manage own passkeys" ON public.passkeys;
CREATE POLICY "Users manage own passkeys" ON public.passkeys FOR ALL USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users view own device fingerprints" ON public.device_fingerprints;
CREATE POLICY "Users view own device fingerprints" ON public.device_fingerprints FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users view own behavioral biometrics" ON public.behavioral_biometrics;
CREATE POLICY "Users view own behavioral biometrics" ON public.behavioral_biometrics FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users view own ai risk logs" ON public.ai_risk_logs;
CREATE POLICY "Users view own ai risk logs" ON public.ai_risk_logs FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users manage own secure enclave keys" ON public.secure_enclave_keys;
CREATE POLICY "Users manage own secure enclave keys" ON public.secure_enclave_keys FOR ALL USING (auth.uid() = user_id);

-- System bypass for security tables
DROP POLICY IF EXISTS "Service role passkeys bypass" ON public.passkeys;
CREATE POLICY "Service role passkeys bypass" ON public.passkeys FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role device fingerprints bypass" ON public.device_fingerprints;
CREATE POLICY "Service role device fingerprints bypass" ON public.device_fingerprints FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role behavioral biometrics bypass" ON public.behavioral_biometrics;
CREATE POLICY "Service role behavioral biometrics bypass" ON public.behavioral_biometrics FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role ai risk logs bypass" ON public.ai_risk_logs;
CREATE POLICY "Service role ai risk logs bypass" ON public.ai_risk_logs FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role secure enclave keys bypass" ON public.secure_enclave_keys;
CREATE POLICY "Service role secure enclave keys bypass" ON public.secure_enclave_keys FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Escrow Agreements
DROP POLICY IF EXISTS "Users view own escrow agreements" ON public.escrow_agreements;
CREATE POLICY "Users view own escrow agreements" ON public.escrow_agreements
    FOR SELECT USING (auth.uid() = sender_id OR auth.uid() = receiver_id);

-- Treasury Policies
DROP POLICY IF EXISTS "Org members view treasury policies" ON public.treasury_policies;
CREATE POLICY "Org members view treasury policies" ON public.treasury_policies
    FOR SELECT USING (
        organization_id IN (SELECT organization_id FROM public.users WHERE id = auth.uid())
    );

-- Treasury Approvers
DROP POLICY IF EXISTS "Approvers view assignments" ON public.treasury_approvers;
CREATE POLICY "Approvers view assignments" ON public.treasury_approvers
    FOR SELECT USING (
        organization_id IN (SELECT organization_id FROM public.users WHERE id = auth.uid())
    );

-- 6. INDEXES
CREATE INDEX IF NOT EXISTS idx_tx_user_date ON public.transactions(user_id, date);
CREATE INDEX IF NOT EXISTS idx_ledger_tx ON public.financial_ledger(transaction_id);
CREATE INDEX IF NOT EXISTS idx_transactions_user_wallet ON public.transactions(user_id, wallet_id);
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_created ON public.transactions(wallet_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_to_wallet_created ON public.transactions(to_wallet_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_wallet_created ON public.financial_ledger(wallet_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_wallet_tx ON public.financial_ledger(wallet_id, transaction_id);
CREATE INDEX IF NOT EXISTS idx_goals_source_wallet ON public.goals(source_wallet_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status_updated ON public.transactions(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_review_timeout ON public.transactions(updated_at DESC) WHERE status = 'held_for_review';
CREATE INDEX IF NOT EXISTS idx_transactions_processing_timeout ON public.transactions(updated_at DESC) WHERE status = 'processing';
CREATE INDEX IF NOT EXISTS idx_transaction_events_transaction_created ON public.transaction_events(transaction_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_transaction_timestamp ON public.audit_trail(transaction_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_event_timestamp ON public.audit_trail(event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_actor_timestamp ON public.audit_trail(actor_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_institutional_payment_accounts_role ON public.institutional_payment_accounts(role, currency, status);
CREATE INDEX IF NOT EXISTS idx_institutional_payment_accounts_provider ON public.institutional_payment_accounts(provider_id);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_user_date ON public.external_fund_movements(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_transaction ON public.external_fund_movements(transaction_id);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_provider_status ON public.external_fund_movements(provider_id, status);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_status_updated ON public.external_fund_movements(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_provider_routing_rules_lookup ON public.provider_routing_rules(rail, operation_code, status, priority);
CREATE INDEX IF NOT EXISTS idx_inbound_sms_request_id ON public.inbound_sms_messages(request_id);
CREATE INDEX IF NOT EXISTS idx_offline_transaction_sessions_request_id ON public.offline_transaction_sessions(request_id);
CREATE INDEX IF NOT EXISTS idx_offline_transaction_sessions_status ON public.offline_transaction_sessions(status, created_at);
CREATE INDEX IF NOT EXISTS idx_outbound_sms_request_id ON public.outbound_sms_messages(request_id);
CREATE INDEX IF NOT EXISTS idx_wallets_user ON public.wallets(user_id);
CREATE INDEX IF NOT EXISTS idx_goals_user ON public.goals(user_id);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_user ON public.external_fund_movements(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_provider ON public.external_fund_movements(provider_id, status);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_reference ON public.external_fund_movements(external_reference);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_tx ON public.settlement_lifecycle(transaction_id);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_external_movement ON public.settlement_lifecycle(external_movement_id);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_merchant_settlement ON public.settlement_lifecycle(merchant_settlement_id);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_provider ON public.settlement_lifecycle(provider_id);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_stage ON public.settlement_lifecycle(stage);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_status ON public.settlement_lifecycle(status);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_created_at ON public.settlement_lifecycle(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_batch ON public.settlement_lifecycle(settlement_batch_id);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_provider_reference ON public.settlement_lifecycle(provider_reference);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_lifecycle_key ON public.settlement_lifecycle(lifecycle_key);
CREATE INDEX IF NOT EXISTS idx_provider_routing_rules_lookup ON public.provider_routing_rules(rail, operation_code, currency, country_code, status, priority);
CREATE INDEX IF NOT EXISTS idx_platform_fee_configs_lookup ON public.platform_fee_configs(flow_code, status, currency, provider_id, rail, channel, direction, operation_type, transaction_type, priority);
CREATE INDEX IF NOT EXISTS idx_service_commissions_actor ON public.service_commissions(actor_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_commissions_source ON public.service_commissions(source_transaction_id);
CREATE INDEX IF NOT EXISTS idx_agent_transactions_owner ON public.agent_transactions(owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_merchant_transactions_owner ON public.merchant_transactions(owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_categories_user ON public.categories(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_user ON public.tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_user_messages_user_read ON public.user_messages(user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_kyc_requests_user_id ON public.kyc_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_kyc_requests_status ON public.kyc_requests(status);
CREATE INDEX IF NOT EXISTS idx_user_devices_user ON public.user_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_user_devices_fingerprint ON public.user_devices(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_user_devices_user_trust ON public.user_devices(user_id, is_trusted, status);
CREATE INDEX IF NOT EXISTS idx_user_documents_user ON public.user_documents(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON public.user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_device_fingerprint ON public.user_sessions(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON public.user_sessions(user_id, is_revoked, last_active_at);
CREATE INDEX IF NOT EXISTS idx_escrow_tx_id ON public.escrow_agreements(transaction_id);
CREATE INDEX IF NOT EXISTS idx_escrow_sender ON public.escrow_agreements(sender_id);
CREATE INDEX IF NOT EXISTS idx_escrow_receiver ON public.escrow_agreements(receiver_id);
CREATE INDEX IF NOT EXISTS idx_treasury_org ON public.treasury_policies(organization_id);

-- 7. SYSTEM PROVISIONING (IDEMPOTENT)
DO $$
DECLARE
    enc_zero TEXT := 'enc_v2_eyJ2ZXJzaW9uIjoxLCJpdiI6IkFBQUFBQUFBQUFBQSIsImNpcGhlcnRleHQiOiJBQUFBQUFBQUFBQUEiLCJ0YWciOiJBQUFBQUFBQUFBQUEiLCJ0aW1lc3RhbXAiOjAsImtleUlkIjoicC1ub2RlLWFjdGl2ZSIsImFsZ29yaXRobSI6IkFFUy1HQ00tMjU2In0=';
BEGIN
    -- Provision System Vaults
    INSERT INTO public.platform_vaults (id, user_id, vault_role, name, balance, encrypted_balance, currency, color, icon)
    VALUES ('00000000-0000-0000-0000-000000000003', NULL, 'FEE_COLLECTOR', 'System Fee Collector', 0, enc_zero, 'USD', '#F59E0B', 'bank')
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.platform_vaults (id, user_id, vault_role, name, balance, encrypted_balance, currency, color, icon)
    VALUES ('00000000-0000-0000-0000-000000000001', NULL, 'ESCROW_VAULT', 'System Escrow Vault', 0, enc_zero, 'USD', '#6366F1', 'shield-check')
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.platform_vaults (id, user_id, vault_role, name, balance, encrypted_balance, currency, color, icon)
    VALUES ('00000000-0000-0000-0000-000000000004', NULL, 'TAX_RESERVE', 'System Tax Reserve', 0, enc_zero, 'USD', '#EF4444', 'landmark')
    ON CONFLICT (id) DO NOTHING;

    -- Provision Fee Collector Wallets
    INSERT INTO public.fee_collector_wallets (fee_type, vault_id, currency)
    VALUES ('GOV_TAX', '00000000-0000-0000-0000-000000000004', 'TZS')
    ON CONFLICT (fee_type) DO NOTHING;

    INSERT INTO public.fee_collector_wallets (fee_type, vault_id, currency)
    VALUES ('SERVICE_FEE', '00000000-0000-0000-0000-000000000003', 'TZS')
    ON CONFLICT (fee_type) DO NOTHING;

    -- Map System Nodes
    INSERT INTO public.system_nodes (node_type, vault_id) VALUES ('FEE_COLLECTOR', '00000000-0000-0000-0000-000000000003') ON CONFLICT (node_type) DO UPDATE SET vault_id = EXCLUDED.vault_id;
    INSERT INTO public.system_nodes (node_type, vault_id) VALUES ('ESCROW_VAULT', '00000000-0000-0000-0000-000000000001') ON CONFLICT (node_type) DO UPDATE SET vault_id = EXCLUDED.vault_id;
    INSERT INTO public.system_nodes (node_type, vault_id) VALUES ('TAX_RESERVE', '00000000-0000-0000-0000-000000000004') ON CONFLICT (node_type) DO UPDATE SET vault_id = EXCLUDED.vault_id;
    INSERT INTO public.system_nodes (node_type, vault_id) VALUES ('PLATFORM_FEE', '00000000-0000-0000-0000-000000000003') ON CONFLICT (node_type) DO UPDATE SET vault_id = EXCLUDED.vault_id;
    INSERT INTO public.system_nodes (node_type, vault_id) VALUES ('GOV_TAX', '00000000-0000-0000-0000-000000000004') ON CONFLICT (node_type) DO UPDATE SET vault_id = EXCLUDED.vault_id;
END $$;

-- 7B. PAYMENT PROVIDER BOOTSTRAP (IDEMPOTENT)
DO $$
BEGIN
    -- Provider registry seeds keep fresh environments deposit-ready.
    INSERT INTO public.financial_partners (
        id, name, type, supported_currencies, icon, color, api_base_url,
        provider_metadata, mapping_config, logic_type, status
    ) VALUES
    (
        '10000000-0000-0000-0000-000000000101',
        'ORBI M-Pesa Tanzania',
        'mobile_money',
        ARRAY['TZS']::TEXT[],
        'smartphone',
        '#16A34A',
        'https://api.example.com/mobile-money/mpesa',
        jsonb_build_object(
            'group', 'Mobile Money',
            'brand_name', 'M-Pesa',
            'provider_code', 'MPESA_TZ',
            'display_icon', 'smartphone',
            'checkout_mode', 'server_to_server',
            'channels', jsonb_build_array('stk_push', 'ussd'),
            'rail', 'MOBILE_MONEY',
            'operations', jsonb_build_array('COLLECTION_REQUEST', 'DISBURSEMENT_REQUEST'),
            'countries', jsonb_build_array('TZ'),
            'routing_priority', 10
        ),
        jsonb_build_object(
            'service_root', 'https://api.example.com/mobile-money/mpesa',
            'operations', jsonb_build_object(
                'COLLECTION_REQUEST', jsonb_build_object('timeout_ms', 30000),
                'DISBURSEMENT_REQUEST', jsonb_build_object('timeout_ms', 30000)
            )
        ),
        'REGISTRY',
        'ACTIVE'
    ),
    (
        '10000000-0000-0000-0000-000000000102',
        'ORBI Bank Transfer Tanzania',
        'bank',
        ARRAY['TZS', 'USD']::TEXT[],
        'account_balance',
        '#2563EB',
        'https://api.example.com/bank/core',
        jsonb_build_object(
            'group', 'Bank',
            'brand_name', 'Bank Transfer',
            'provider_code', 'BANK_TZ',
            'display_icon', 'account_balance',
            'checkout_mode', 'server_to_server',
            'channels', jsonb_build_array('account', 'bank_transfer'),
            'rail', 'BANK',
            'operations', jsonb_build_array('COLLECTION_REQUEST', 'DISBURSEMENT_REQUEST'),
            'countries', jsonb_build_array('TZ'),
            'routing_priority', 20
        ),
        jsonb_build_object(
            'service_root', 'https://api.example.com/bank/core',
            'operations', jsonb_build_object(
                'COLLECTION_REQUEST', jsonb_build_object('timeout_ms', 30000),
                'DISBURSEMENT_REQUEST', jsonb_build_object('timeout_ms', 30000)
            )
        ),
        'REGISTRY',
        'ACTIVE'
    ),
    (
        '10000000-0000-0000-0000-000000000103',
        'ORBI Card Gateway',
        'card',
        ARRAY['TZS', 'USD']::TEXT[],
        'credit_card',
        '#7C3AED',
        'https://api.example.com/card/gateway',
        jsonb_build_object(
            'group', 'Cards',
            'brand_name', 'Card Gateway',
            'provider_code', 'CARD_GATEWAY',
            'display_icon', 'credit_card',
            'checkout_mode', 'server_to_server',
            'channels', jsonb_build_array('visa', 'mastercard'),
            'rail', 'CARD_GATEWAY',
            'operations', jsonb_build_array('COLLECTION_REQUEST'),
            'countries', jsonb_build_array('TZ'),
            'routing_priority', 30
        ),
        jsonb_build_object(
            'service_root', 'https://api.example.com/card/gateway',
            'operations', jsonb_build_object(
                'COLLECTION_REQUEST', jsonb_build_object('timeout_ms', 30000)
            )
        ),
        'REGISTRY',
        'ACTIVE'
    ),
    (
        '10000000-0000-0000-0000-000000000104',
        'ORBI Crypto Gateway',
        'crypto',
        ARRAY['USDT', 'BTC', 'ETH']::TEXT[],
        'currency_bitcoin',
        '#F59E0B',
        'https://api.example.com/crypto/gateway',
        jsonb_build_object(
            'group', 'Crypto',
            'brand_name', 'Crypto Gateway',
            'provider_code', 'CRYPTO_GATEWAY',
            'display_icon', 'currency_bitcoin',
            'checkout_mode', 'server_to_server',
            'channels', jsonb_build_array('onchain', 'wallet'),
            'rail', 'CRYPTO',
            'operations', jsonb_build_array('COLLECTION_REQUEST', 'DISBURSEMENT_REQUEST'),
            'countries', jsonb_build_array('TZ'),
            'routing_priority', 40
        ),
        jsonb_build_object(
            'service_root', 'https://api.example.com/crypto/gateway',
            'operations', jsonb_build_object(
                'COLLECTION_REQUEST', jsonb_build_object('timeout_ms', 45000),
                'DISBURSEMENT_REQUEST', jsonb_build_object('timeout_ms', 45000)
            )
        ),
        'REGISTRY',
        'ACTIVE'
    )
    ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        type = EXCLUDED.type,
        supported_currencies = EXCLUDED.supported_currencies,
        icon = EXCLUDED.icon,
        color = EXCLUDED.color,
        api_base_url = EXCLUDED.api_base_url,
        provider_metadata = EXCLUDED.provider_metadata,
        mapping_config = EXCLUDED.mapping_config,
        logic_type = EXCLUDED.logic_type,
        status = EXCLUDED.status;

    INSERT INTO public.institutional_payment_accounts (
        id, role, provider_id, bank_name, account_name, account_number, currency,
        country_code, status, is_primary, metadata
    ) VALUES
    (
        '10000000-0000-0000-0000-000000000201',
        'MAIN_COLLECTION',
        '10000000-0000-0000-0000-000000000101',
        'Vodacom M-Pesa Trust',
        'ORBI Main Collection',
        '255700000001',
        'TZS',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'deposit_collection', 'rail', 'MOBILE_MONEY')
    ),
    (
        '10000000-0000-0000-0000-000000000202',
        'TRANSFER_SAVINGS',
        '10000000-0000-0000-0000-000000000101',
        'Vodacom M-Pesa Trust',
        'ORBI Transfer Settlement',
        '255700000002',
        'TZS',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'outbound_settlement', 'rail', 'MOBILE_MONEY')
    ),
    (
        '10000000-0000-0000-0000-000000000203',
        'FEE_COLLECTION',
        '10000000-0000-0000-0000-000000000101',
        'Vodacom M-Pesa Trust',
        'ORBI Fee Reserve',
        '255700000003',
        'TZS',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'fee_collection', 'rail', 'MOBILE_MONEY')
    ),
    (
        '10000000-0000-0000-0000-000000000204',
        'TAX_COLLECTION',
        '10000000-0000-0000-0000-000000000101',
        'Vodacom M-Pesa Trust',
        'ORBI Tax Reserve',
        '255700000004',
        'TZS',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'tax_collection', 'rail', 'MOBILE_MONEY')
    ),
    (
        '10000000-0000-0000-0000-000000000205',
        'MAIN_COLLECTION',
        '10000000-0000-0000-0000-000000000102',
        'CRDB Bank',
        'ORBI Main Collection Bank',
        '1100000001',
        'TZS',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'deposit_collection', 'rail', 'BANK')
    ),
    (
        '10000000-0000-0000-0000-000000000206',
        'TRANSFER_SAVINGS',
        '10000000-0000-0000-0000-000000000102',
        'CRDB Bank',
        'ORBI Transfer Clearing',
        '1100000002',
        'TZS',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'outbound_settlement', 'rail', 'BANK')
    ),
    (
        '10000000-0000-0000-0000-000000000207',
        'FEE_COLLECTION',
        '10000000-0000-0000-0000-000000000102',
        'CRDB Bank',
        'ORBI Fee Collection Bank',
        '1100000003',
        'TZS',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'fee_collection', 'rail', 'BANK')
    ),
    (
        '10000000-0000-0000-0000-000000000208',
        'TAX_COLLECTION',
        '10000000-0000-0000-0000-000000000102',
        'CRDB Bank',
        'ORBI Tax Collection Bank',
        '1100000004',
        'TZS',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'tax_collection', 'rail', 'BANK')
    ),
    (
        '10000000-0000-0000-0000-000000000209',
        'MAIN_COLLECTION',
        '10000000-0000-0000-0000-000000000103',
        'Card Settlement Bank',
        'ORBI Card Collection',
        '2200000001',
        'TZS',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'deposit_collection', 'rail', 'CARD_GATEWAY')
    ),
    (
        '10000000-0000-0000-0000-000000000210',
        'TRANSFER_SAVINGS',
        '10000000-0000-0000-0000-000000000103',
        'Card Settlement Bank',
        'ORBI Card Settlement',
        '2200000002',
        'TZS',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'outbound_settlement', 'rail', 'CARD_GATEWAY')
    ),
    (
        '10000000-0000-0000-0000-000000000211',
        'MAIN_COLLECTION',
        '10000000-0000-0000-0000-000000000104',
        'ORBI Digital Assets',
        'ORBI Crypto Collection',
        'CRYPTO-COLLECT-001',
        'USDT',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'deposit_collection', 'rail', 'CRYPTO')
    ),
    (
        '10000000-0000-0000-0000-000000000212',
        'TRANSFER_SAVINGS',
        '10000000-0000-0000-0000-000000000104',
        'ORBI Digital Assets',
        'ORBI Crypto Settlement',
        'CRYPTO-SETTLE-001',
        'USDT',
        'TZ',
        'ACTIVE',
        TRUE,
        jsonb_build_object('purpose', 'outbound_settlement', 'rail', 'CRYPTO')
    )
    ON CONFLICT (id) DO UPDATE SET
        role = EXCLUDED.role,
        provider_id = EXCLUDED.provider_id,
        bank_name = EXCLUDED.bank_name,
        account_name = EXCLUDED.account_name,
        account_number = EXCLUDED.account_number,
        currency = EXCLUDED.currency,
        country_code = EXCLUDED.country_code,
        status = EXCLUDED.status,
        is_primary = EXCLUDED.is_primary,
        metadata = EXCLUDED.metadata,
        updated_at = NOW();

    INSERT INTO public.provider_routing_rules (
        id, rail, country_code, currency, operation_code, provider_id, priority, conditions, status
    ) VALUES
    (
        '10000000-0000-0000-0000-000000000301',
        'MOBILE_MONEY',
        'TZ',
        'TZS',
        'COLLECTION_REQUEST',
        '10000000-0000-0000-0000-000000000101',
        10,
        '{}'::jsonb,
        'ACTIVE'
    ),
    (
        '10000000-0000-0000-0000-000000000302',
        'MOBILE_MONEY',
        'TZ',
        'TZS',
        'DISBURSEMENT_REQUEST',
        '10000000-0000-0000-0000-000000000101',
        10,
        '{}'::jsonb,
        'ACTIVE'
    ),
    (
        '10000000-0000-0000-0000-000000000303',
        'BANK',
        'TZ',
        'TZS',
        'COLLECTION_REQUEST',
        '10000000-0000-0000-0000-000000000102',
        20,
        '{}'::jsonb,
        'ACTIVE'
    ),
    (
        '10000000-0000-0000-0000-000000000304',
        'BANK',
        'TZ',
        'TZS',
        'DISBURSEMENT_REQUEST',
        '10000000-0000-0000-0000-000000000102',
        20,
        '{}'::jsonb,
        'ACTIVE'
    ),
    (
        '10000000-0000-0000-0000-000000000305',
        'CARD_GATEWAY',
        'TZ',
        'TZS',
        'COLLECTION_REQUEST',
        '10000000-0000-0000-0000-000000000103',
        30,
        '{}'::jsonb,
        'ACTIVE'
    ),
    (
        '10000000-0000-0000-0000-000000000306',
        'CRYPTO',
        'TZ',
        'USDT',
        'COLLECTION_REQUEST',
        '10000000-0000-0000-0000-000000000104',
        40,
        '{}'::jsonb,
        'ACTIVE'
    ),
    (
        '10000000-0000-0000-0000-000000000307',
        'CRYPTO',
        'TZ',
        'USDT',
        'DISBURSEMENT_REQUEST',
        '10000000-0000-0000-0000-000000000104',
        40,
        '{}'::jsonb,
        'ACTIVE'
    )
    ON CONFLICT (id) DO UPDATE SET
        rail = EXCLUDED.rail,
        country_code = EXCLUDED.country_code,
        currency = EXCLUDED.currency,
        operation_code = EXCLUDED.operation_code,
        provider_id = EXCLUDED.provider_id,
        priority = EXCLUDED.priority,
        conditions = EXCLUDED.conditions,
        status = EXCLUDED.status,
        updated_at = NOW();
END $$;

-- 8. EVENT SOURCING LAYER
CREATE TABLE IF NOT EXISTS public.financial_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    aggregate_id UUID NOT NULL, -- Transaction ID or Wallet ID
    payload JSONB NOT NULL,
    actor TEXT DEFAULT 'system',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_financial_events_aggregate ON public.financial_events(aggregate_id);
CREATE INDEX IF NOT EXISTS idx_financial_events_type ON public.financial_events(event_type);

-- ==========================================
-- ENTERPRISE FALLBACKS (NO-REDIS MODE)
-- ==========================================

-- 1. Database-Backed Idempotency
CREATE TABLE IF NOT EXISTS public.ent_idempotency_keys (
    key TEXT PRIMARY KEY,
    client_id TEXT,
    request_path TEXT,
    status TEXT DEFAULT 'PROCESSING',
    response_status INTEGER,
    response_body JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Database-Backed Distributed Locks
CREATE TABLE IF NOT EXISTS public.ent_locks (
    lock_key TEXT PRIMARY KEY,
    acquired_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- 3. Transactional Outbox (EventBus)
CREATE TABLE IF NOT EXISTS public.outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT DEFAULT 'PENDING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS public.fraud_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
    risk_score NUMERIC NOT NULL,
    decision TEXT NOT NULL,
    flags TEXT[] NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- PAYMENT CARD PROCESSING (PCI-DSS Compliant)
CREATE TABLE IF NOT EXISTS public.card_tokens (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    masked_card_number TEXT NOT NULL,
    tokenized_card_number TEXT NOT NULL, -- Encrypted
    expiry_month INTEGER NOT NULL,
    expiry_year INTEGER NOT NULL,
    cardholder_name TEXT NOT NULL,
    card_brand TEXT NOT NULL CHECK (card_brand IN ('VISA', 'MASTERCARD', 'AMEX', 'DISCOVERY')),
    card_type TEXT DEFAULT 'CREDIT' CHECK (card_type IN ('CREDIT', 'DEBIT')),
    last_four_digits TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE', 'EXPIRED')),
    encrypted_cvv TEXT, -- Encrypted CVV for one-click payments
    billing_address JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS public.card_transactions (
    id TEXT PRIMARY KEY,
    card_token_id TEXT REFERENCES public.card_tokens(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE SET NULL,
    amount NUMERIC NOT NULL,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'AUTHORIZED', 'SETTLED', 'FAILED', 'DECLINED', 'REVERSED')),
    authorization_code TEXT,
    rrn TEXT, -- Retrieval Reference Number
    stan_number TEXT, -- System Trace Audit Number
    response_code TEXT,
    response_message TEXT,
    risk_score NUMERIC DEFAULT 0,
    fraud_flags TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    settled_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Card Transaction Audit Trail
CREATE TABLE IF NOT EXISTS public.card_transaction_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    card_transaction_id TEXT REFERENCES public.card_transactions(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT,
    actor TEXT DEFAULT 'system',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Merchant Card Acceptance Settings
CREATE TABLE IF NOT EXISTS public.merchant_card_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE,
    min_amount NUMERIC DEFAULT 0,
    max_amount NUMERIC,
    accepted_card_brands TEXT[] DEFAULT ARRAY['VISA', 'MASTERCARD'],
    avs_enabled BOOLEAN DEFAULT TRUE,
    cvv_required BOOLEAN DEFAULT TRUE,
    three_d_secure_enabled BOOLEAN DEFAULT TRUE,
    fraud_check_level TEXT DEFAULT 'MEDIUM' CHECK (fraud_check_level IN ('LOW', 'MEDIUM', 'HIGH')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(merchant_id)
);

-- Card Network Processing Fees
CREATE TABLE IF NOT EXISTS public.card_processing_fees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    card_brand TEXT NOT NULL,
    transaction_type TEXT NOT NULL,
    percentage_fee NUMERIC DEFAULT 0.025, -- 2.5% default
    fixed_fee NUMERIC DEFAULT 0.30,
    currency TEXT DEFAULT 'TZS',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for Card Processing
CREATE INDEX IF NOT EXISTS idx_card_tokens_user ON public.card_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_card_tokens_status ON public.card_tokens(status);
CREATE INDEX IF NOT EXISTS idx_card_tokens_fingerprint ON public.card_tokens(fingerprint);
CREATE INDEX IF NOT EXISTS idx_card_transactions_user ON public.card_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_card_transactions_card_token ON public.card_transactions(card_token_id);
CREATE INDEX IF NOT EXISTS idx_card_transactions_status ON public.card_transactions(status);
CREATE INDEX IF NOT EXISTS idx_card_transactions_merchant ON public.card_transactions(merchant_id);
CREATE INDEX IF NOT EXISTS idx_card_transactions_created ON public.card_transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_card_transaction_audit_user ON public.card_transaction_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_merchant_card_settings_merchant ON public.merchant_card_settings(merchant_id);

-- Enable RLS for Card Tables
ALTER TABLE public.card_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.card_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.card_transaction_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.merchant_card_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.card_processing_fees ENABLE ROW LEVEL SECURITY;

-- Card Processing RLS Policies
DROP POLICY IF EXISTS "Users manage own card tokens" ON public.card_tokens;
CREATE POLICY "Users manage own card tokens" ON public.card_tokens
    FOR ALL USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role card tokens bypass" ON public.card_tokens;
CREATE POLICY "Service role card tokens bypass" ON public.card_tokens
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Users view own card transactions" ON public.card_transactions;
CREATE POLICY "Users view own card transactions" ON public.card_transactions
    FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role card transactions bypass" ON public.card_transactions;
CREATE POLICY "Service role card transactions bypass" ON public.card_transactions
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admins view card settings" ON public.merchant_card_settings;
CREATE POLICY "Admins view card settings" ON public.merchant_card_settings
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN'));

CREATE TABLE IF NOT EXISTS public.background_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_background_jobs_status ON public.background_jobs(status);
CREATE INDEX IF NOT EXISTS idx_background_jobs_claim ON public.background_jobs(status, attempts, created_at);
CREATE INDEX IF NOT EXISTS idx_outbox_events_pending ON public.outbox_events(status, created_at);

-- 4. JWT Revocation Blocklist
CREATE TABLE IF NOT EXISTS public.revoked_tokens (
    jti TEXT PRIMARY KEY,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
