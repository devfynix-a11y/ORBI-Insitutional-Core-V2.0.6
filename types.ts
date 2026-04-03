
export type TransactionStatus = 'created' | 'pending' | 'authorized' | 'processing' | 'settled' | 'completed' | 'failed' | 'reversed' | 'refunded' | 'cancelled' | 'held_for_review';
export type TransactionPath = 'SOVEREIGN_LEDGER' | 'EXTERNAL_ROUTING';
export type TransactionType = 'deposit' | 'expense' | 'transfer' | 'escrow' | 'goal_allocation' | 'salary' | 'interest' | 'dividend' | 'refund' | 'fee' | 'bill_payment' | 'withdrawal';

export interface ThreatEvent {
    id: string;
    timestamp: string;
    priority: 'EMERGENCY' | 'CRITICAL' | 'WARNING' | 'NOTICE';
    rule: string;
    output: string;
    container: string;
    node: string;
    raw_event?: any;
}

export interface FalcoAgent {
    id: string;
    node_name: string;
    status: 'ACTIVE' | 'OFFLINE' | 'DEGRADED';
    version: string;
    kernel_module: 'READY' | 'FAULT';
    events_per_sec: number;
}

export interface TransactionStatusLog {
    status: TransactionStatus;
    timestamp: string;
    notes?: string;
}

export interface Wallet {
    id: string | number;
    name: string;
    management_tier: 'sovereign' | 'linked';
    type: 'operating' | 'tax' | 'escrow' | 'reserve' | 'mobile_money' | 'bank' | 'cash' | 'crypto' | 'system';
    balance: number;
    actualBalance: number;
    availableBalance: number;
    currency: string;
    color: string;
    icon: string;
    accountNumber?: string;
    initialBalance: number;
    createdAt?: string;
    user_id?: string;
    status?: string;
    is_locked?: boolean;
    locked_at?: string;
    lock_reason?: string;
    metadata?: any;
}

export interface UserPublicProfile {
    id: string;
    full_name: string;
    avatar_url?: string;
    customer_id?: string;
    phone?: string;
    email?: string;
    registry_type?: string;
    matched_by?: 'customer_id' | 'phone' | 'email';
}

export interface Transaction {
    id: string | number;
    referenceId?: string;
    transactionId?: string | number;
    amount: number;
    currency?: string;
    description: string;
    type: TransactionType | string;
    status: TransactionStatus;
    settlement_path?: TransactionPath;
    status_history: TransactionStatusLog[];
    date: string;
    createdAt: string;
    walletId: string | number;
    toWalletId?: string | number;
    idempotencyKey?: string;
    tax_info?: { vat: number; fee: number; gov_fee?: number; rate: number; duty?: number; };
    user_id?: string;
    status_notes?: string;
    categoryName?: string;
    notes?: string;
    peerContact?: string;
    categoryId?: string;
    linkedGoalId?: string | number;
    incomeSource?: string;
    metadata?: any;
    direction?: 'DEBIT' | 'CREDIT';
    sourceWalletName?: string;
    targetWalletName?: string;
    sender?: { id: string; name: string; customerId: string; };
    receiver?: { id: string; name: string; customerId: string; };
    counterparty?: { label: string; name: string; id: string; };
}

export interface Goal {
    id: string | number;
    name: string;
    target: number;
    current: number;
    deadline: string;
    color: string;
    icon: string;
    fundingStrategy: 'manual' | 'percentage' | 'fixed';
    linkedIncomePercentage?: number;
    monthlyTarget?: number;
    autoAllocationEnabled: boolean;
    createdAt: string;
    sourceWalletId?: string;
    user_id?: string;
    treatAsTask?: boolean;
    taskBounty?: number;
    linkedTaskId?: string;
}

export interface Category {
    id: string | number;
    name: string;
    budget: number;
    color: string;
    icon: string;
    user_id?: string;
}

export interface GoalAllocation {
    goalId: string | number;
    percentage?: number;
    fixedAmount?: number;
}

export interface User {
    id: string;
    email?: string;
    phone?: string;
    user_metadata?: any;
    role?: UserRole;
    full_name?: string;
    customer_id?: string;
    account_status?: string;
    kyc_level?: number;
    kyc_status?: string;
    id_type?: string;
    id_number?: string;
    registry_type?: string;
    app_origin?: string;
}

export interface UserProfile {
    id?: string;
    full_name?: string;
    first_name?: string;
    avatar_url?: string;
    currency?: string;
    role?: UserRole;
    dob?: string;
    address?: string;
    nationality?: string;
    phone?: string;
    account_status?: string;
    kyc_level?: number;
    kyc_status?: string;
    customer_id?: string;
    notif_push?: boolean;
    notif_email?: boolean;
    notif_security?: boolean;
    notif_financial?: boolean;
    notif_budget?: boolean;
    notif_marketing?: boolean;
    security_tx_pin_hash?: string;
    security_tx_pin_enabled?: boolean;
    security_biometric_enabled?: boolean;
    language?: 'en' | 'sw';
    created_at?: string;
}

export interface KYCRequest {
    id: string;
    user_id: string;
    full_name: string;
    id_type: 'NATIONAL_ID' | 'DRIVER_LICENSE' | 'VOTER_ID' | 'PASSPORT';
    id_number: string;
    document_url: string;
    selfie_url: string;
    status: 'PENDING' | 'APPROVED' | 'REJECTED';
    submitted_at: string;
    reviewed_at?: string;
    reviewer_id?: string;
    rejection_reason?: string;
    metadata?: any;
}

export interface UserMessage {
    id: string;
    user_id: string;
    subject: string;
    body: string;
    category: 'security' | 'update' | 'promo' | 'info';
    is_read: boolean;
    created_at: string;
}

export interface StaffMessage {
    id: string;
    sender_id: string;
    recipient_id?: string | null;
    sender_name: string;
    content: string;
    type: 'staff' | 'system' | 'alert';
    is_flagged: boolean;
    target_role?: string | null;
    tagged_user_ids?: string[] | null;
    created_at: string;
}

export interface SystemMessage {
    id: string;
    title: string;
    message: string;
    type: 'critical' | 'warning' | 'info';
}

export interface NotificationItem {
    id: string;
    message: string;
    type: NotificationType;
    priority: PriorityLevel;
    timestamp: Date;
    read: boolean;
}

export type NotificationType = 'info' | 'success' | 'warning' | 'error';
export type PriorityLevel = 'low' | 'medium' | 'high';

export interface FinancialOverview {
    totalIncome: number;
    totalExpenses: number;
    allocatedToGoals: number;
    availableBalance: number;
    netWorth: number;
    orbiBalance: number;
    savingsRate: number;
    goalProgressRate: number;
}

export interface StaffMember {
    id: string;
    email: string;
    full_name: string;
    role: UserRole;
    account_status: string;
    customer_id: string;
    avatar_url?: string;
    phone?: string;
    nationality?: string;
    address?: string;
    dob?: string;
    last_active?: string;
    created_at: string;
}

export interface DisputeCase {
    id: string;
    transactionId: string;
    userId: string;
    userName: string;
    amount: number;
    reason: string;
    status: 'OPEN' | 'REVIEW' | 'RESOLVED' | 'REJECTED';
    priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    evidencePacketHash?: string;
    resolutionNotes?: string;
    createdAt: string;
    updatedAt: string;
}

export interface SupportTicket {
    id: string;
    user_id: string;
    user_name: string;
    category: string;
    priority: PriorityLevel | 'critical';
    subject: string;
    description: string;
    status: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED';
    resolution_notes?: string;
    created_at: string;
    updated_at: string;
}

export interface ForensicReport {
    timestamp: string;
    holds: LegalHold[];
    anomalyCount: number;
    integrityStatus: 'VALID' | 'TAMPERED';
}

export interface LegalHold {
    id: string;
    targetType: 'TRANSACTION' | 'USER' | 'WALLET';
    targetId: string;
    reason: string;
    active: boolean;
    issuedBy: string;
    issuedAt: string;
    releasedAt?: string;
}

export interface RegisteredApp {
    id: string;
    name: string;
    app_id: string;
    app_token: string;
    tier: NodeTier;
    status: string;
    developer_id: string;
    created_at: string;
}

export type NodeTier = 'COMMUNITY' | 'PREMIUM' | 'INSTITUTIONAL' | 'PINNACLE';

export interface Session {
    access_token: string;
    refresh_token?: string;
    token_type: string;
    user: User;
    sub: string;
    iss: string;
    exp: number;
    expires_at: number;
    role: UserRole;
    permissions: Permission[];
    client_id?: string;
}

export interface UserSession {
    id: string;
    user_id: string;
    refresh_token_hash: string;
    device_fingerprint: string;
    ip_address: string;
    user_agent: string;
    is_revoked: boolean;
    created_at: string;
    expires_at: string;
    last_active_at: string;
    replaced_by?: string;
}

export interface UserDevice {
    id: string;
    user_id: string;
    device_fingerprint: string;
    device_name?: string;
    device_type?: string;
    user_agent?: string;
    last_active_at: string;
    is_trusted: boolean;
    status: 'active' | 'blocked' | 'pending_approval';
    created_at: string;
}

export interface UserDocument {
    id: string;
    user_id: string;
    document_type: string;
    file_url: string;
    file_name?: string;
    mime_type?: string;
    size_bytes?: number;
    status: 'pending' | 'verified' | 'rejected' | 'archived';
    uploaded_at: string;
    verified_at?: string;
    verified_by?: string;
    rejection_reason?: string;
    metadata?: any;
}

export type UserRole =
    | 'SUPER_ADMIN'
    | 'ADMIN'
    | 'IT'
    | 'AUDIT'
    | 'ACCOUNTANT'
    | 'CUSTOMER_CARE'
    | 'CONSUMER'
    | 'USER'
    | 'MERCHANT'
    | 'AGENT'
    | 'SYSTEM'
    | 'HUMAN_RESOURCE';

export type Permission = 
    | 'auth.login' | 'auth.logout' | 'auth.refresh' | 'auth.pwd_reset'
    | 'user.read' | 'user.update' | 'user.freeze'
    | 'wallet.read' | 'wallet.create' | 'wallet.update' | 'wallet.delete' | 'wallet.credit' | 'wallet.debit' | 'wallet.freeze'
    | 'transaction.create' | 'transaction.view' | 'transaction.verify' | 'transaction.reverse' | 'transaction.delete'
    | 'ledger.read' | 'ledger.write'
    | 'admin.approve' | 'admin.freeze' | 'admin.audit.read' | 'admin.user.manage'
    | 'staff.read' | 'staff.write'
    | 'provider.read' | 'provider.write'
    | 'institutional_account.read' | 'institutional_account.write'
    | 'provider_routing.read' | 'provider_routing.write'
    | 'config.ledger.read' | 'config.ledger.write'
    | 'config.fx.read' | 'config.fx.write'
    | 'config.commissions.read' | 'config.commissions.write'
    | 'reconciliation.read' | 'reconciliation.run'
    | 'device.read' | 'device.trust.manage'
    | 'kyc.review' | 'document.review' | 'service_access.review'
    | 'system.wallet.credit' | 'system.wallet.debit' | 'goal.read' | 'goal.create' | 'goal.update' | 'goal.delete'
    | 'category.read' | 'category.create' | 'category.update' | 'category.delete'
    | 'task.read' | 'task.create' | 'task.update' | 'task.delete'
    | 'merchant.read' | 'merchant.create' | 'merchant.update' | 'merchant.settlement'
    | 'agent.cash.deposit' | 'agent.cash.withdraw' | 'agent.float.manage';

export interface UserActivity {
    id: string;
    user_id: string;
    activity_type: 'login' | 'logout' | 'login_failed' | 'network_attack_blocked' | 'WAF_INTERCEPT' | 'security_update' | 'profile_update' | 'biometric_login' | 'password_change' | 'settings_change' | 'GOVERNANCE_STATUS_UPDATE' | 'GOVERNANCE_ROLE_ELEVATION' | 'REGULATORY_MATRIX_UPDATE' | 'SENSITIVE_ACTION_VERIFIED' | 'SENSITIVE_ACTION_FAILED';
    status: 'success' | 'failed' | 'info' | 'blocked';
    device_info: string;
    ip_address: string;
    location: string;
    created_at: string;
    fingerprint?: string;
}

export interface Task {
    id: string;
    text: string;
    completed: boolean;
    createdAt: string;
    user_id?: string;
    linkedGoalId?: string | number;
    bounty?: number;
    dueDate?: string;
}

export type DataLoadStatus = 'idle' | 'loading' | 'success' | 'error';

export interface EncryptedData {
    version: number;
    iv: string;
    ciphertext: string;
    tag?: string;
    timestamp: number;
    keyId: string;
    algorithm: string;
    aad?: string;
}

export interface AuditLogEntry {
    id: string;
    prevHash: string;
    hash: string;
    timestamp: string;
    type: AuditEventType;
    actor_id: string;
    actor_name: string;
    action: string;
    metadata: any;
    signature: string;
    verificationStatus: 'UNCHECKED' | 'VERIFIED' | 'FAILED';
    transaction_id?: string | number;
}

export type AuditEventType = 'SECURITY' | 'IDENTITY' | 'ADMIN' | 'FINANCIAL' | 'COMPLIANCE' | 'FRAUD' | 'INFRASTRUCTURE';

export interface LedgerEntry {
    transactionId: string;
    walletId: string | null;
    type: 'CREDIT' | 'DEBIT';
    amount: number;
    currency: string;
    description: string;
    timestamp: string;
}

export interface RegulatoryConfig {
    id: string;
    vat_rate: number;
    service_fee_rate: number;
    gov_fee_rate: number;
    stamp_duty_fixed: number;
    is_active: boolean;
    updated_at: string;
    updated_by?: string;
    updated_by_name?: string;
}

export interface PricingRule {
    id: string;
    method: string;
    feePercentage: number;
    fixedFee: number;
    fxMargin: number;
    status: 'ACTIVE' | 'BETA' | 'ALPHA' | 'DEPRECATED';
    tier: 'INSTITUTIONAL' | 'RETAIL';
    updatedAt: string;
}

export interface AIReport {
    id?: string;
    user_id?: string;
    timestamp: string;
    health: { score: number; healthLevel: string; breakdown: { savings: number; budget: number; goals: number; } };
    metrics: { runwayDays: number; volatilityScore: number; strategicAlignment: number; burnRate: number; };
    spendingAnalysis: { 
        totalSpent: number;
        topCategories: any[];
        habits: { patterns: any[]; budgetAlerts: any[]; savingsTips: SavingsTip[]; }
    };
    summary: { strengths: string[]; areasForImprovement: string[]; immediateActions: string[]; longTermFocus: string[]; };
    fullSummary: string;
}

export interface SavingsTip {
    title: string;
    tip: string;
    potentialSaving: number;
    category: string;
    effort: 'EASY' | 'MEDIUM' | 'HARD';
    priority: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface ThreatReport {
    riskScore: number;
    status: 'OPTIMAL' | 'ELEVATED' | 'CRITICAL';
    recommendation: 'ALLOW' | 'BLOCK';
    anomalies: string[];
}

export interface RegulatoryReport {
    id: string;
    type: 'SAR' | 'CTR';
    status: 'PREPARING' | 'SUBMITTED';
    periodStart: string;
    periodEnd: string;
    generatedAt: string;
    riskSummary: string;
}

export interface MonitoringEndpoint {
    id: string;
    name: string;
    url: string;
    type: 'PROMETHEUS' | 'GRAFANA';
    status: 'ACTIVE' | 'INACTIVE';
    auth_header?: string;
}

export interface ReconReport {
    id: string;
    date: string;
    provider_id: string;
    internal_total: number;
    external_total: number;
    delta: number;
    discrepancies: string[];
    status: 'MATCHED' | 'MISMATCH';
}

export interface InfraSnapshot {
    id: string;
    actor_id: string;
    snapshot_data: any;
    created_at: string;
}

export interface RuleResult {
    ruleId: string;
    passed: boolean;
    severity: RiskSeverity;
    message: string;
    evidence?: any;
    shadowMode?: boolean;
}

export type RiskSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ValidationReport {
    timestamp: string;
    passed: boolean;
    score: number;
    results: RuleResult[];
    decision: 'ALLOW' | 'CHALLENGE' | 'BLOCK';
    version: string;
    metadata: any;
}

export interface MLFeatures {
    transaction_amount: number;
    transaction_amount_usd: number;
    user_avg_transaction: number;
    amount_zscore: number;
    transactions_last_hour: number;
    hour_sin: number;
    hour_cos: number;
    day_sin: number;
    day_cos: number;
    is_high_risk_country: boolean;
    account_age_days: number;
    device_user_count: number;
}

export interface FraudAlert {
    id: string;
    transactionId: string;
    userId: string;
    riskScore: number;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    ruleTriggered: string;
    status: 'OPEN' | 'CLOSED';
    timestamp: string;
}

export interface ComplianceResult {
    passed: boolean;
    riskScore: number;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    flags: string[];
    decision: 'PASS' | 'HOLD' | 'BLOCK';
    reason?: string;
}

export interface ApprovalRequest {
    id: string;
    type: string;
    targetId: string;
    requesterId: string;
    requesterName: string;
    status: 'PENDING' | 'APPROVED' | 'REJECTED';
    metadata?: any;
    createdAt: string;
}

export interface RestEndpointConfig {
    url: string;
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    headers?: Record<string, string>;
    payload_template?: Record<string, any>;
    response_mapping?: {
        id_field?: string;
        status_field?: string;
        error_field?: string;
        balance_field?: string;
        token_field?: string;
        expires_in_field?: string;
        message_field?: string;
    };
}

export interface ProviderAuthConfig extends RestEndpointConfig {
    type?: 'oauth2_client_credentials' | 'api_key' | 'static_token' | 'none';
    cache_ttl_seconds?: number;
}

export type RailType =
    | 'MOBILE_MONEY'
    | 'BANK'
    | 'CARD_GATEWAY'
    | 'CRYPTO'
    | 'WALLET';

export type MoneyOperation =
    | 'AUTH'
    | 'ACCOUNT_LOOKUP'
    | 'COLLECTION_REQUEST'
    | 'COLLECTION_STATUS'
    | 'DISBURSEMENT_REQUEST'
    | 'DISBURSEMENT_STATUS'
    | 'PAYOUT_REQUEST'
    | 'PAYOUT_STATUS'
    | 'REVERSAL_REQUEST'
    | 'REVERSAL_STATUS'
    | 'BALANCE_INQUIRY'
    | 'TRANSACTION_LOOKUP'
    | 'WEBHOOK_VERIFY'
    | 'BENEFICIARY_VALIDATE';

export interface UnifiedPaymentIntent {
    intentId: string;
    tenantId?: string;
    rail: RailType;
    providerCode?: string;
    operation: MoneyOperation;
    countryCode?: string;
    currency: string;
    amount?: string;
    reference: string;
    description?: string;
    source?: {
        walletId?: string;
        msisdn?: string;
        bankAccount?: string;
        accountRef?: string;
    };
    destination?: {
        walletId?: string;
        msisdn?: string;
        bankAccount?: string;
        merchantCode?: string;
        accountRef?: string;
    };
    customer?: {
        fullName?: string;
        msisdn?: string;
        email?: string;
    };
    metadata?: Record<string, unknown>;
}

export interface ProviderResolutionInput {
    rail: RailType;
    operation: MoneyOperation;
    countryCode?: string;
    currency?: string;
    tenantId?: string;
    preferredProviderCode?: string;
    preferredProviderId?: string;
}

export interface ProviderRoutingDecision {
    providerId: string;
    providerCode: string;
    rail: RailType;
    operation: MoneyOperation;
    source: 'routing_rule' | 'registry_fallback';
    ruleId?: string;
    priority?: number;
    countryCode?: string;
    currency?: string;
    preferredProviderCode?: string;
    preferredProviderId?: string;
    resolvedAt: string;
}

export type OfflineMessageType =
    | 'APP_OFFLINE_REQUEST'
    | 'APP_OFFLINE_CONFIRM'
    | 'BALANCE_CHECK'
    | 'MINI_STATEMENT'
    | 'INTERNAL_TRANSFER'
    | 'MERCHANT_PAYMENT'
    | 'WITHDRAWAL_REQUEST'
    | 'CHALLENGE_RESPONSE'
    | 'HELP'
    | 'UNKNOWN';

export type OfflineSessionStatus =
    | 'RECEIVED'
    | 'PARSED'
    | 'VALIDATED'
    | 'PENDING_CONFIRMATION'
    | 'FORWARDED_TO_ORBI'
    | 'CHALLENGE_SENT'
    | 'CONFIRMED'
    | 'SUCCESS'
    | 'FAILED'
    | 'EXPIRED'
    | 'REJECTED';

export interface ResolvedProviderConfig {
    providerId: string;
    providerCode: string;
    providerName: string;
    rail: RailType;
    operation: MoneyOperation;
    authType?: string;
    baseUrl?: string;
    timeoutMs?: number;
    requestTemplate?: Record<string, unknown>;
    responseMapping?: Record<string, unknown>;
    extraConfig?: Record<string, unknown>;
    routingDecision?: ProviderRoutingDecision;
}

export type ProviderGroup = 'Mobile' | 'Bank' | 'Gateways' | 'Crypto';
export type ProviderCheckoutMode =
    | 'redirect'
    | 'embedded'
    | 'tokenized'
    | 'server_to_server'
    | 'ussd'
    | 'stk_push'
    | 'manual';
export type ProviderChannel =
    | 'bank_transfer'
    | 'bank_account'
    | 'mobile_money'
    | 'card'
    | 'paypal'
    | 'crypto'
    | 'ussd'
    | 'qr'
    | 'checkout_link';

export interface FinancialPartnerMetadata {
    group?: ProviderGroup | string;
    provider_group?: ProviderGroup | string;
    rail?: RailType | string;
    brand_name?: string;
    display_name?: string;
    display_icon?: string;
    icon?: string;
    color?: string;
    checkout_mode?: ProviderCheckoutMode | string;
    channels?: ProviderChannel[] | string[];
    sort_order?: number;
    region?: string;
    currency?: string;
    countries?: string[];
    capabilities?: string[];
    operations?: MoneyOperation[] | string[];
    routing_priority?: number;
    provider_code?: string;
    supports_webhooks?: boolean;
    supports_polling?: boolean;
    [key: string]: any;
}

export interface FinancialPartner {
    id: string;
    name: string;
    /**
     * Legacy field kept for backward compatibility only.
     * Dynamic integrations should use `type`, `logic_type`, and `mapping_config`.
     */
    provider_type?: string;
    type?: 'mobile_money' | 'bank' | 'card' | 'crypto';
    icon?: string;
    color?: string;
    status: 'ACTIVE' | 'INACTIVE' | 'MAINTENANCE';
    client_id?: string;
    client_secret?: string;
    api_key?: string;
    api_base_url?: string;
    merchant_id?: string;
    webhook_secret?: string;
    connection_secret?: string;
    logic_type?: 'REGISTRY' | 'GENERIC_REST' | 'SPECIALIZED';
    token_cache?: string;
    token_expiry?: number;
    provider_metadata?: FinancialPartnerMetadata;
    mapping_config?: ProviderRegistryConfig | Record<string, any>;
    supported_currencies?: string[];
    provider_fee?: number;
    fixed_fee?: number;
    settlement_fee?: number;
    created_at?: string;
    updated_at?: string;
    created_by?: string;
    updated_by?: string;
}

export type InstitutionalAccountRole =
    | 'MAIN_COLLECTION'
    | 'FEE_COLLECTION'
    | 'TAX_COLLECTION'
    | 'TRANSFER_SAVINGS';
export type PlatformFeeFlowCode =
    | 'CORE_TRANSACTION'
    | 'INTERNAL_TRANSFER'
    | 'EXTERNAL_PAYMENT'
    | 'WITHDRAWAL'
    | 'DEPOSIT'
    | 'EXTERNAL_TO_INTERNAL'
    | 'INTERNAL_TO_EXTERNAL'
    | 'EXTERNAL_TO_EXTERNAL'
    | 'CARD_SETTLEMENT'
    | 'GATEWAY_SETTLEMENT'
    | 'FX_CONVERSION'
    | 'TENANT_SETTLEMENT_PAYOUT'
    | 'MERCHANT_PAYMENT'
    | 'AGENT_CASH_DEPOSIT'
    | 'AGENT_CASH_WITHDRAWAL'
    | 'AGENT_REFERRAL_COMMISSION'
    | 'AGENT_CASH_COMMISSION'
    | 'SYSTEM_OPERATION';
export type InstitutionalAccountStatus = 'ACTIVE' | 'INACTIVE';
export type ExternalFundMovementDirection =
    | 'INTERNAL_TO_EXTERNAL'
    | 'EXTERNAL_TO_INTERNAL'
    | 'EXTERNAL_TO_EXTERNAL';
export type ExternalFundMovementStatus =
    | 'previewed'
    | 'initiated'
    | 'processing'
    | 'completed'
    | 'failed'
    | 'recorded'
    | 'reversed';

export interface InstitutionalPaymentAccount {
    id: string;
    role: InstitutionalAccountRole;
    provider_id?: string | null;
    bank_name: string;
    account_name: string;
    account_number: string;
    currency: string;
    country_code?: string | null;
    status: InstitutionalAccountStatus;
    is_primary?: boolean;
    metadata?: Record<string, any>;
    created_at?: string;
    updated_at?: string;
}

export interface PlatformFeeConfig {
    id: string;
    name: string;
    flow_code: PlatformFeeFlowCode | string;
    transaction_type?: string | null;
    operation_type?: string | null;
    direction?: string | null;
    rail?: RailType | string | null;
    channel?: string | null;
    provider_id?: string | null;
    currency?: string | null;
    country_code?: string | null;
    percentage_rate?: number;
    fixed_amount?: number;
    minimum_fee?: number;
    maximum_fee?: number | null;
    tax_rate?: number;
    gov_fee_rate?: number;
    stamp_duty_fixed?: number;
    priority?: number;
    status?: 'ACTIVE' | 'INACTIVE';
    metadata?: Record<string, any>;
    created_at?: string;
    updated_at?: string;
}

export interface PlatformFeeComputation {
    flowCode: string;
    configId?: string | null;
    configName?: string | null;
    currency: string;
    amount: number;
    percentageRate: number;
    fixedAmount: number;
    minimumFee: number;
    maximumFee?: number | null;
    taxRate: number;
    govFeeRate: number;
    stampDutyFixed: number;
    percentageFee: number;
    serviceFee: number;
    taxAmount: number;
    govFeeAmount: number;
    totalFee: number;
    netAmount: number;
    metadata?: Record<string, any>;
}

export interface ExternalFundMovement {
    id: string;
    user_id: string;
    direction: ExternalFundMovementDirection;
    status: ExternalFundMovementStatus;
    provider_id?: string | null;
    institutional_source_account_id?: string | null;
    institutional_target_account_id?: string | null;
    transaction_id?: string | null;
    source_wallet_id?: string | null;
    target_wallet_id?: string | null;
    gross_amount: number;
    net_amount: number;
    fee_amount?: number;
    tax_amount?: number;
    currency: string;
    description?: string;
    external_reference?: string | null;
    source_external_ref?: string | null;
    target_external_ref?: string | null;
    metadata?: Record<string, any>;
    created_at?: string;
    updated_at?: string;
}

export interface ProviderCallbackConfig {
    reference_field?: string;
    status_field?: string;
    message_field?: string;
    event_id_field?: string;
    replay_key_field?: string;
    signature_header?: string;
    signature_prefix?: string;
    signature_encoding?: 'hex' | 'base64';
    signature_payload_mode?: 'raw' | 'timestamp.raw';
    timestamp_header?: string;
    timestamp_field?: string;
    max_age_seconds?: number;
    success_values?: Array<string | number>;
    pending_values?: Array<string | number>;
    failed_values?: Array<string | number>;
    completed_values?: Array<string | number>;
}

export interface ProviderRegistryConfig {
    service_root?: string;
    service_roots?: Record<string, string>;
    operations?: Partial<Record<MoneyOperation, RestEndpointConfig>>;
    auth?: ProviderAuthConfig;
    endpoint?: string;
    method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    headers?: Record<string, string>;
    payload_template?: Record<string, any>;
    response_mapping?: {
        id_field?: string;
        status_field?: string;
        error_field?: string;
        message_field?: string;
    };
    stk_push?: RestEndpointConfig;
    disbursement?: RestEndpointConfig;
    check_status?: RestEndpointConfig;
    balance?: RestEndpointConfig;
    callback?: ProviderCallbackConfig;
}

export interface TransferTaxRule {
    id: string;
    name: string;
    description: string;
    rate: number;
    is_active: boolean;
}

export type MerchantCategory = 'bundles' | 'internet' | 'utilities' | 'entertainment' | 'education' | 'government' | 'business' | 'general';

export interface DigitalMerchant {
    id: string;
    name: string;
    category: MerchantCategory;
    icon: string;
    color: string;
    account_label: string;
    status: 'ACTIVE' | 'INACTIVE';
    created_at: string;
}

export type RiskLevel = RiskSeverity;

export interface Condition {
    field: string;
    operator: 'eq' | 'neq' | 'gt' | 'lt' | 'contains';
    value: any;
}

export interface RuleDefinition {
    id: string;
    active: boolean;
    name: string;
    severity: RiskSeverity;
    description: string;
    parameters?: any;
}

export interface TransactionLimits {
    max_per_transaction: number;
    max_daily_total: number;
    max_monthly_total: number;
    category_limits: Record<string, number>;
}

// FIX: Added missing AppData interface to resolve module resolution errors
export interface ReconciliationReport {
    id: string;
    type: 'INTERNAL' | 'SYSTEM' | 'EXTERNAL';
    expected_balance: number;
    actual_balance: number;
    difference: number;
    status: 'MATCHED' | 'MISMATCH' | 'INVESTIGATING';
    metadata?: any;
    created_at: string;
}

export interface AppData {
    transactions: Transaction[];
    wallets: Wallet[];
    financialGoals: Goal[];
    categories: Category[];
    tasks: Task[];
    userProfile: UserProfile;
    goalAllocations: GoalAllocation[];
    messages: UserMessage[];
    systemMessages: SystemMessage[];
}

// FIX: Added missing AuthContextType interface to resolve type errors in AuthProvider.tsx
export interface AuthContextType {
    user: User | null;
    session: Session | null;
    loading: boolean;
    error: any;
    nodeTier: NodeTier;
    signIn: (email: string, password: string) => Promise<{ data: any, error: any }>;
    signUp: (email: string, password: string, metadata?: any) => Promise<{ data: any, error: any }>;
    signOut: () => Promise<void>;
    initiatePhoneLogin: (phone: string) => Promise<any>;
    verifyPhoneLogin: (phone: string, token: string) => Promise<any>;
    completeProfile: (phone: string, updates: any) => Promise<any>;
}
