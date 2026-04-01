import 'dotenv/config';
import { registerInternalRoutes, mountInternalRoutes } from '../routes/internal/index.js';
import { registerAdminRoutes, mountAdminRoutes } from '../routes/admin/index.js';
import { mountPublicRoutes, registerLegacyGatewayRoute, registerMonitoringRoutes, registerTerminalHandlers, registerTopLevelPublicRoutes } from '../routes/public/index.js';
import { registerAuthUserRoutes } from '../routes/public/authUser.js';
import { registerSupportOpsRoutes } from '../routes/public/supportOps.js';
import { registerAdminOpsRoutes } from '../routes/public/adminOps.js';
import { registerCommerceRoutes } from '../routes/public/commerce.js';
import { registerProviderRoutes, mountProviderRoutes } from '../routes/providers/index.js';
import { validate } from '../middleware/validation/validate.js';
import { authenticate, adminOnly, resolveSessionRole, requireRole, resolveSessionRegistryType, mapServiceRoleToRegistryType, requireSessionPermission } from '../middleware/auth/sessionAuth.js';
import { ALLOWED_ORIGINS, configureCoreSecurityMiddleware, createGlobalIpLimiter } from '../middleware/security/setup.js';
import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { createServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { Server as LogicCore } from '../../backend/server.js';
import { Sentinel } from '../../backend/security/sentinel.js';
import { WAF } from '../../backend/security/waf.js';
import { getSupabase, getAdminSupabase } from '../../backend/supabaseClient.js';
import { BankingEngineService } from '../../backend/ledger/transactionEngine.js';
import { Audit } from '../../backend/security/audit.js';
import { ResilienceEngine } from '../../backend/infrastructure/ResilienceEngine.js';
import { Webhooks } from '../../backend/payments/webhookHandler.js';
import { PolicyEngine } from '../../backend/ledger/PolicyEngine.js';
import { ConfigClient } from '../../backend/infrastructure/RulesConfigClient.js';
import { 
    LoginSchema, SignUpSchema, PaymentIntentSchema, 
    WalletCreateSchema, WalletLockSchema, WalletUnlockSchema, GoalCreateSchema, GoalUpdateSchema, KYCSubmitSchema, KYCReviewSchema,
    AccountStatusUpdateSchema, UserProfileUpdateSchema, StaffCreateSchema, StaffAdminUpdateSchema, StaffPasswordResetSchema, ManagedIdentityCreateSchema, BootstrapAdminSchema,
    DeviceRegisterSchema, DeviceTrustSchema, DocumentUploadSchema, DocumentVerifySchema, ServiceCustomerRegistrationSchema,
    ServiceAccessRequestCreateSchema, ServiceAccessRequestReviewSchema
} from '../../backend/security/schemas.js';
import { z } from 'zod';
import { RedisClusterFactory } from '../../backend/infrastructure/RedisClusterFactory.js';
import { AuthService } from '../../iam/authService.js';
// emailService removed as per user request
import multer from 'multer';
import { Auth as NewAuth } from '../../backend/src/modules/auth/auth.controller.js';
import { ReconEngine as LegacyRecon } from '../../backend/ledger/reconciliationService.js';
import { ReconciliationEngine as ReconEngine } from '../../backend/ledger/reconciliationEngine.js';
import { authenticateApiKey } from '../../backend/middleware/apiKeyAuth.js';
import { EntProcessor } from '../../backend/enterprise/wealth/EnterprisePaymentProcessor.js';
import { PartnerRegistry } from '../../backend/admin/partnerRegistry.js';
import { TransactionService } from '../../ledger/transactionService.js';
import { FXEngine } from '../../backend/ledger/FXEngine.js';
import { NotificationSubscriber } from '../../backend/infrastructure/NotificationSubscriber.js';
import { OrbiKnowledge } from '../constants/orbiKnowledge.js';
import { continuousSessionMonitor } from '../../backend/src/middleware/session-monitor.middleware.js';
import { TransactionSigning } from '../../backend/src/modules/transaction/signing.service.js';
import { GoogleGenAI, Type } from "@google/genai";
import { RecoveryService } from '../../services/security/recoveryService.js';
import { OTPService } from '../../backend/security/otpService.js';
import { Messaging } from '../../backend/features/MessagingService.js';
import { ServiceActorOps } from '../../backend/features/ServiceActorOps.js';
import gatewayRoutes from '../../backend/payments/gatewayRoutes.js';
import { settlementScheduler } from '../../backend/payments/settlementScheduler.js';
import { KMS } from '../../backend/security/kms.js';
import { DataVault } from '../../backend/security/encryption.js';

// Helper for Gemini calls with retry logic
async function callGeminiWithRetry(ai: GoogleGenAI, params: any, retries = 3, delay = 1000): Promise<any> {
    try {
        return await ai.models.generateContent(params);
    } catch (e: any) {
        if (retries > 0 && e.status === 503) {
            console.warn(`[Gemini] 503 error, retrying in ${delay}ms... (${retries} retries left)`);
            await new Promise(resolve => setTimeout(resolve, delay));
            return callGeminiWithRetry(ai, params, retries - 1, delay * 2);
        }
        throw e;
    }
}

// --- STARTUP VALIDATION ---
const requiredEnv = [
    'JWT_SECRET',
    'RP_ID',
    'ORBI_WEB_ORIGIN',
    'ORBI_ANDROID_APP_HASH',
    'ORBI_MOBILE_ORIGIN',
    'KMS_MASTER_KEY',
    'WORKER_SECRET'
];

for (const key of requiredEnv) {
    if (process.env.NODE_ENV === 'production' && !process.env[key]) {
        console.error(`[Startup] CRITICAL_FAILURE: Missing required environment variable: ${key}`);
        process.exit(1);
    }
}

if (process.env.NODE_ENV === 'production') {
    if (
        process.env.REDIS_TLS_ENABLED === 'true' &&
        process.env.REDIS_ALLOW_INSECURE_TLS === 'true'
    ) {
        console.error('[Startup] CRITICAL_FAILURE: REDIS_ALLOW_INSECURE_TLS cannot be enabled in production.');
        process.exit(1);
    }

    if (process.env.ORBI_ANDROID_APP_HASH && !process.env.ORBI_ANDROID_PACKAGE_NAME) {
        console.error('[Startup] CRITICAL_FAILURE: ORBI_ANDROID_PACKAGE_NAME is required when ORBI_ANDROID_APP_HASH is configured.');
        process.exit(1);
    }
}

const app = express();
const httpServer = createServer(app);

// Configure Multer for memory storage
const upload = multer({ 
    storage: multer.memoryStorage(), 
    limits: { fileSize: 20 * 1024 * 1024 } 
});

// PORT CONFIGURATION
// Render/Production requires process.env.PORT
const PORT = Number(process.env.PORT) || 3000;

// Enable trust proxy for correct IP detection behind Render/Nginx
app.set('trust proxy', 1);

// Serve static files from the 'public' directory
app.use(express.static('public'));

/**
 * ORBI SOVEREIGN GATEWAY (V28.0 Platinum)
 * ---------------------------------------
 * Production-hardened RESTful API with Zod validation and Sentinel AI.
 */

// 1. INFRASTRUCTURE SECURITY GATES
const redisAvailable = RedisClusterFactory.isAvailable();
const redisClient = redisAvailable ? RedisClusterFactory.getClient('monitor') : null;
const allowProcessLocalIdempotency =
    process.env.ORBI_ALLOW_PROCESS_LOCAL_IDEMPOTENCY === 'true';
const gatewayBackgroundJobsEnabled =
    process.env.ORBI_ENABLE_GATEWAY_BACKGROUND_JOBS !== 'false';
const legacyApiGatewayEnabled =
    process.env.ORBI_ENABLE_LEGACY_API_GATEWAY === 'true';
const legacyBiometricAliasesEnabled =
    process.env.ORBI_ENABLE_LEGACY_BIOMETRIC_ROUTES === 'true';
const sandboxRoutesEnabled =
    process.env.ORBI_ENABLE_SANDBOX_ROUTES === 'true';
const messagingTestRoutesEnabled =
    process.env.ORBI_ENABLE_MESSAGING_TEST_ROUTES === 'true';
const idempotencyTtlSeconds = Number(process.env.ORBI_IDEMPOTENCY_TTL_SECONDS || 60 * 60);

// IDEMPOTENCY CACHE
// Redis is authoritative. Process-local fallback is disabled by default because
// it is unsafe in horizontally scaled runtimes.
configureCoreSecurityMiddleware(app, {
    redisAvailable,
    redisClient,
    allowProcessLocalIdempotency,
    idempotencyTtlSeconds,
});

// --- FORENSIC MONITORING API ---
registerMonitoringRoutes(app, {
    authenticateApiKey,
    ReconEngine,
});

const globalIpLimiter = createGlobalIpLimiter(redisAvailable, redisClient);

registerTopLevelPublicRoutes(app, {
    ResilienceEngine,
    LogicCore,
});

const syncUserIdentityClassification = async (
    userId: string,
    updates: { role: string; registryType: string; metadata?: Record<string, any> },
) => {
    const adminSb = getAdminSupabase();
    if (!adminSb) throw new Error('DB_OFFLINE');

    const normalizedRole = String(updates.role).trim().toUpperCase();
    const normalizedRegistryType = String(updates.registryType).trim().toUpperCase();

    const { data: authUserResult, error: authUserError } = await adminSb.auth.admin.getUserById(userId);
    if (authUserError) throw new Error(authUserError.message);
    const currentMetadata = authUserResult?.user?.user_metadata || {};

    const { error: profileError } = await adminSb
        .from('users')
        .update({
            role: normalizedRole,
            registry_type: normalizedRegistryType,
        })
        .eq('id', userId);
    if (profileError) throw new Error(profileError.message);

    const { error: authUpdateError } = await adminSb.auth.admin.updateUserById(userId, {
        user_metadata: {
            ...currentMetadata,
            role: normalizedRole,
            registry_type: normalizedRegistryType,
            ...(updates.metadata || {}),
        },
    });
    if (authUpdateError) throw new Error(authUpdateError.message);

    if (normalizedRole === 'AGENT') {
        const { data: userRow } = await adminSb
            .from('users')
            .select('full_name')
            .eq('id', userId)
            .maybeSingle();

        await adminSb.from('agents').upsert({
            user_id: userId,
            display_name: userRow?.full_name || 'Agent',
            status: 'active',
            commission_enabled: true,
            metadata: updates.metadata || {},
        }, { onConflict: 'user_id' });
    }
};

// Continuous Session Monitoring Middleware
app.use('/api/v1', continuousSessionMonitor);

// 3. HEALTH & TELEMETRY NODE
app.get('/', (req, res) => {
    res.json({
        status: 'ONLINE',
        service: 'ORBI SOVEREIGN NODE',
        version: '28.0.0',
        docs: '/v1/docs' // Placeholder for docs
    });
});

app.get(['/health', '/heath'], async (req, res) => {
    const breakerStates = ResilienceEngine.getCircuitStates();
    const ledgerIntegrity = await LogicCore.getAuditTrail().then(logs => logs.length > 0).catch(() => false);
    
    res.json({
        status: 'NOMINAL',
        node: process.env.RENDER_INSTANCE_ID || 'DPS-PRIMARY-RELAY',
        version: '28.0.0',
        uptime: (process as any).uptime(),
        circuits: breakerStates,
        ledger: ledgerIntegrity ? 'VERIFIED' : 'PENDING_SYNC',
        ts: Date.now()
    });
});

// 3.5 BROKER MONITORING
let lastBrokerHeartbeat: any = null;

app.post('/api/broker/heartbeat', (req, res) => {
    const providedSecret = req.get('x-worker-secret') || req.get('x-orbi-worker-secret');
    if (!providedSecret || providedSecret !== process.env.WORKER_SECRET) {
        return res.status(403).json({ success: false, error: 'UNAUTHORIZED_WORKER' });
    }
    lastBrokerHeartbeat = {
        ...req.body,
        receivedAt: new Date().toISOString()
    };
    res.json({ success: true });
});

app.get('/api/broker/health', (req, res) => {
    if (!lastBrokerHeartbeat) {
        return res.status(503).json({ 
            status: 'OFFLINE', 
            error: 'No heartbeat received from broker' 
        });
    }

    const lastSeen = new Date(lastBrokerHeartbeat.receivedAt).getTime();
    const now = Date.now();
    const diff = (now - lastSeen) / 1000;

    if (diff > 120) { // 2 minutes timeout
        return res.status(503).json({ 
            status: 'STALE', 
            lastSeen: lastBrokerHeartbeat.receivedAt,
            error: `Broker heartbeat is ${Math.round(diff)}s old`
        });
    }

    res.json({
        status: 'ONLINE',
        nodeId: lastBrokerHeartbeat.nodeId,
        isInitialized: lastBrokerHeartbeat.isInitialized,
        lastPollingCycle: lastBrokerHeartbeat.lastPollingCycle,
        lastSeen: lastBrokerHeartbeat.receivedAt,
        latency: Math.round(diff * 1000) + 'ms'
    });
});

// 4. RESTFUL API ROUTES (V1)
// --- Internal Worker Routes ---
const internal = express.Router();
registerInternalRoutes(internal);
mountInternalRoutes(app, internal);

const queryStringValue = (value: unknown) => {
    if (Array.isArray(value)) {
        return value.length ? String(value[0]) : undefined;
    }
    if (typeof value === 'string') {
        return value;
    }
    return undefined;
};

const TransactionIssueSchema = z.object({
    reason: z.string().min(5).max(500),
});

const TransactionAuditDecisionSchema = z.object({
    passed: z.boolean(),
    notes: z.string().min(3).max(500),
});

const ProviderRoutingRuleSchema = z.object({
    rail: z.enum(['MOBILE_MONEY', 'BANK', 'CARD_GATEWAY', 'CRYPTO', 'WALLET']),
    countryCode: z.string().min(2).max(3).optional(),
    currency: z.string().length(3).optional(),
    operationCode: z.enum([
        'AUTH',
        'ACCOUNT_LOOKUP',
        'COLLECTION_REQUEST',
        'COLLECTION_STATUS',
        'DISBURSEMENT_REQUEST',
        'DISBURSEMENT_STATUS',
        'PAYOUT_REQUEST',
        'PAYOUT_STATUS',
        'REVERSAL_REQUEST',
        'REVERSAL_STATUS',
        'BALANCE_INQUIRY',
        'TRANSACTION_LOOKUP',
        'WEBHOOK_VERIFY',
        'BENEFICIARY_VALIDATE',
    ]),
    providerId: z.string().uuid(),
    priority: z.coerce.number().int().min(1).optional(),
    status: z.enum(['ACTIVE', 'INACTIVE']).optional(),
    conditions: z.record(z.string(), z.unknown()).optional(),
});

const PlatformFeeConfigSchema = z.object({
    name: z.string().min(1),
    flowCode: z.enum([
        'CORE_TRANSACTION',
        'INTERNAL_TRANSFER',
        'EXTERNAL_PAYMENT',
        'WITHDRAWAL',
        'DEPOSIT',
        'EXTERNAL_TO_INTERNAL',
        'INTERNAL_TO_EXTERNAL',
        'EXTERNAL_TO_EXTERNAL',
        'CARD_SETTLEMENT',
        'GATEWAY_SETTLEMENT',
        'FX_CONVERSION',
        'TENANT_SETTLEMENT_PAYOUT',
        'MERCHANT_PAYMENT',
        'AGENT_CASH_DEPOSIT',
        'AGENT_CASH_WITHDRAWAL',
        'AGENT_REFERRAL_COMMISSION',
        'AGENT_CASH_COMMISSION',
        'SYSTEM_OPERATION',
    ]),
    transactionType: z.string().optional(),
    operationType: z.string().optional(),
    direction: z.string().optional(),
    rail: z.enum(['MOBILE_MONEY', 'BANK', 'CARD_GATEWAY', 'CRYPTO', 'WALLET']).optional(),
    channel: z.string().optional(),
    providerId: z.string().uuid().optional(),
    currency: z.string().length(3).optional(),
    countryCode: z.string().min(2).max(3).optional(),
    percentageRate: z.coerce.number().min(0).optional(),
    fixedAmount: z.coerce.number().min(0).optional(),
    minimumFee: z.coerce.number().min(0).optional(),
    maximumFee: z.coerce.number().min(0).optional(),
    taxRate: z.coerce.number().min(0).optional(),
    govFeeRate: z.coerce.number().min(0).optional(),
    stampDutyFixed: z.coerce.number().min(0).optional(),
    priority: z.coerce.number().int().min(0).optional(),
    status: z.enum(['ACTIVE', 'INACTIVE']).optional(),
    metadata: z.record(z.string(), z.unknown()).optional(),
});

// 11. ADMIN PARTNER REGISTRY ROUTES
const admin = express.Router();
registerAdminRoutes(admin, authenticate as any);
mountAdminRoutes(app, admin);

const v1 = express.Router();
const gatewayV1 = express.Router();

const BillReserveCreateSchema = z.object({
    provider_name: z.string().min(2),
    bill_type: z.string().min(2),
    source_wallet_id: z.string().uuid().optional(),
    currency: z.string().min(3).max(8).optional(),
    due_pattern: z.enum(['WEEKLY', 'MONTHLY', 'CUSTOM']).optional(),
    due_day: z.coerce.number().int().min(1).max(31).optional(),
    reserve_mode: z.enum(['FIXED', 'PERCENT']).optional(),
    reserve_amount: z.coerce.number().nonnegative(),
});

const SharedPotCreateSchema = z.object({
    name: z.string().min(2),
    purpose: z.string().optional(),
    currency: z.string().min(3).max(8).optional(),
    target_amount: z.coerce.number().nonnegative().optional(),
    access_model: z.enum(['INVITE', 'PRIVATE', 'ORG']).optional(),
});

const BillReserveUpdateSchema = BillReserveCreateSchema.partial().extend({
    is_active: z.boolean().optional(),
    status: z.enum(['ACTIVE', 'PAUSED', 'ARCHIVED']).optional(),
});

const BillReservePaymentSchema = z.object({
    bill_reserve_id: z.string().uuid().optional(),
    reserve_id: z.string().uuid().optional(),
    amount: z.coerce.number().positive(),
    currency: z.string().min(3).max(8).optional(),
    provider: z.string().min(2),
    billCategory: z.string().optional(),
    reference: z.string().optional(),
    description: z.string().max(255).optional(),
    metadata: z.record(z.string(), z.any()).optional(),
}).refine((data) => !!(data.bill_reserve_id || data.reserve_id), {
    message: 'bill_reserve_id is required',
});

const SharedPotUpdateSchema = SharedPotCreateSchema.partial().extend({
    status: z.enum(['ACTIVE', 'PAUSED', 'COMPLETED', 'ARCHIVED']).optional(),
});

const SharedPotContributionSchema = z.object({
    amount: z.coerce.number().positive(),
    source_wallet_id: z.string().uuid().optional(),
});

const SharedPotMemberAddSchema = z.object({
    identifier: z.string().min(3),
    role: z.enum(['MANAGER', 'CONTRIBUTOR', 'VIEWER']).optional(),
    message: z.string().max(240).optional(),
});

const SharedPotInviteResponseSchema = z.object({
    action: z.enum(['ACCEPT', 'REJECT']),
});

const SharedPotWithdrawSchema = z.object({
    amount: z.coerce.number().positive(),
    target_wallet_id: z.string().uuid().optional(),
});

const SharedBudgetCreateSchema = z.object({
    name: z.string().min(2),
    purpose: z.string().optional(),
    currency: z.string().min(3).max(8).optional(),
    budget_limit: z.coerce.number().positive(),
    period_type: z.enum(['WEEKLY', 'MONTHLY', 'CUSTOM']).optional(),
    approval_mode: z.enum(['AUTO', 'REVIEW']).optional(),
});

const SharedBudgetUpdateSchema = SharedBudgetCreateSchema.partial().extend({
    status: z.enum(['ACTIVE', 'PAUSED', 'ARCHIVED']).optional(),
});

const SharedBudgetMemberAddSchema = z.object({
    identifier: z.string().min(3),
    role: z.enum(['MANAGER', 'SPENDER', 'VIEWER']).optional(),
    member_limit: z.coerce.number().positive().optional(),
    message: z.string().max(240).optional(),
});

const SharedBudgetInviteResponseSchema = z.object({
    action: z.enum(['ACCEPT', 'REJECT']),
});

const SharedBudgetApprovalResponseSchema = z.object({
    action: z.enum(['APPROVE', 'REJECT']),
    note: z.string().max(255).optional(),
});

const SharedBudgetSpendSchema = z.object({
    source_wallet_id: z.string().uuid().optional(),
    amount: z.coerce.number().positive(),
    currency: z.string().min(3).max(8).optional(),
    provider: z.string().min(2).optional(),
    bill_category: z.string().min(2).optional(),
    reference: z.string().min(2).optional(),
    description: z.string().max(255).optional(),
    type: z.enum(['EXTERNAL_PAYMENT', 'BILL_PAYMENT', 'MERCHANT_PAYMENT']).optional(),
    metadata: z.record(z.string(), z.any()).optional(),
});

const AllocationRuleCreateSchema = z.object({
    name: z.string().min(2),
    trigger_type: z.enum(['DEPOSIT', 'SALARY', 'ROUNDUP', 'REMITTANCE', 'MANUAL']),
    source_wallet_id: z.string().uuid().optional(),
    target_type: z.enum(['GOAL', 'BUDGET', 'BILL_RESERVE', 'SHARED_POT', 'WEALTH_BUCKET']),
    target_id: z.string().uuid(),
    mode: z.enum(['FIXED', 'PERCENT']),
    fixed_amount: z.coerce.number().nonnegative().optional(),
    percentage: z.coerce.number().min(0).max(100).optional(),
    priority: z.coerce.number().int().min(1).optional(),
});

const AllocationRuleUpdateSchema = AllocationRuleCreateSchema.partial().extend({
    is_active: z.boolean().optional(),
});

mountProviderRoutes(v1, gatewayV1, gatewayRoutes, authenticate as any);
registerProviderRoutes(v1, authenticate as any);

registerAuthUserRoutes(v1, {
    authenticate: authenticate as any,
    validate,
    upload,
    NewAuth,
    LogicCore,
    LoginSchema,
    BootstrapAdminSchema,
    SignUpSchema,
    KYCSubmitSchema,
    ServiceAccessRequestCreateSchema,
    resolveSessionRole,
    resolveSessionRegistryType,
    mapServiceRoleToRegistryType,
    legacyBiometricAliasesEnabled,
});

registerSupportOpsRoutes(v1, {
    authenticate: authenticate as any,
    validate,
    upload,
    LogicCore,
    KYCReviewSchema,
    DeviceRegisterSchema,
    DeviceTrustSchema,
    DocumentUploadSchema,
});

registerAdminOpsRoutes(v1, {
    authenticate: authenticate as any,
    adminOnly: adminOnly as any,
    validate,
    requireSessionPermission,
    LogicCore,
    queryStringValue,
    syncUserIdentityClassification,
    mapServiceRoleToRegistryType,
    TransactionIssueSchema,
    TransactionAuditDecisionSchema,
    DocumentVerifySchema,
    StaffCreateSchema,
    StaffAdminUpdateSchema,
    StaffPasswordResetSchema,
    ManagedIdentityCreateSchema,
    ServiceAccessRequestReviewSchema,
    AccountStatusUpdateSchema,
    UserProfileUpdateSchema,
    messagingTestRoutesEnabled,
});

// --- FINANCIAL CORE ENGINE (MULTI-TENANT) ---

v1.post('/core/tenants', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.createTenant(session.sub, req.body);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/core/tenants/my', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getUserTenants(session.sub);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/core/tenants/:id/api-keys', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.generateTenantApiKeys(session.sub, req.params.id, req.body.type);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/core/tenants/:id/api-keys', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getTenantApiKeys(session.sub, req.params.id);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.delete('/core/tenants/:id/api-keys/:keyId', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.revokeTenantApiKey(session.sub, req.params.id, req.params.keyId);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/core/tenants/:id/wallets', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getTenantWallets(session.sub, req.params.id);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- EXTERNAL PROGRAMMATIC API (API KEY AUTHENTICATED) ---
/**
 * Sample endpoint for external systems to fetch tenant wallets using an API Key
 */
v1.get('/external/wallets', authenticateApiKey as any, async (req, res) => {
    const tenantId = (req as any).tenantId;
    try {
        const sb = getSupabase();
        if (!sb) throw new Error("Database not connected");

        const { data, error } = await sb
            .from('wallets')
            .select('*')
            .eq('tenant_id', tenantId);

        if (error) throw new Error(error.message);
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- SETTLEMENT ENGINE ENDPOINTS ---
v1.get('/core/tenants/:id/settlement/config', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getTenantSettlementConfig(session.sub, req.params.id);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/core/tenants/:id/settlement/config', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.updateTenantSettlementConfig(session.sub, req.params.id, req.body);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/core/tenants/:id/settlement/pending', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.getTenantPendingSettlement(req.params.id);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/core/tenants/:id/settlement/payout', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.triggerTenantPayout(session.sub, req.params.id);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/core/tenants/:id/settlement/history', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getTenantPayoutHistory(session.sub, req.params.id);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- Specific Wallet Endpoints for Dashboard ---
v1.get('/wallets/linked', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const allWallets = await LogicCore.getWallets(session.sub);
        const linked = allWallets.filter(w => w.management_tier === 'linked');
        res.json({ success: true, data: linked });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/wallets/sovereign', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const allWallets = await LogicCore.getWallets(session.sub);
        const sovereign = allWallets.filter(w => w.management_tier === 'sovereign');
        res.json({ success: true, data: sovereign });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/user/dashboard', authenticate as any, async (req, res) => {
    const token = req.headers.authorization?.substring(7);
    try {
        const result = await LogicCore.getBootstrapData(token);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/dashboard', authenticate as any, async (req, res) => {
    const token = req.headers.authorization?.substring(7);
    try {
        const result = await LogicCore.getBootstrapData(token);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/wallets', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getWallets(session.sub);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/wallets', authenticate as any, validate(WalletCreateSchema), async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.postWallet({ ...req.body, userId: session.sub });
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.delete('/wallets/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const walletId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        await LogicCore.deleteWallet(session.sub, walletId);
        res.json({ success: true });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.post('/wallets/:id/lock', authenticate as any, validate(WalletLockSchema), async (req, res) => {
    const session = (req as any).session;
    const isAdmin = requireRole(session, ['ADMIN', 'SUPER_ADMIN', 'IT', 'STAFF']);
    try {
        const walletId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const result = await LogicCore.lockWallet(session.sub, walletId, {
            reason: req.body.reason,
            pin: req.body.pin,
            force: req.body.force,
            isAdmin
        });
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.post('/wallets/:id/unlock', authenticate as any, validate(WalletUnlockSchema), async (req, res) => {
    const session = (req as any).session;
    const isAdmin = requireRole(session, ['ADMIN', 'SUPER_ADMIN', 'IT', 'STAFF']);
    if (!isAdmin && !req.body.pin) {
        return res.status(400).json({ success: false, error: 'PIN_REQUIRED' });
    }
    try {
        const walletId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const result = await LogicCore.unlockWallet(session.sub, walletId, {
            pin: req.body.pin,
            force: req.body.force,
            isAdmin
        });
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.post('/transactions/settle', authenticate as any, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    const rawIdempotencyKey = req.headers['x-idempotency-key'];
    const idempotencyKey = Array.isArray(rawIdempotencyKey) ? rawIdempotencyKey[0] : rawIdempotencyKey;
    
    // HARDENING: KYC & Status Limits
    const kycStatus = session.user.user_metadata?.kyc_status || 'unverified';
    const amount = req.body.amount || 0;
    const currency = req.body.currency || 'TZS';

    // 1. Policy Engine Guard Check
    const policyResult = await PolicyEngine.evaluateTransaction(session.sub, amount, currency, 'settlement');
    if (!policyResult.allowed) {
        return res.status(403).json({ 
            success: false, 
            error: 'POLICY_VIOLATION', 
            message: policyResult.reason 
        });
    }

    // 2. KYC Specific Limits (Legacy check kept for backward compatibility)
    if (kycStatus !== 'verified' && amount > 1000000) { 
        return res.status(403).json({ 
            success: false, 
            error: 'KYC_LIMIT_EXCEEDED', 
            message: 'Unverified accounts are limited to 1,000,000 TZS per transaction. Please complete KYC.' 
        });
    }

    try {
        // Inject idempotency key for the Enterprise Payment Processor
        req.body.idempotencyKey = idempotencyKey || `tx-${Date.now()}-${Math.random()}`;
        
        const result = await LogicCore.processSecurePayment(req.body, session.user);
        
        if (!result.success) {
            // Check if it's a security challenge
            if (result.error === 'SECURITY_CHALLENGE') {
                return res.status(403).json(result); // Return the challenge response directly
            }
            
            // Determine appropriate status code based on error message
            const isTransient = result.error?.includes('LOCK_TIMEOUT') || 
                                result.error?.includes('LEDGER_COMMIT_FAILED') || 
                                result.error?.includes('LEDGER_FAULT') ||
                                result.error?.includes('INFRASTRUCTURE_ERROR');
            
            const statusCode = isTransient ? 500 : 400;
            return res.status(statusCode).json(result);
        }
        
        // result is already { success: true, transaction: ... }
        // Commit metrics for policy tracking
        await PolicyEngine.commitMetrics(session.sub, amount, currency);

        // We return it wrapped in data for consistency with other endpoints
        res.json({ success: true, data: result });
    } catch (e: any) {
        console.error(`[Transaction] Settle Error: ${e.message}`);
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/transactions/preview', authenticate as any, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getTransactionPreview(session.sub, req.body);
        if (!result.success) {
            return res.status(400).json(result);
        }
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/fx/quote', authenticate as any, async (req, res) => {
    const { from, to, amount } = req.query;
    if (!from || !to || !amount) {
        return res.status(400).json({ success: false, error: 'Missing required parameters: from, to, amount' });
    }

    try {
        const result = await FXEngine.processConversion(Number(amount), String(from), String(to));
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/transactions', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);
    try {
        const result = await LogicCore.getTransactionsPaginated(session.sub, limit, offset);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/transactions/:id/lock', authenticate as any, validate(TransactionIssueSchema), async (req, res) => {
    const session = (req as any).session;
    try {
        const transactionId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        const result = await LogicCore.requestTransactionRecall(session.sub, transactionId, req.body.reason);
        res.json({
            success: true,
            data: {
                ...result,
                advisory: 'Transaction recall requested. Funds remain under review and may take up to 24 hours to reflect back to your operating wallet.',
            },
        });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

/**
 * GET ENRICHED RECEIPT DATA
 * Provides full, decrypted context for frontend-side receipt generation.
 */
v1.get('/transactions/:id/receipt', authenticate as any, async (req, res) => {
    const { id } = req.params;
    const session = (req as any).session;

    try {
        const service = new TransactionService();
        const transactions = await service.getLatestTransactions(session.sub, 100, 0);
        
        // Find the specific transaction (handling both internal UUID and reference_id)
        const tx = transactions.find(t => t.internalId === id || t.referenceId === id || t.id === id);
        
        if (!tx) {
            return res.status(404).json({ success: false, error: 'TRANSACTION_NOT_FOUND' });
        }

        // The TransactionService already decrypts and enriches the data (sender, receiver, counterparty)
        // so we can return it directly for the frontend ReceiptEngine.
        res.json({ 
            success: true, 
            data: {
                ...tx,
                generatedAt: new Date().toISOString(),
                issuer: "ORBI FINANCIAL TECHNOLOGIES"
            } 
        });
    } catch (e: any) {
        console.error(`[Receipt Data] Fetch failed for ${id}:`, e);
        res.status(500).json({ success: false, error: 'RECEIPT_DATA_FAULT', message: e.message });
    }
});

// --- Messaging Domain ---
v1.post('/chat', authenticate as any, upload.single('document'), async (req, res) => {
    const { message } = req.body;
    const session = (req as any).session;
    const userId = session.sub;

    if (!message) return res.status(400).json({ success: false, error: 'Message required' });

    try {
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) throw new Error("GEMINI_API_KEY_MISSING");
        const ai = new GoogleGenAI({ apiKey });

        // 1. Fetch user context
        const sb = getAdminSupabase();
        const { data: user } = await sb!.from('users').select('full_name, email, account_status').eq('id', userId).single();
        
        // Fetch recent activity
        const { data: recentActivity } = await sb!.from('transactions')
            .select('amount, description, created_at')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(1);
            
        const context = { user, recentActivity };

        // 2. Handle 'init' message for welcome greeting
        let prompt = `User context: ${JSON.stringify(context)}. User message: ${message}`;
        if (message === 'init') {
            const hour = new Date().getHours();
            const timeOfDay = hour < 12 ? 'morning' : hour < 18 ? 'afternoon' : 'evening';
            
            prompt = `User context: ${JSON.stringify(context)}. 
            Current time of day: ${timeOfDay}.
            Please provide a warm, professional welcome greeting to the user, ${user?.full_name || 'valued customer'}.
            Use the time of day (${timeOfDay}) in the greeting.
            Mention one of their recent activities from the context if available, or if their account status is not 'active', mention an account issue.
            Ask them how you can help them with Orbi services (payments, savings, corporate).`;
        }

        // 3. Stream response from Gemini
        const systemInstruction = `
            You are the Orbi AI Agent. 
            
            KNOWLEDGE BASE:
            ${JSON.stringify(OrbiKnowledge, null, 2)}
            
            INSTRUCTIONS:
            1. Always use the provided KNOWLEDGE BASE to answer questions about Orbi.
            2. If a user asks about something not in the knowledge base, politely state that you don't have that information.
            3. Use a professional, helpful, and secure tone.
            4. Avoid technical jargon (e.g., 'ledger', 'settlement'); use user-friendly terms (e.g., 'payment', 'account').
            5. If the user provides a document, analyze it specifically for issues related to the Orbi Platform using the KNOWLEDGE BASE.
            6. CRITICAL: Do NOT use the word 'Fynix' or 'fynix'. Always use 'Orbi'.
        `;

        const contents: any = { parts: [{ text: prompt }] };
        if (req.file) {
            contents.parts.push({
                inlineData: {
                    mimeType: req.file.mimetype,
                    data: req.file.buffer.toString("base64"),
                },
            });
        }

        const response = await callGeminiWithRetry(ai, {
            model: req.file ? 'gemini-2.5-flash' : 'gemini-2.5-flash',
            contents: contents,
            config: { systemInstruction }
        });

        if (!response.text) {
            throw new Error("No response text from Gemini");
        }

        res.json({ success: true, data: response.text });
    } catch (e: any) {
        console.error("[Chat] Error:", e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- Insights Domain ---
v1.get('/insights', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const userId = session.sub;

    try {
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) throw new Error("GEMINI_API_KEY_MISSING");
        const ai = new GoogleGenAI({ apiKey });

        // 1. Fetch comprehensive user financial context
        const sb = getAdminSupabase();
        const { data: transactions } = await sb!.from('transactions')
            .select('amount, description, created_at, category')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(20);
        
        const { data: goals } = await sb!.from('goals')
            .select('name, target_amount, current_amount, funding_strategy, auto_allocation_enabled, linked_income_percentage, monthly_target')
            .eq('user_id', userId);
        
        const { data: categories } = await sb!.from('categories')
            .select('name, budget, spent_amount, hard_limit, period')
            .eq('user_id', userId);

        const allocatedToGoals = (goals || []).reduce((sum: number, g: any) => sum + Number(g.current_amount || 0), 0);
        const allocatedToBudgets = (categories || []).reduce((sum: number, c: any) => sum + Number(c.budget || 0), 0);
        const recentSpend = (transactions || []).reduce((sum: number, t: any) => sum + Number(t.amount || 0), 0);

        const context = {
            transactions,
            goals,
            categories,
            moneyState: {
                allocatedToGoals,
                allocatedToBudgets,
                totalAllocated: allocatedToGoals + allocatedToBudgets,
                recentObservedSpend: recentSpend
            }
        };

        // 2. Generate insights using Gemini
        const systemInstruction = `
            You are the Orbi Financial Advisor. 
            Analyze the provided transaction history, savings goals, budget allocations, and money-state summary to provide personalized financial advice.
            
            Return the response in the following JSON format:
            {
                "spendingAlerts": ["string"],
                "budgetSuggestions": ["string"],
                "financialAdvice": ["string"]
            }
            
            GUIDELINES:
            - Base all advice ONLY on the provided user activity (transactions, goals, categories, and moneyState).
            - Focus on spending habits, savings progress, budget pressure, allocation discipline, and helpful next steps.
            - Explicitly reason about where money currently sits: available, budgeted, saved, locked, or spent.
            - Prefer concrete behavioral observations over generic advice.
            - Mention weak liquidity, overspending pressure, or over-concentration in allocations when the data supports it.
            - Use a professional, helpful, and secure tone.
            - Avoid technical jargon; use user-friendly terms.
            - CRITICAL: Do NOT use the word 'Fynix' or 'fynix'. Always use 'Orbi'.
        `;

        const response = await callGeminiWithRetry(ai, {
            model: 'gemini-2.5-flash',
            contents: `Analyze this financial data: ${JSON.stringify(context)}`,
            config: { 
                systemInstruction,
                responseMimeType: "application/json"
            }
        });

        let insights;
        try {
            insights = JSON.parse(response.text || '{}');
        } catch (e) {
            console.error("[Insights] JSON Parse Error:", e, "Response:", response.text);
            insights = { spendingAlerts: [], budgetSuggestions: [], financialAdvice: ["Unable to generate insights at this time."] };
        }
        res.json({ success: true, data: insights });
    } catch (e: any) {
        console.error("[Insights] Error:", e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- Receipt Scanning Domain ---
v1.post('/receipt/scan', authenticate as any, upload.single('receipt'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, error: 'No receipt image provided' });
    }

    try {
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) throw new Error("GEMINI_API_KEY_MISSING");
        const ai = new GoogleGenAI({ apiKey });

        const imagePart = {
            inlineData: {
                mimeType: req.file.mimetype,
                data: req.file.buffer.toString("base64"),
            },
        };

        const response = await callGeminiWithRetry(ai, {
            model: 'gemini-2.5-flash',
            contents: { parts: [imagePart, { text: 'Extract the merchant name, total amount, currency, and date from this receipt.' }] },
            config: {
                responseMimeType: "application/json",
                responseSchema: {
                    type: Type.OBJECT,
                    properties: {
                        merchant: { type: Type.STRING },
                        amount: { type: Type.NUMBER },
                        currency: { type: Type.STRING },
                        date: { type: Type.STRING }
                    },
                    required: ["merchant", "amount", "currency", "date"]
                }
            }
        });

        const receiptData = JSON.parse(response.text || '{}');
        res.json({ success: true, data: receiptData });
    } catch (e: any) {
        console.error("[ReceiptScan] Error:", e);
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/notifications', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);
    try {
        const result = await LogicCore.getUserMessages(session.sub, limit, offset);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/notifications/:id/read', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        await LogicCore.markMessageRead(session.sub, req.params.id);
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/notifications/read-all', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        await LogicCore.markAllMessagesRead(session.sub);
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.delete('/notifications/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        await LogicCore.deleteMessage(session.sub, req.params.id);
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- Strategy Domain ---
v1.post('/goals', authenticate as any, validate(GoalCreateSchema), async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    try {
        const result = await LogicCore.postGoal({ ...req.body, user_id: session.sub }, authToken || undefined);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/goals', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    try {
        const result = await LogicCore.getGoals(session.sub, authToken || undefined);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/goals/:id', authenticate as any, validate(GoalUpdateSchema), async (req, res) => {
    const authToken = (req as any).authToken as string | null;
    try {
        const result = await LogicCore.updateGoal({ ...req.body, id: req.params.id }, authToken || undefined);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.delete('/goals/:id', authenticate as any, async (req, res) => {
    const authToken = (req as any).authToken as string | null;
    try {
        const result = await LogicCore.deleteGoal(req.params.id, authToken || undefined);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/categories', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    try {
        const result = await LogicCore.getCategories(session.sub, authToken || undefined);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/categories', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    try {
        const result = await LogicCore.postCategory(
            { ...req.body, user_id: session.sub },
            authToken || undefined
        );
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/categories/:id', authenticate as any, async (req, res) => {
    const authToken = (req as any).authToken as string | null;
    try {
        const result = await LogicCore.updateCategory(
            { ...req.body, id: req.params.id },
            authToken || undefined
        );
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.delete('/categories/:id', authenticate as any, async (req, res) => {
    const authToken = (req as any).authToken as string | null;
    try {
        const result = await LogicCore.deleteCategory(req.params.id, authToken || undefined);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

const wealthNumber = (value: any) => {
    if (typeof value === 'number') return value;
    if (typeof value === 'string') return Number(value.replace(/,/g, '')) || 0;
    return 0;
};

const resolveWealthSourceWallet = async (
    sb: any,
    userId: string,
    sourceWalletId?: string,
) => {
    let sourceRecord: any = null;
    let sourceTable: 'platform_vaults' | 'wallets' = 'platform_vaults';

    if (sourceWalletId) {
        const { data: vaultMatch } = await sb
            .from('platform_vaults')
            .select('*')
            .eq('id', sourceWalletId)
            .eq('user_id', userId)
            .maybeSingle();
        if (vaultMatch) {
            sourceRecord = vaultMatch;
            sourceTable = 'platform_vaults';
        } else {
            const { data: walletMatch } = await sb
                .from('wallets')
                .select('*')
                .eq('id', sourceWalletId)
                .eq('user_id', userId)
                .maybeSingle();
            if (walletMatch) {
                sourceRecord = walletMatch;
                sourceTable = 'wallets';
            }
        }
    }

    if (!sourceRecord) {
        const { data: operatingVault } = await sb
            .from('platform_vaults')
            .select('*')
            .eq('user_id', userId)
            .eq('vault_role', 'OPERATING')
            .maybeSingle();
        if (operatingVault) {
            sourceRecord = operatingVault;
            sourceTable = 'platform_vaults';
        } else {
            const { data: fallbackWallet } = await sb
                .from('wallets')
                .select('*')
                .eq('user_id', userId)
                .order('created_at', { ascending: true })
                .limit(1)
                .maybeSingle();
            sourceRecord = fallbackWallet;
            sourceTable = 'wallets';
        }
    }

    if (!sourceRecord) throw new Error('NO_OPERATING_WALLET');
    return { sourceRecord, sourceTable };
};

const updateWealthSourceBalance = async (
    sb: any,
    sourceTable: 'platform_vaults' | 'wallets',
    sourceRecord: any,
    userId: string,
    nextBalance: number,
) => {
    const { error } = await sb
        .from(sourceTable)
        .update({
            balance: nextBalance,
            updated_at: new Date().toISOString(),
        })
        .eq('id', sourceRecord.id)
        .eq('user_id', userId);
    if (error) throw new Error(error.message);
};

const createWealthTransaction = async (
    sb: any,
    userId: string,
    sourceRecord: any,
    amount: number,
    currency: string,
    description: string,
    wealthImpactType: string,
    metadata: Record<string, any>,
    options?: {
        transactionType?: string;
        transactionStatus?: string;
    },
) => {
    const reference = `wealth_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
    const { data, error } = await sb
        .from('transactions')
        .insert({
            reference_id: reference,
            user_id: userId,
            wallet_id: sourceRecord.id,
            amount: String(amount),
            currency,
            description,
            type: options?.transactionType || 'internal_transfer',
            status: options?.transactionStatus || 'completed',
            wealth_impact_type: wealthImpactType,
            protection_state: 'OPEN',
            allocation_source: metadata.allocation_source || null,
            metadata,
        })
        .select('*')
        .single();
    if (error || !data) throw new Error(error?.message || 'TX_CREATE_FAILED');
    return data;
};

const insertBillReserveLedger = async (
    sb: any,
    {
        transactionId,
        userId,
        sourceRecord,
        reserveId,
        amount,
        sourceBalanceAfter,
        reserveBalanceAfter,
        action,
    }: {
        transactionId: string;
        userId: string;
        sourceRecord: any;
        reserveId: string;
        amount: number;
        sourceBalanceAfter: number;
        reserveBalanceAfter: number;
        action: 'LOCK' | 'RELEASE';
    },
) => {
    const isLock = action == 'LOCK';
    const rows = [
        {
            transaction_id: transactionId,
            user_id: userId,
            wallet_id: sourceRecord.id,
            bill_reserve_id: reserveId,
            bucket_type: 'OPERATING',
            entry_side: isLock ? 'DEBIT' : 'CREDIT',
            entry_type: isLock ? 'DEBIT' : 'CREDIT',
            amount: String(amount),
            balance_after: String(sourceBalanceAfter),
            description: isLock
                ? 'Bill reserve funding debit'
                : 'Bill reserve release credit',
        },
        {
            transaction_id: transactionId,
            user_id: userId,
            wallet_id: sourceRecord.id,
            bill_reserve_id: reserveId,
            bucket_type: 'PLANNED',
            entry_side: isLock ? 'CREDIT' : 'DEBIT',
            entry_type: isLock ? 'CREDIT' : 'DEBIT',
            amount: String(amount),
            balance_after: String(reserveBalanceAfter),
            description: isLock
                ? 'Bill reserve protected balance credit'
                : 'Bill reserve protected balance release',
        },
    ];
    const { error } = await sb.from('financial_ledger').insert(rows);
    if (error) throw new Error(error.message);
};

const wealthSourceMetadata = (sourceRecord: any): Record<string, any> => {
    const metadata = sourceRecord?.metadata;
    if (metadata && typeof metadata === 'object' && !Array.isArray(metadata)) {
        return metadata as Record<string, any>;
    }
    return {};
};

const isGoalBackedWealthSourceWallet = (sourceRecord: any) => {
    const metadata = wealthSourceMetadata(sourceRecord);
    const sourceKind = String(
        metadata.source_kind ??
        metadata.sourceKind ??
        sourceRecord?.vault_role ??
        sourceRecord?.type ??
        '',
    ).trim().toLowerCase();
    const linkedGoalId = metadata.goal_id ?? metadata.goalId ?? sourceRecord?.goal_id;
    return sourceKind.includes('goal') || Boolean(linkedGoalId);
};

const assertBillPaymentSourceAllowed = (sourceRecord: any) => {
    if (isGoalBackedWealthSourceWallet(sourceRecord)) {
        throw new Error('GOAL_FUNDS_BILL_PAYMENT_NOT_ALLOWED');
    }
};

const normalizeBillReserveValue = (value: string) =>
    value
        .trim()
        .toLowerCase()
        .replace(/&/g, 'and')
        .replace(/[^a-z0-9]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

const billReserveValuesMatch = (left?: string | null, right?: string | null) => {
    const leftKey = normalizeBillReserveValue(String(left || ''));
    const rightKey = normalizeBillReserveValue(String(right || ''));
    if (!leftKey || !rightKey) return false;
    return leftKey === rightKey || leftKey.includes(rightKey) || rightKey.includes(leftKey);
};

const resolveBillReserveReference = (reserve: any) =>
    String(
        reserve?.reference ??
        reserve?.bill_reference ??
        reserve?.account_number ??
        reserve?.meter_number ??
        reserve?.customer_number ??
        '',
    ).trim();

const normalizeWealthIdentifier = (value: string) => value.trim().toLowerCase();

const normalizeWealthPhone = (value: string) =>
    value
        .trim()
        .replace(/[^\d+]/g, '')
        .replace(/(?!^)\+/g, '');

const isEmailLikeIdentifier = (value: string) => value.includes('@');

const resolveSharedPotMembership = async (sb: any, potId: string, userId: string) => {
    const { data: pot, error: potError } = await sb
        .from('shared_pots')
        .select('*')
        .eq('id', potId)
        .maybeSingle();
    if (potError) throw new Error(potError.message);
    if (!pot) throw new Error('SHARED_POT_NOT_FOUND');

    const { data: membership, error: memberError } = await sb
        .from('shared_pot_members')
        .select('*')
        .eq('pot_id', potId)
        .eq('user_id', userId)
        .maybeSingle();
    if (memberError) throw new Error(memberError.message);

    const ownerMembership = pot.owner_user_id === userId
        ? { role: 'OWNER', user_id: userId, pot_id: potId }
        : null;

    const effectiveMembership = membership || ownerMembership;
    if (!effectiveMembership) throw new Error('SHARED_POT_ACCESS_DENIED');
    return { pot, membership: effectiveMembership };
};

const canManageSharedPot = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());
const canContributeToSharedPot = (role: string) =>
    ['OWNER', 'MANAGER', 'CONTRIBUTOR'].includes(role.toUpperCase());

const resolveUserBySharedPotIdentifier = async (sb: any, identifier: string) => {
    if (isEmailLikeIdentifier(identifier)) {
        const { data, error } = await sb
            .from('users')
            .select('id,email,phone,full_name')
            .eq('email', normalizeWealthIdentifier(identifier))
            .maybeSingle();
        if (error) throw new Error(error.message);
        return data;
    }

    const normalizedPhone = normalizeWealthPhone(identifier);
    const candidates = Array.from(new Set([identifier.trim(), normalizedPhone, normalizedPhone.replace(/\D/g, '')].filter(Boolean)));
    const { data, error } = await sb
        .from('users')
        .select('id,email,phone,full_name')
        .in('phone', candidates)
        .limit(1)
        .maybeSingle();
    if (error) throw new Error(error.message);
    return data;
};

const expireSharedPotInvitationIfNeeded = async (sb: any, invite: any) => {
    if (!invite?.expires_at) return invite;
    if (String(invite.status || '').toUpperCase() !== 'PENDING') return invite;
    if (new Date(invite.expires_at).getTime() > Date.now()) return invite;

    const { data, error } = await sb
        .from('shared_pot_invitations')
        .update({
            status: 'EXPIRED',
            updated_at: new Date().toISOString(),
        })
        .eq('id', invite.id)
        .select('*')
        .single();
    if (error) throw new Error(error.message);
    return data || invite;
};

const resolveSharedBudgetMembership = async (sb: any, budgetId: string, userId: string) => {
    const { data: budget, error: budgetError } = await sb
        .from('shared_budgets')
        .select('*')
        .eq('id', budgetId)
        .maybeSingle();
    if (budgetError) throw new Error(budgetError.message);
    if (!budget) throw new Error('SHARED_BUDGET_NOT_FOUND');

    const { data: membership, error: memberError } = await sb
        .from('shared_budget_members')
        .select('*')
        .eq('budget_id', budgetId)
        .eq('user_id', userId)
        .maybeSingle();
    if (memberError) throw new Error(memberError.message);

    const ownerMembership = budget.owner_user_id === userId
        ? { role: 'OWNER', user_id: userId, budget_id: budgetId }
        : null;

    const effectiveMembership = membership || ownerMembership;
    if (!effectiveMembership) throw new Error('SHARED_BUDGET_ACCESS_DENIED');
    return { budget, membership: effectiveMembership };
};

const canManageSharedBudget = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());
const canSpendFromSharedBudget = (role: string) => ['OWNER', 'MANAGER', 'SPENDER'].includes(role.toUpperCase());
const canReviewSharedBudgetSpend = (role: string) => ['OWNER', 'MANAGER'].includes(role.toUpperCase());

const resolveUserBySharedBudgetIdentifier = async (sb: any, identifier: string) => {
    return resolveUserBySharedPotIdentifier(sb, identifier);
};

const expireSharedBudgetInvitationIfNeeded = async (sb: any, invite: any) => {
    if (!invite?.expires_at) return invite;
    if (String(invite.status || '').toUpperCase() !== 'PENDING') return invite;
    if (new Date(invite.expires_at).getTime() > Date.now()) return invite;

    const { data, error } = await sb
        .from('shared_budget_invitations')
        .update({
            status: 'EXPIRED',
            updated_at: new Date().toISOString(),
        })
        .eq('id', invite.id)
        .select('*')
        .single();
    if (error) throw new Error(error.message);
    return data || invite;
};

const executeSharedBudgetSpend = async (
    sb: any,
    {
        budget,
        membership,
        actorUserId,
        actorUser,
        payload,
        approvalId,
    }: {
        budget: any;
        membership: any;
        actorUserId: string;
        actorUser: any;
        payload: any;
        approvalId?: string | null;
    },
) => {
    const currentSpent = wealthNumber(budget.spent_amount);
    const budgetLimit = wealthNumber(budget.budget_limit);
    if (currentSpent + payload.amount > budgetLimit) {
        throw new Error('SHARED_BUDGET_LIMIT_EXCEEDED');
    }

    const memberSpent = wealthNumber(membership.spent_amount || 0);
    if (membership.member_limit && memberSpent + payload.amount > wealthNumber(membership.member_limit)) {
        throw new Error('SHARED_BUDGET_MEMBER_LIMIT_EXCEEDED');
    }

    const enrichedMetadata = {
        ...(payload.metadata || {}),
        shared_budget_id: budget.id,
        shared_budget_name: budget.name,
        shared_budget_role: membership.role || 'SPENDER',
        bill_provider: payload.provider || null,
        bill_category: payload.bill_category || null,
        bill_reference: payload.reference || null,
        spend_origin: 'SHARED_BUDGET',
        spend_type: payload.type || 'EXTERNAL_PAYMENT',
        approval_id: approvalId || null,
        approval_mode: budget.approval_mode || 'AUTO',
        actor_user_id: actorUserId,
        member_user_id: actorUserId,
    };

    const result = await LogicCore.processSecurePayment({
        sourceWalletId: payload.source_wallet_id,
        recipientId: payload.provider,
        amount: payload.amount,
        currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
        description: payload.description || `${budget.name} spend`,
        type: payload.type || 'EXTERNAL_PAYMENT',
        metadata: enrichedMetadata,
    }, actorUser);
    if (!result.success) throw new Error(result.error || 'SHARED_BUDGET_SPEND_FAILED');

    const tx = result.transaction || {};
    const transactionId = tx.internalId || tx.id || null;
    const newBudgetSpent = currentSpent + payload.amount;
    const newMemberSpent = memberSpent + payload.amount;
    const nowIso = new Date().toISOString();

    if (transactionId) {
        const { error: txLinkError } = await sb
            .from('transactions')
            .update({
                shared_budget_id: budget.id,
                updated_at: nowIso,
                metadata: enrichedMetadata,
            })
            .eq('id', transactionId);
        if (txLinkError) throw new Error(txLinkError.message);

        const { error: ledgerLinkError } = await sb
            .from('financial_ledger')
            .update({ shared_budget_id: budget.id })
            .eq('transaction_id', transactionId);
        if (ledgerLinkError) throw new Error(ledgerLinkError.message);
    }

    const { error: budgetUpdateError } = await sb
        .from('shared_budgets')
        .update({
            spent_amount: newBudgetSpent,
            updated_at: nowIso,
        })
        .eq('id', budget.id);
    if (budgetUpdateError) throw new Error(budgetUpdateError.message);

    const { error: memberUpdateError } = await sb
        .from('shared_budget_members')
        .upsert({
            budget_id: budget.id,
            user_id: actorUserId,
            role: membership.role || 'SPENDER',
            status: membership.status || 'ACTIVE',
            member_limit: membership.member_limit || null,
            spent_amount: newMemberSpent,
            metadata: membership.metadata || {},
        }, {
            onConflict: 'budget_id,user_id',
        });
    if (memberUpdateError) throw new Error(memberUpdateError.message);

    const { data: budgetTx, error: budgetTxError } = await sb
        .from('shared_budget_transactions')
        .insert({
            shared_budget_id: budget.id,
            member_user_id: actorUserId,
            source_wallet_id: payload.source_wallet_id || tx.fromWalletId || null,
            transaction_id: transactionId,
            merchant_name: payload.provider || tx.toUserId || null,
            provider: payload.provider || null,
            category: payload.bill_category || payload.type || 'SPEND',
            amount: payload.amount,
            currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
            status: 'COMPLETED',
            note: payload.description || null,
            metadata: {
                ...enrichedMetadata,
                reference: payload.reference || null,
                approved_from_review: approvalId != null,
            },
        })
        .select('*')
        .single();
    if (budgetTxError) throw new Error(budgetTxError.message);

    return {
        transaction: result.transaction,
        budget_transaction: budgetTx,
        shared_budget: {
            ...budget,
            spent_amount: newBudgetSpent,
            remaining_amount: Math.max(0, budgetLimit - newBudgetSpent),
        },
        member: {
            ...membership,
            spent_amount: newMemberSpent,
        },
    };
};

registerCommerceRoutes(v1, {
    authenticate: authenticate as any,
    validate,
    requireRole,
    LogicCore,
    Webhooks,
    getAdminSupabase,
    getSupabase,
    resolveWealthSourceWallet,
    assertBillPaymentSourceAllowed,
    billReserveValuesMatch,
    resolveBillReserveReference,
    wealthNumber,
    ServiceCustomerRegistrationSchema,
    PaymentIntentSchema,
    BillReservePaymentSchema,
});

v1.get('/wealth/summary', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

        const userId = session.sub;
        const [
            platformVaultsResult,
            walletsResult,
            goalsResult,
            categoriesResult,
            billReservesResult,
            sharedPotsResult,
            userResult,
        ] = await Promise.all([
            sb.from('platform_vaults').select('vault_role,name,balance,currency,metadata').eq('user_id', userId),
            sb.from('wallets').select('name,balance,currency,type,management_tier,metadata').eq('user_id', userId),
            sb.from('goals').select('current').eq('user_id', userId),
            sb.from('categories').select('budget').eq('user_id', userId),
            sb.from('bill_reserves').select('reserve_amount,locked_balance,currency,is_active').eq('user_id', userId),
            sb.from('shared_pots').select('current_amount,target_amount,currency,status').eq('owner_user_id', userId),
            sb.from('users').select('currency').eq('id', userId).single(),
        ]);

        const firstError = [
            platformVaultsResult.error,
            walletsResult.error,
            goalsResult.error,
            categoriesResult.error,
            billReservesResult.error,
            sharedPotsResult.error,
            userResult.error,
        ].find(Boolean);
        if (firstError) {
            return res.status(400).json({ success: false, error: (firstError as any).message });
        }

        const preferredCurrency = String(userResult.data?.currency || 'TZS').toUpperCase();
        const asNumber = (value: any) => {
            if (typeof value === 'number') return value;
            if (typeof value === 'string') return Number(value.replace(/,/g, '')) || 0;
            return 0;
        };

        const platformVaults = platformVaultsResult.data || [];
        const wallets = walletsResult.data || [];
        const operatingVault = platformVaults.find((vault: any) => String(vault.vault_role || '').toUpperCase() === 'OPERATING');
        const fallbackOperatingWallet = wallets.find((wallet: any) => {
            const lowType = String(wallet.type || '').toLowerCase();
            const lowTier = String(wallet.management_tier || '').toLowerCase();
            const lowName = String(wallet.name || '').toLowerCase();
            return lowType.includes('internal') || lowTier.includes('sovereign') || lowName.includes('dilpesa');
        });

        const escrowBalance = [
            ...platformVaults.filter((vault: any) => String(vault.vault_role || '').toUpperCase() === 'INTERNAL_TRANSFER'),
            ...wallets.filter((wallet: any) => {
                const lowName = String(wallet.name || '').toLowerCase();
                const lowType = String(wallet.type || '').toLowerCase();
                const escrowMeta = wallet.metadata?.is_secure_escrow === true;
                return lowName.includes('paysafe') || lowName.includes('escrow') || lowType.includes('internal_transfer') || escrowMeta;
            }),
        ].reduce((sum: number, item: any) => sum + asNumber(item.balance), 0);

        const plannedBudget = (categoriesResult.data || []).reduce(
            (sum: number, category: any) => sum + asNumber(category.budget),
            0,
        );
        const reserveLocked = (billReservesResult.data || [])
            .filter((reserve: any) => reserve.is_active !== false)
            .reduce((sum: number, reserve: any) => sum + asNumber(reserve.locked_balance || reserve.reserve_amount), 0);
        const growingGoals = (goalsResult.data || []).reduce(
            (sum: number, goal: any) => sum + asNumber(goal.current),
            0,
        );
        const sharedPotBalance = (sharedPotsResult.data || [])
            .filter((pot: any) => String(pot.status || 'ACTIVE').toUpperCase() !== 'ARCHIVED')
            .reduce((sum: number, pot: any) => sum + asNumber(pot.current_amount), 0);

        const operatingBalance = asNumber(
            operatingVault?.balance ?? fallbackOperatingWallet?.balance ?? 0,
        );
        const plannedBalance = plannedBudget + reserveLocked;
        const protectedBalance = escrowBalance;
        const growingBalance = growingGoals + sharedPotBalance;

        const insights: Array<{ type: string; title: string; message: string; severity: string }> = [];
        if (plannedBalance > operatingBalance) {
            insights.push({
                type: 'SPEND_PRESSURE',
                title: 'Planned spending is ahead of available money',
                message: 'Reduce planned spending or top up the operating wallet to stay in control.',
                severity: 'WARNING',
            });
        }
        if ((goalsResult.data || []).length === 0) {
            insights.push({
                type: 'GOAL_START',
                title: 'Start a first growth goal',
                message: 'Create one goal so ORBI can separate daily money from long-term money.',
                severity: 'INFO',
            });
        }
        if ((billReservesResult.data || []).length === 0) {
            insights.push({
                type: 'BILL_RESERVE_START',
                title: 'Protect your next bill',
                message: 'Create a bill reserve so important payments are set aside before spending.',
                severity: 'INFO',
            });
        }

        res.json({
            success: true,
            data: {
                currency: preferredCurrency,
                operating_balance: operatingBalance,
                planned_balance: plannedBalance,
                protected_balance: protectedBalance,
                growing_balance: growingBalance,
                goal_count: (goalsResult.data || []).length,
                budget_count: (categoriesResult.data || []).length,
                linked_wallet_count: wallets.filter((wallet: any) => {
                    const lowType = String(wallet.type || '').toLowerCase();
                    const lowTier = String(wallet.management_tier || '').toLowerCase();
                    return lowType.includes('linked') || lowType.includes('external') || lowTier.includes('linked');
                }).length,
                insights,
            },
        });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/bill-reserves', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { data, error } = await sb
            .from('bill_reserves')
            .select('*')
            .eq('user_id', session.sub)
            .order('created_at', { ascending: false });
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data: { reserves: data || [] } });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/bill-reserves', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = BillReserveCreateSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const currency = payload.currency?.toUpperCase() || 'TZS';
        const isFixedReserve = (payload.reserve_mode || 'FIXED') === 'FIXED';
        const lockedBalance = isFixedReserve ? payload.reserve_amount : 0;

        let sourceRecord: any = null;
        let sourceTable: 'platform_vaults' | 'wallets' = 'platform_vaults';
        let sourceBalanceAfter: number | null = null;

        if (lockedBalance > 0) {
            const resolved = await resolveWealthSourceWallet(
                sb,
                session.sub,
                payload.source_wallet_id,
            );
            sourceRecord = resolved.sourceRecord;
            sourceTable = resolved.sourceTable;
            assertBillPaymentSourceAllowed(sourceRecord);
            const currentBalance = wealthNumber(sourceRecord.balance);
            if (currentBalance < lockedBalance) {
                return res.status(400).json({ success: false, error: 'INSUFFICIENT_FUNDS' });
            }
            sourceBalanceAfter = currentBalance - lockedBalance;
        }

        const insertPayload = {
            user_id: session.sub,
            provider_name: payload.provider_name,
            bill_type: payload.bill_type,
            source_wallet_id: sourceRecord?.id || payload.source_wallet_id,
            currency,
            due_pattern: payload.due_pattern || 'MONTHLY',
            due_day: payload.due_day,
            reserve_mode: payload.reserve_mode || 'FIXED',
            reserve_amount: payload.reserve_amount,
            locked_balance: lockedBalance,
            is_active: true,
            metadata: {
                created_from: 'mobile_app',
                source_table: sourceRecord ? sourceTable : null,
            },
        };
        const { data, error } = await sb
            .from('bill_reserves')
            .insert(insertPayload)
            .select('*')
            .single();
        if (error) return res.status(400).json({ success: false, error: error.message });

        let transaction: any = null;
        if (lockedBalance > 0 && sourceRecord && sourceBalanceAfter != null) {
            transaction = await createWealthTransaction(
                sb,
                session.sub,
                sourceRecord,
                lockedBalance,
                currency,
                `Bill reserve funding: ${payload.provider_name}`,
                'PLANNED',
                {
                    bill_reserve_id: data.id,
                    source_table: sourceTable,
                    source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
                    allocation_source: 'BILL_RESERVE_CREATE',
                },
            );
            await updateWealthSourceBalance(
                sb,
                sourceTable,
                sourceRecord,
                session.sub,
                sourceBalanceAfter,
            );
            await insertBillReserveLedger(sb, {
                transactionId: transaction.id,
                userId: session.sub,
                sourceRecord,
                reserveId: data.id,
                amount: lockedBalance,
                sourceBalanceAfter,
                reserveBalanceAfter: lockedBalance,
                action: 'LOCK',
            });
        }
        res.json({
            success: true,
            data: {
                ...data,
                source_balance: sourceBalanceAfter,
                transaction,
            },
        });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.patch('/wealth/bill-reserves/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = BillReserveUpdateSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { data: existingReserve, error: reserveError } = await sb
            .from('bill_reserves')
            .select('*')
            .eq('id', req.params.id)
            .eq('user_id', session.sub)
            .single();
        if (reserveError || !existingReserve) {
            return res.status(404).json({ success: false, error: 'BILL_RESERVE_NOT_FOUND' });
        }

        const nextReserveMode = payload.reserve_mode ?? existingReserve.reserve_mode ?? 'FIXED';
        const nextReserveAmount = payload.reserve_amount ?? wealthNumber(existingReserve.reserve_amount);
        const nextStatus = payload.status ?? String(existingReserve.status || 'ACTIVE').toUpperCase();
        const nextIsActive = payload.is_active ?? (existingReserve.is_active !== false);
        const shouldLockFunds =
            nextIsActive &&
            String(nextStatus).toUpperCase() == 'ACTIVE' &&
            String(nextReserveMode).toUpperCase() == 'FIXED';

        const currentLockedBalance = wealthNumber(existingReserve.locked_balance || 0);
        const desiredLockedBalance = shouldLockFunds ? wealthNumber(nextReserveAmount) : 0;
        const delta = desiredLockedBalance - currentLockedBalance;

        const updatePayload: any = {
            updated_at: new Date().toISOString(),
        };
        if (payload.provider_name !== undefined) updatePayload.provider_name = payload.provider_name;
        if (payload.bill_type !== undefined) updatePayload.bill_type = payload.bill_type;
        if (payload.source_wallet_id !== undefined) updatePayload.source_wallet_id = payload.source_wallet_id;
        if (payload.currency !== undefined) updatePayload.currency = payload.currency.toUpperCase();
        if (payload.due_pattern !== undefined) updatePayload.due_pattern = payload.due_pattern;
        if (payload.due_day !== undefined) updatePayload.due_day = payload.due_day;
        if (payload.reserve_mode !== undefined) updatePayload.reserve_mode = payload.reserve_mode;
        if (payload.reserve_amount !== undefined) updatePayload.reserve_amount = payload.reserve_amount;
        if (payload.is_active !== undefined) updatePayload.is_active = payload.is_active;
        if (payload.status !== undefined) updatePayload.status = payload.status;
        updatePayload.locked_balance = desiredLockedBalance;

        let sourceRecord: any = null;
        let sourceTable: 'platform_vaults' | 'wallets' = 'platform_vaults';
        let sourceBalanceAfter: number | null = null;
        let adjustmentAction: 'LOCK' | 'RELEASE' | null = null;

        if (delta !== 0) {
            const resolved = await resolveWealthSourceWallet(
                sb,
                session.sub,
                (payload.source_wallet_id ?? existingReserve.source_wallet_id ?? '').toString() || undefined,
            );
            sourceRecord = resolved.sourceRecord;
            sourceTable = resolved.sourceTable;
            assertBillPaymentSourceAllowed(sourceRecord);
            const currentBalance = wealthNumber(sourceRecord.balance);
            if (delta > 0) {
                if (currentBalance < delta) {
                    return res.status(400).json({ success: false, error: 'INSUFFICIENT_FUNDS' });
                }
                sourceBalanceAfter = currentBalance - delta;
                adjustmentAction = 'LOCK';
            } else {
                sourceBalanceAfter = currentBalance + Math.abs(delta);
                adjustmentAction = 'RELEASE';
            }
            updatePayload.source_wallet_id = sourceRecord.id;
        }

        const { data, error } = await sb
            .from('bill_reserves')
            .update(updatePayload)
            .eq('id', req.params.id)
            .eq('user_id', session.sub)
            .select('*')
            .single();
        if (error) return res.status(400).json({ success: false, error: error.message });

        let transaction: any = null;
        if (delta !== 0 && sourceRecord && sourceBalanceAfter != null && adjustmentAction) {
            const adjustmentAmount = Math.abs(delta);
            transaction = await createWealthTransaction(
                sb,
                session.sub,
                sourceRecord,
                adjustmentAmount,
                String(data.currency || sourceRecord.currency || 'TZS').toUpperCase(),
                adjustmentAction == 'LOCK'
                    ? `Bill reserve top-up: ${data.provider_name}`
                    : `Bill reserve release: ${data.provider_name}`,
                'PLANNED',
                {
                    bill_reserve_id: data.id,
                    source_table: sourceTable,
                    source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
                    allocation_source: adjustmentAction == 'LOCK'
                        ? 'BILL_RESERVE_TOP_UP'
                        : 'BILL_RESERVE_RELEASE',
                },
            );
            await updateWealthSourceBalance(
                sb,
                sourceTable,
                sourceRecord,
                session.sub,
                sourceBalanceAfter,
            );
            await insertBillReserveLedger(sb, {
                transactionId: transaction.id,
                userId: session.sub,
                sourceRecord,
                reserveId: data.id,
                amount: adjustmentAmount,
                sourceBalanceAfter,
                reserveBalanceAfter: desiredLockedBalance,
                action: adjustmentAction,
            });
        }
        res.json({
            success: true,
            data: {
                ...data,
                source_balance: sourceBalanceAfter,
                transaction,
            },
        });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.delete('/wealth/bill-reserves/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

        const { data: reserve, error: reserveError } = await sb
            .from('bill_reserves')
            .select('*')
            .eq('id', req.params.id)
            .eq('user_id', session.sub)
            .single();
        if (reserveError || !reserve) {
            return res.status(404).json({ success: false, error: 'BILL_RESERVE_NOT_FOUND' });
        }

        const lockedBalance = wealthNumber(reserve.locked_balance || 0);
        let sourceBalanceAfter: number | null = null;
        let transaction: any = null;

        if (lockedBalance > 0) {
            const resolved = await resolveWealthSourceWallet(
                sb,
                session.sub,
                String(reserve.source_wallet_id || '').trim() || undefined,
            );
            const sourceRecord = resolved.sourceRecord;
            const sourceTable = resolved.sourceTable;
            const currentBalance = wealthNumber(sourceRecord.balance);
            sourceBalanceAfter = currentBalance + lockedBalance;

            transaction = await createWealthTransaction(
                sb,
                session.sub,
                sourceRecord,
                lockedBalance,
                String(reserve.currency || sourceRecord.currency || 'TZS').toUpperCase(),
                `Bill reserve delete release: ${reserve.provider_name || reserve.bill_type || 'Reserve'}`,
                'PLANNED',
                {
                    bill_reserve_id: reserve.id,
                    source_table: sourceTable,
                    source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
                    allocation_source: 'BILL_RESERVE_DELETE_RELEASE',
                },
            );

            await updateWealthSourceBalance(
                sb,
                sourceTable,
                sourceRecord,
                session.sub,
                sourceBalanceAfter,
            );

            await insertBillReserveLedger(sb, {
                transactionId: transaction.id,
                userId: session.sub,
                sourceRecord,
                reserveId: reserve.id,
                amount: lockedBalance,
                sourceBalanceAfter,
                reserveBalanceAfter: 0,
                action: 'RELEASE',
            });
        }

        const { error: deleteError } = await sb
            .from('bill_reserves')
            .delete()
            .eq('id', reserve.id)
            .eq('user_id', session.sub);
        if (deleteError) {
            return res.status(400).json({ success: false, error: deleteError.message });
        }

        res.json({
            success: true,
            data: {
                deleted: true,
                released_amount: lockedBalance,
                source_balance: sourceBalanceAfter,
                transaction,
            },
        });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/shared-pots', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { data: memberships, error: memberError } = await sb
            .from('shared_pot_members')
            .select('pot_id, role')
            .eq('user_id', session.sub);
        if (memberError) return res.status(400).json({ success: false, error: memberError.message });

        const memberPotIds = Array.from(new Set((memberships || []).map((item: any) => String(item.pot_id || '')).filter(Boolean)));
        let query = sb
            .from('shared_pots')
            .select('*')
            .eq('owner_user_id', session.sub);
        if (memberPotIds.length > 0) {
            query = sb
                .from('shared_pots')
                .select('*')
                .or([
                    `owner_user_id.eq.${session.sub}`,
                    `id.in.(${memberPotIds.join(',')})`,
                ].join(','));
        }
        const { data, error } = await query.order('created_at', { ascending: false });
        if (error) return res.status(400).json({ success: false, error: error.message });
        const membershipByPot = new Map(
            (memberships || []).map((item: any) => [String(item.pot_id), String(item.role || 'CONTRIBUTOR').toUpperCase()]),
        );
        const items = (data || []).map((pot: any) => ({
            ...pot,
            my_role: pot.owner_user_id === session.sub
                ? 'OWNER'
                : (membershipByPot.get(String(pot.id)) || 'CONTRIBUTOR'),
            is_owner: pot.owner_user_id === session.sub,
        }));
        res.json({ success: true, data: { pots: items } });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/shared-pots', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedPotCreateSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { data, error } = await sb
            .from('shared_pots')
            .insert({
                owner_user_id: session.sub,
                name: payload.name,
                purpose: payload.purpose,
                currency: payload.currency?.toUpperCase() || 'TZS',
                target_amount: payload.target_amount || 0,
                current_amount: 0,
                access_model: payload.access_model || 'INVITE',
                status: 'ACTIVE',
                metadata: { created_from: 'mobile_app' },
            })
            .select('*')
            .single();
        if (error) return res.status(400).json({ success: false, error: error.message });
        await sb.from('shared_pot_members').insert({
            pot_id: data.id,
            user_id: session.sub,
            role: 'OWNER',
            contributed_amount: 0,
        });
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.patch('/wealth/shared-pots/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedPotUpdateSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { membership } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
        if (!canManageSharedPot(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_POT_ACCESS_DENIED' });
        }
        const updatePayload: any = {
            updated_at: new Date().toISOString(),
        };
        if (payload.name !== undefined) updatePayload.name = payload.name;
        if (payload.purpose !== undefined) updatePayload.purpose = payload.purpose;
        if (payload.currency !== undefined) updatePayload.currency = payload.currency.toUpperCase();
        if (payload.target_amount !== undefined) updatePayload.target_amount = payload.target_amount;
        if (payload.access_model !== undefined) updatePayload.access_model = payload.access_model;
        if (payload.status !== undefined) updatePayload.status = payload.status;
        const { data, error } = await sb
            .from('shared_pots')
            .update(updatePayload)
            .eq('id', req.params.id)
            .eq('owner_user_id', session.sub)
            .select('*')
            .single();
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(e.message === 'SHARED_POT_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/shared-pots/:id/members', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { pot } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
        const { data, error } = await sb
            .from('shared_pot_members')
            .select('id,pot_id,user_id,role,contribution_target,contributed_amount,metadata,created_at, users!shared_pot_members_user_id_fkey(id, full_name, email, phone)')
            .eq('pot_id', pot.id)
            .order('created_at', { ascending: true });
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data: { members: data || [] } });
    } catch (e: any) {
        res.status(e.message === 'SHARED_POT_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/shared-pots/:id/invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { pot, membership } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
        if (!canManageSharedPot(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_POT_ACCESS_DENIED' });
        }
        const { data, error } = await sb
            .from('shared_pot_invitations')
            .select('id,pot_id,inviter_user_id,invitee_user_id,invitee_identifier,role,status,message,responded_at,expires_at,metadata,created_at, users!shared_pot_invitations_invitee_user_id_fkey(id, full_name, email, phone)')
            .eq('pot_id', pot.id)
            .order('created_at', { ascending: false });
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data: { invitations: data || [] } });
    } catch (e: any) {
        res.status(e.message === 'SHARED_POT_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/shared-pot-invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { data, error } = await sb
            .from('shared_pot_invitations')
            .select('id,pot_id,inviter_user_id,invitee_user_id,invitee_identifier,role,status,message,responded_at,expires_at,metadata,created_at, shared_pots!shared_pot_invitations_pot_id_fkey(id, name, purpose, currency, target_amount, current_amount, status), users!shared_pot_invitations_inviter_user_id_fkey(id, full_name, email, phone)')
            .eq('invitee_user_id', session.sub)
            .order('created_at', { ascending: false });
        if (error) return res.status(400).json({ success: false, error: error.message });

        const invitations = [];
        for (const invite of data || []) {
            invitations.push(await expireSharedPotInvitationIfNeeded(sb, invite));
        }
        res.json({ success: true, data: { invitations } });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/shared-pots/:id/invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedPotMemberAddSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { pot, membership } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
        if (!canManageSharedPot(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_POT_ACCESS_DENIED' });
        }
        const memberUser = await resolveUserBySharedPotIdentifier(sb, payload.identifier);
        if (!memberUser?.id) {
            return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
        }
        if (String(memberUser.id) === String(pot.owner_user_id)) {
            return res.status(400).json({ success: false, error: 'OWNER_ALREADY_MEMBER' });
        }
        const { data: existingMember, error: existingMemberError } = await sb
            .from('shared_pot_members')
            .select('id')
            .eq('pot_id', pot.id)
            .eq('user_id', memberUser.id)
            .maybeSingle();
        if (existingMemberError) {
            return res.status(400).json({ success: false, error: existingMemberError.message });
        }
        if (existingMember) {
            return res.status(400).json({ success: false, error: 'SHARED_POT_MEMBER_ALREADY_EXISTS' });
        }

        const { data: pendingInvite, error: pendingInviteError } = await sb
            .from('shared_pot_invitations')
            .select('*')
            .eq('pot_id', pot.id)
            .eq('invitee_user_id', memberUser.id)
            .eq('status', 'PENDING')
            .order('created_at', { ascending: false })
            .limit(1)
            .single();
        if (pendingInviteError && pendingInviteError.code !== 'PGRST116') {
            return res.status(400).json({ success: false, error: pendingInviteError.message });
        }
        if (pendingInvite) {
            return res.status(400).json({ success: false, error: 'SHARED_POT_INVITE_ALREADY_PENDING' });
        }

        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
        const { data, error } = await sb
            .from('shared_pot_invitations')
            .insert({
                pot_id: pot.id,
                inviter_user_id: session.sub,
                invitee_user_id: memberUser.id,
                invitee_identifier: payload.identifier,
                role: payload.role || 'CONTRIBUTOR',
                message: payload.message || null,
                expires_at: expiresAt,
                metadata: {
                    invited_by: session.sub,
                    invite_source: 'shared_pot_member_sheet',
                    identifier: payload.identifier,
                },
            })
            .select('id,pot_id,inviter_user_id,invitee_user_id,invitee_identifier,role,status,message,responded_at,expires_at,metadata,created_at')
            .single();
        if (error) return res.status(400).json({ success: false, error: error.message });

        await Messaging.dispatch(
            String(memberUser.id),
            'info',
            'Shared pot invitation',
            `${session.user?.user_metadata?.full_name || 'A member'} invited you to join "${pot.name}" as ${String(payload.role || 'CONTRIBUTOR').toLowerCase()}.`,
            {
                push: true,
                sms: false,
                email: true,
                eventCode: 'SHARED_POT_INVITATION',
                variables: {
                    pot_name: pot.name,
                    role: payload.role || 'CONTRIBUTOR',
                    invite_id: data.id,
                },
            },
        );

        res.json({
            success: true,
            data: {
                invitation: {
                    ...data,
                    invitee: {
                        id: memberUser.id,
                        full_name: memberUser.full_name,
                        email: memberUser.email,
                        phone: memberUser.phone,
                    },
                },
            },
        });
    } catch (e: any) {
        res.status(e.message === 'SHARED_POT_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/shared-pot-invitations/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedPotInviteResponseSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

        const { data: inviteRaw, error: inviteError } = await sb
            .from('shared_pot_invitations')
            .select('*')
            .eq('id', req.params.id)
            .maybeSingle();
        if (inviteError) return res.status(400).json({ success: false, error: inviteError.message });
        if (!inviteRaw) return res.status(404).json({ success: false, error: 'SHARED_POT_INVITE_NOT_FOUND' });
        const invite = await expireSharedPotInvitationIfNeeded(sb, inviteRaw);

        if (String(invite.invitee_user_id || '') !== String(session.sub)) {
            return res.status(403).json({ success: false, error: 'SHARED_POT_INVITE_ACCESS_DENIED' });
        }
        if (String(invite.status || '').toUpperCase() !== 'PENDING') {
            return res.status(400).json({ success: false, error: 'SHARED_POT_INVITE_NOT_PENDING' });
        }

        if (payload.action === 'REJECT') {
            const { data, error } = await sb
                .from('shared_pot_invitations')
                .update({
                    status: 'REJECTED',
                    responded_at: new Date().toISOString(),
                    updated_at: new Date().toISOString(),
                })
                .eq('id', invite.id)
                .select('*')
                .single();
            if (error) return res.status(400).json({ success: false, error: error.message });
            return res.json({ success: true, data: { invitation: data } });
        }

        const { data: existingMember, error: existingMemberError } = await sb
            .from('shared_pot_members')
            .select('id')
            .eq('pot_id', invite.pot_id)
            .eq('user_id', session.sub)
            .maybeSingle();
        if (existingMemberError) return res.status(400).json({ success: false, error: existingMemberError.message });
        if (existingMember) {
            return res.status(400).json({ success: false, error: 'SHARED_POT_MEMBER_ALREADY_EXISTS' });
        }

        const { data: member, error: memberError } = await sb
            .from('shared_pot_members')
            .insert({
                pot_id: invite.pot_id,
                user_id: session.sub,
                role: invite.role || 'CONTRIBUTOR',
                contributed_amount: 0,
                metadata: {
                    joined_via_invitation: invite.id,
                    invited_by: invite.inviter_user_id,
                },
            })
            .select('*')
            .single();
        if (memberError) return res.status(400).json({ success: false, error: memberError.message });

        const { data: updatedInvite, error: updateInviteError } = await sb
            .from('shared_pot_invitations')
            .update({
                status: 'ACCEPTED',
                responded_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
            })
            .eq('id', invite.id)
            .select('*')
            .single();
        if (updateInviteError) return res.status(400).json({ success: false, error: updateInviteError.message });

        res.json({ success: true, data: { invitation: updatedInvite, member } });
    } catch (e: any) {
        const status = e.message === 'SHARED_POT_INVITE_ACCESS_DENIED' ? 403 : 400;
        res.status(status).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/shared-pots/:id/contribute', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedPotContributionSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { pot, membership } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
        if (!canContributeToSharedPot(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_POT_CONTRIBUTION_DENIED' });
        }

        const { sourceRecord, sourceTable } = await resolveWealthSourceWallet(
            sb,
            session.sub,
            payload.source_wallet_id,
        );
        const currentBalance = wealthNumber(sourceRecord.balance);
        if (currentBalance < payload.amount) {
            return res.status(400).json({ success: false, error: 'INSUFFICIENT_FUNDS' });
        }

        const newSourceBalance = currentBalance - payload.amount;
        const newPotBalance = wealthNumber(pot.current_amount) + payload.amount;
        const reference = `pot_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;

        const { data: tx, error: txError } = await sb
            .from('transactions')
            .insert({
                reference_id: reference,
                user_id: session.sub,
                wallet_id: sourceRecord.id,
                amount: String(payload.amount),
                currency: String(pot.currency || sourceRecord.currency || 'TZS').toUpperCase(),
                description: `Shared pot contribution: ${pot.name}`,
                type: 'internal_transfer',
                status: 'completed',
                wealth_impact_type: 'GROWING',
                protection_state: 'OPEN',
                allocation_source: 'SHARED_POT_CONTRIBUTION',
                metadata: {
                    shared_pot_id: pot.id,
                    member_role: membership.role,
                    source_table: sourceTable,
                    source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
                },
            })
            .select('*')
            .single();
        if (txError || !tx) {
            return res.status(400).json({ success: false, error: txError?.message || 'TX_CREATE_FAILED' });
        }

        const { error: walletUpdateError } = await sb
            .from(sourceTable)
            .update({
                balance: newSourceBalance,
                updated_at: new Date().toISOString(),
            })
            .eq('id', sourceRecord.id)
            .eq('user_id', session.sub);
        if (walletUpdateError) {
            return res.status(400).json({ success: false, error: walletUpdateError.message });
        }

        const { error: potUpdateError } = await sb
            .from('shared_pots')
            .update({
                current_amount: newPotBalance,
                updated_at: new Date().toISOString(),
            })
            .eq('id', pot.id);
        if (potUpdateError) {
            return res.status(400).json({ success: false, error: potUpdateError.message });
        }

        const ledgerRows = [
            {
                transaction_id: tx.id,
                user_id: session.sub,
                wallet_id: sourceRecord.id,
                shared_pot_id: pot.id,
                bucket_type: 'OPERATING',
                entry_side: 'DEBIT',
                entry_type: 'DEBIT',
                amount: String(payload.amount),
                balance_after: String(newSourceBalance),
                description: `Shared pot contribution debit: ${pot.name}`,
            },
            {
                transaction_id: tx.id,
                user_id: session.sub,
                wallet_id: sourceRecord.id,
                shared_pot_id: pot.id,
                bucket_type: 'GROWING',
                entry_side: 'CREDIT',
                entry_type: 'CREDIT',
                amount: String(payload.amount),
                balance_after: String(newPotBalance),
                description: `Shared pot contribution credit: ${pot.name}`,
            },
        ];
        const { error: ledgerError } = await sb.from('financial_ledger').insert(ledgerRows);
        if (ledgerError) {
            return res.status(400).json({ success: false, error: ledgerError.message });
        }

        res.json({
            success: true,
            data: {
                transaction: tx,
                shared_pot: { ...pot, current_amount: newPotBalance },
                source_balance: newSourceBalance,
            },
        });
    } catch (e: any) {
        res.status(
            ['SHARED_POT_ACCESS_DENIED', 'SHARED_POT_CONTRIBUTION_DENIED'].includes(e.message) ? 403 : 400,
        ).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/shared-pots/:id/withdraw', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedPotWithdrawSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { pot, membership } = await resolveSharedPotMembership(sb, req.params.id, session.sub);
        if (!canManageSharedPot(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_POT_WITHDRAW_DENIED' });
        }
        const currentPotBalance = wealthNumber(pot.current_amount);
        if (currentPotBalance < payload.amount) {
            return res.status(400).json({ success: false, error: 'INSUFFICIENT_POT_FUNDS' });
        }

        const { sourceRecord: targetRecord, sourceTable: targetTable } = await resolveWealthSourceWallet(
            sb,
            session.sub,
            payload.target_wallet_id,
        );
        const targetBalance = wealthNumber(targetRecord.balance);
        const newTargetBalance = targetBalance + payload.amount;
        const newPotBalance = currentPotBalance - payload.amount;
        const reference = `pot_w_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;

        const { data: tx, error: txError } = await sb
            .from('transactions')
            .insert({
                reference_id: reference,
                user_id: session.sub,
                wallet_id: targetRecord.id,
                amount: String(payload.amount),
                currency: String(pot.currency || targetRecord.currency || 'TZS').toUpperCase(),
                description: `Shared pot withdrawal: ${pot.name}`,
                type: 'internal_transfer',
                status: 'completed',
                wealth_impact_type: 'GROWING',
                protection_state: 'OPEN',
                allocation_source: 'SHARED_POT_WITHDRAWAL',
                metadata: {
                    shared_pot_id: pot.id,
                    actor_role: membership.role,
                    target_table: targetTable,
                    target_wallet_role: targetRecord.vault_role || targetRecord.type || null,
                },
            })
            .select('*')
            .single();
        if (txError || !tx) {
            return res.status(400).json({ success: false, error: txError?.message || 'TX_CREATE_FAILED' });
        }

        const { error: walletUpdateError } = await sb
            .from(targetTable)
            .update({
                balance: newTargetBalance,
                updated_at: new Date().toISOString(),
            })
            .eq('id', targetRecord.id)
            .eq('user_id', session.sub);
        if (walletUpdateError) {
            return res.status(400).json({ success: false, error: walletUpdateError.message });
        }

        const { error: potUpdateError } = await sb
            .from('shared_pots')
            .update({
                current_amount: newPotBalance,
                updated_at: new Date().toISOString(),
            })
            .eq('id', pot.id);
        if (potUpdateError) {
            return res.status(400).json({ success: false, error: potUpdateError.message });
        }

        const existingMemberContribution = wealthNumber(
            membership.contributed_amount || 0,
        );
        const { error: memberUpdateError } = await sb
            .from('shared_pot_members')
            .upsert({
                pot_id: pot.id,
                user_id: session.sub,
                role: membership.role || 'CONTRIBUTOR',
                contributed_amount: existingMemberContribution + payload.amount,
                metadata: membership.metadata || {},
            }, {
                onConflict: 'pot_id,user_id',
            });
        if (memberUpdateError) {
            return res.status(400).json({ success: false, error: memberUpdateError.message });
        }

        const ledgerRows = [
            {
                transaction_id: tx.id,
                user_id: session.sub,
                wallet_id: targetRecord.id,
                shared_pot_id: pot.id,
                bucket_type: 'GROWING',
                entry_side: 'DEBIT',
                entry_type: 'DEBIT',
                amount: String(payload.amount),
                balance_after: String(newPotBalance),
                description: `Shared pot withdrawal debit: ${pot.name}`,
            },
            {
                transaction_id: tx.id,
                user_id: session.sub,
                wallet_id: targetRecord.id,
                shared_pot_id: pot.id,
                bucket_type: 'OPERATING',
                entry_side: 'CREDIT',
                entry_type: 'CREDIT',
                amount: String(payload.amount),
                balance_after: String(newTargetBalance),
                description: `Shared pot withdrawal credit: ${pot.name}`,
            },
        ];
        const { error: ledgerError } = await sb.from('financial_ledger').insert(ledgerRows);
        if (ledgerError) {
            return res.status(400).json({ success: false, error: ledgerError.message });
        }

        res.json({
            success: true,
            data: {
                transaction: tx,
                shared_pot: { ...pot, current_amount: newPotBalance },
                target_balance: newTargetBalance,
            },
        });
    } catch (e: any) {
        res.status(e.message === 'SHARED_POT_WITHDRAW_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/shared-budgets', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { data: memberships, error: memberError } = await sb
            .from('shared_budget_members')
            .select('budget_id, role')
            .eq('user_id', session.sub);
        if (memberError) return res.status(400).json({ success: false, error: memberError.message });

        const memberBudgetIds = Array.from(new Set((memberships || []).map((item: any) => String(item.budget_id || '')).filter(Boolean)));
        let query = sb
            .from('shared_budgets')
            .select('*')
            .eq('owner_user_id', session.sub);
        if (memberBudgetIds.length > 0) {
            query = sb
                .from('shared_budgets')
                .select('*')
                .or([
                    `owner_user_id.eq.${session.sub}`,
                    `id.in.(${memberBudgetIds.join(',')})`,
                ].join(','));
        }
        const { data, error } = await query.order('created_at', { ascending: false });
        if (error) return res.status(400).json({ success: false, error: error.message });
        const membershipByBudget = new Map(
            (memberships || []).map((item: any) => [String(item.budget_id), String(item.role || 'SPENDER').toUpperCase()]),
        );
        const items = (data || []).map((budget: any) => ({
            ...budget,
            my_role: budget.owner_user_id === session.sub
                ? 'OWNER'
                : (membershipByBudget.get(String(budget.id)) || 'SPENDER'),
            is_owner: budget.owner_user_id === session.sub,
            remaining_amount: Math.max(0, wealthNumber(budget.budget_limit) - wealthNumber(budget.spent_amount)),
        }));
        res.json({ success: true, data: { budgets: items } });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/shared-budgets', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedBudgetCreateSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { data, error } = await sb
            .from('shared_budgets')
            .insert({
                owner_user_id: session.sub,
                name: payload.name,
                purpose: payload.purpose,
                currency: payload.currency?.toUpperCase() || 'TZS',
                budget_limit: payload.budget_limit,
                spent_amount: 0,
                period_type: payload.period_type || 'MONTHLY',
                approval_mode: payload.approval_mode || 'AUTO',
                status: 'ACTIVE',
                metadata: { created_from: 'mobile_app' },
            })
            .select('*')
            .single();
        if (error) return res.status(400).json({ success: false, error: error.message });
        await sb.from('shared_budget_members').insert({
            budget_id: data.id,
            user_id: session.sub,
            role: 'OWNER',
            spent_amount: 0,
        });
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.patch('/wealth/shared-budgets/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedBudgetUpdateSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
        if (!canManageSharedBudget(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
        }
        const updatePayload: any = { updated_at: new Date().toISOString() };
        if (payload.name !== undefined) updatePayload.name = payload.name;
        if (payload.purpose !== undefined) updatePayload.purpose = payload.purpose;
        if (payload.currency !== undefined) updatePayload.currency = payload.currency.toUpperCase();
        if (payload.budget_limit !== undefined) updatePayload.budget_limit = payload.budget_limit;
        if (payload.period_type !== undefined) updatePayload.period_type = payload.period_type;
        if (payload.approval_mode !== undefined) updatePayload.approval_mode = payload.approval_mode;
        if (payload.status !== undefined) updatePayload.status = payload.status;
        const { data, error } = await sb
            .from('shared_budgets')
            .update(updatePayload)
            .eq('id', req.params.id)
            .select('*')
            .single();
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/shared-budgets/:id/members', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { budget } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
        const { data, error } = await sb
            .from('shared_budget_members')
            .select('id,budget_id,user_id,role,status,member_limit,spent_amount,metadata,created_at, users!shared_budget_members_user_id_fkey(id, full_name, email, phone)')
            .eq('budget_id', budget.id)
            .order('created_at', { ascending: true });
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data: { members: data || [] } });
    } catch (e: any) {
        res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/shared-budgets/:id/transactions', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { budget } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
        const { data, error } = await sb
            .from('shared_budget_transactions')
            .select('*, users!shared_budget_transactions_member_user_id_fkey(id, full_name, email, phone)')
            .eq('shared_budget_id', budget.id)
            .order('created_at', { ascending: false });
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data: { transactions: data || [] } });
    } catch (e: any) {
        res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/shared-budgets/:id/invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
        if (!canManageSharedBudget(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
        }
        const { data, error } = await sb
            .from('shared_budget_invitations')
            .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at, users!shared_budget_invitations_invitee_user_id_fkey(id, full_name, email, phone)')
            .eq('budget_id', budget.id)
            .order('created_at', { ascending: false });
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data: { invitations: data || [] } });
    } catch (e: any) {
        res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/shared-budget-invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { data, error } = await sb
            .from('shared_budget_invitations')
            .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at, shared_budgets!shared_budget_invitations_budget_id_fkey(id, name, purpose, currency, budget_limit, spent_amount, period_type, approval_mode, status), users!shared_budget_invitations_inviter_user_id_fkey(id, full_name, email, phone)')
            .eq('invitee_user_id', session.sub)
            .order('created_at', { ascending: false });
        if (error) return res.status(400).json({ success: false, error: error.message });
        const invitations = [];
        for (const invite of data || []) {
            invitations.push(await expireSharedBudgetInvitationIfNeeded(sb, invite));
        }
        res.json({ success: true, data: { invitations } });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/shared-budgets/:id/invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedBudgetMemberAddSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
        if (!canManageSharedBudget(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
        }
        const memberUser = await resolveUserBySharedBudgetIdentifier(sb, payload.identifier);
        if (!memberUser?.id) {
            return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
        }
        if (String(memberUser.id) === String(budget.owner_user_id)) {
            return res.status(400).json({ success: false, error: 'OWNER_ALREADY_MEMBER' });
        }
        const { data: existingMember, error: existingMemberError } = await sb
            .from('shared_budget_members')
            .select('id')
            .eq('budget_id', budget.id)
            .eq('user_id', memberUser.id)
            .maybeSingle();
        if (existingMemberError) return res.status(400).json({ success: false, error: existingMemberError.message });
        if (existingMember) {
            return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_ALREADY_EXISTS' });
        }
        const { data: pendingInvite, error: pendingInviteError } = await sb
            .from('shared_budget_invitations')
            .select('*')
            .eq('budget_id', budget.id)
            .eq('invitee_user_id', memberUser.id)
            .eq('status', 'PENDING')
            .order('created_at', { ascending: false })
            .limit(1)
            .single();
        if (pendingInviteError && pendingInviteError.code !== 'PGRST116') {
            return res.status(400).json({ success: false, error: pendingInviteError.message });
        }
        if (pendingInvite) {
            return res.status(400).json({ success: false, error: 'SHARED_BUDGET_INVITE_ALREADY_PENDING' });
        }

        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
        const { data, error } = await sb
            .from('shared_budget_invitations')
            .insert({
                budget_id: budget.id,
                inviter_user_id: session.sub,
                invitee_user_id: memberUser.id,
                invitee_identifier: payload.identifier,
                role: payload.role || 'SPENDER',
                member_limit: payload.member_limit || null,
                message: payload.message || null,
                expires_at: expiresAt,
                metadata: {
                    invited_by: session.sub,
                    invite_source: 'shared_budget_member_sheet',
                    identifier: payload.identifier,
                },
            })
            .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at')
            .single();
        if (error) return res.status(400).json({ success: false, error: error.message });

        await Messaging.dispatch(
            String(memberUser.id),
            'info',
            'Shared budget invitation',
            `${session.user?.user_metadata?.full_name || 'A member'} invited you to join "${budget.name}" as ${String(payload.role || 'SPENDER').toLowerCase()}.`,
            {
                push: true,
                sms: false,
                email: true,
                eventCode: 'SHARED_BUDGET_INVITATION',
                variables: {
                    budget_name: budget.name,
                    role: payload.role || 'SPENDER',
                    invite_id: data.id,
                },
            },
        );

        res.json({ success: true, data: { invitation: data } });
    } catch (e: any) {
        res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/shared-budget-invitations/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedBudgetInviteResponseSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

        const { data: inviteRaw, error: inviteError } = await sb
            .from('shared_budget_invitations')
            .select('*')
            .eq('id', req.params.id)
            .maybeSingle();
        if (inviteError) return res.status(400).json({ success: false, error: inviteError.message });
        if (!inviteRaw) return res.status(404).json({ success: false, error: 'SHARED_BUDGET_INVITE_NOT_FOUND' });
        const invite = await expireSharedBudgetInvitationIfNeeded(sb, inviteRaw);

        if (String(invite.invitee_user_id || '') !== String(session.sub)) {
            return res.status(403).json({ success: false, error: 'SHARED_BUDGET_INVITE_ACCESS_DENIED' });
        }
        if (String(invite.status || '').toUpperCase() !== 'PENDING') {
            return res.status(400).json({ success: false, error: 'SHARED_BUDGET_INVITE_NOT_PENDING' });
        }

        if (payload.action === 'REJECT') {
            const { data, error } = await sb
                .from('shared_budget_invitations')
                .update({
                    status: 'REJECTED',
                    responded_at: new Date().toISOString(),
                    updated_at: new Date().toISOString(),
                })
                .eq('id', invite.id)
                .select('*')
                .single();
            if (error) return res.status(400).json({ success: false, error: error.message });
            return res.json({ success: true, data: { invitation: data } });
        }

        const { data: existingMember, error: existingMemberError } = await sb
            .from('shared_budget_members')
            .select('id')
            .eq('budget_id', invite.budget_id)
            .eq('user_id', session.sub)
            .maybeSingle();
        if (existingMemberError) return res.status(400).json({ success: false, error: existingMemberError.message });
        if (existingMember) {
            return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_ALREADY_EXISTS' });
        }

        const { data: member, error: memberError } = await sb
            .from('shared_budget_members')
            .insert({
                budget_id: invite.budget_id,
                user_id: session.sub,
                role: invite.role || 'SPENDER',
                status: 'ACTIVE',
                member_limit: invite.member_limit || null,
                spent_amount: 0,
                metadata: {
                    joined_via_invitation: invite.id,
                    invited_by: invite.inviter_user_id,
                },
            })
            .select('*')
            .single();
        if (memberError) return res.status(400).json({ success: false, error: memberError.message });

        const { data: updatedInvite, error: updateInviteError } = await sb
            .from('shared_budget_invitations')
            .update({
                status: 'ACCEPTED',
                responded_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
            })
            .eq('id', invite.id)
            .select('*')
            .single();
        if (updateInviteError) return res.status(400).json({ success: false, error: updateInviteError.message });

        res.json({ success: true, data: { invitation: updatedInvite, member } });
    } catch (e: any) {
        const status = e.message === 'SHARED_BUDGET_INVITE_ACCESS_DENIED' ? 403 : 400;
        res.status(status).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/shared-budgets/:id/approvals', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
        if (!canReviewSharedBudgetSpend(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
        }
        const { data, error } = await sb
            .from('shared_budget_approvals')
            .select('*, users!shared_budget_approvals_requester_user_id_fkey(id, full_name, email, phone), reviewer:users!shared_budget_approvals_reviewer_user_id_fkey(id, full_name, email, phone)')
            .eq('shared_budget_id', budget.id)
            .order('created_at', { ascending: false });
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data: { approvals: data || [] } });
    } catch (e: any) {
        const status = e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400;
        res.status(status).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/shared-budget-approvals/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedBudgetApprovalResponseSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

        const { data: approval, error: approvalError } = await sb
            .from('shared_budget_approvals')
            .select('*')
            .eq('id', req.params.id)
            .maybeSingle();
        if (approvalError) return res.status(400).json({ success: false, error: approvalError.message });
        if (!approval) return res.status(404).json({ success: false, error: 'SHARED_BUDGET_APPROVAL_NOT_FOUND' });
        if (String(approval.status || '').toUpperCase() !== 'PENDING') {
            return res.status(400).json({ success: false, error: 'SHARED_BUDGET_APPROVAL_NOT_PENDING' });
        }

        const { budget, membership } = await resolveSharedBudgetMembership(sb, approval.shared_budget_id, session.sub);
        if (!canReviewSharedBudgetSpend(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
        }

        if (payload.action === 'REJECT') {
            const { data, error } = await sb
                .from('shared_budget_approvals')
                .update({
                    status: 'REJECTED',
                    reviewer_user_id: session.sub,
                    responded_at: new Date().toISOString(),
                    updated_at: new Date().toISOString(),
                    note: payload.note ?? approval.note ?? null,
                })
                .eq('id', approval.id)
                .select('*')
                .single();
            if (error) return res.status(400).json({ success: false, error: error.message });
            return res.json({ success: true, data: { approval: data } });
        }

        const requesterMembershipResult = await resolveSharedBudgetMembership(
            sb,
            approval.shared_budget_id,
            String(approval.requester_user_id),
        );

        const approvalMetadata = approval.metadata && typeof approval.metadata === 'object'
            ? approval.metadata
            : {};

        const spendPayload = {
            source_wallet_id: approvalMetadata.source_wallet_id || null,
            amount: wealthNumber(approval.amount),
            currency: approval.currency || budget.currency || 'TZS',
            provider: approval.provider || null,
            bill_category: approval.bill_category || null,
            reference: approval.reference || null,
            description: approval.note || null,
            type: approvalMetadata.type || 'EXTERNAL_PAYMENT',
            metadata: {
                ...approvalMetadata,
                approval_reviewer_user_id: session.sub,
                approval_reviewer_role: membership.role || 'MANAGER',
                approval_response_note: payload.note || null,
            },
        };

        const spendData = await executeSharedBudgetSpend(sb, {
            budget,
            membership: requesterMembershipResult.membership,
            actorUserId: String(approval.requester_user_id),
            actorUser: {
                ...(session.user || {}),
                id: String(approval.requester_user_id),
            },
            payload: spendPayload,
            approvalId: approval.id,
        });

        const transactionId = (spendData as any)?.transaction?.internalId || (spendData as any)?.transaction?.id || null;
        const { data: updatedApproval, error: approvalUpdateError } = await sb
            .from('shared_budget_approvals')
            .update({
                status: 'APPROVED',
                reviewer_user_id: session.sub,
                responded_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                metadata: {
                    ...approvalMetadata,
                    approved_transaction_id: transactionId,
                    approval_response_note: payload.note || null,
                },
            })
            .eq('id', approval.id)
            .select('*')
            .single();
        if (approvalUpdateError) return res.status(400).json({ success: false, error: approvalUpdateError.message });

        res.json({ success: true, data: { approval: updatedApproval, ...spendData } });
    } catch (e: any) {
        const status = e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400;
        res.status(status).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/shared-budgets/:id/spend/preview', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedBudgetSpendSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
        if (!canSpendFromSharedBudget(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_BUDGET_SPEND_DENIED' });
        }
        const currentSpent = wealthNumber(budget.spent_amount);
        const budgetLimit = wealthNumber(budget.budget_limit);
        if (currentSpent + payload.amount > budgetLimit) {
            return res.status(400).json({ success: false, error: 'SHARED_BUDGET_LIMIT_EXCEEDED' });
        }
        const memberSpent = wealthNumber(membership.spent_amount || 0);
        const memberLimit = payload.amount + memberSpent;
        if (membership.member_limit && memberLimit > wealthNumber(membership.member_limit)) {
            return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_LIMIT_EXCEEDED' });
        }

        const result = await LogicCore.getTransactionPreview(session.sub, {
            sourceWalletId: payload.source_wallet_id,
            recipientId: payload.provider,
            amount: payload.amount,
            currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
            description: payload.description || `${budget.name} spend`,
            type: payload.type || 'EXTERNAL_PAYMENT',
            metadata: {
                ...(payload.metadata || {}),
                shared_budget_id: budget.id,
                shared_budget_name: budget.name,
                shared_budget_role: membership.role || 'SPENDER',
                bill_provider: payload.provider || null,
                bill_category: payload.bill_category || null,
                bill_reference: payload.reference || null,
                shared_budget_preview: true,
                spend_origin: 'SHARED_BUDGET',
                spend_type: payload.type || 'EXTERNAL_PAYMENT',
            },
            dryRun: true,
        });
        if (!result.success) return res.status(400).json(result);
        res.json({
            success: true,
            data: {
                preview: result,
                budget: {
                    ...budget,
                    remaining_amount: Math.max(0, budgetLimit - currentSpent - payload.amount),
                },
                member: {
                    ...membership,
                    remaining_member_limit: membership.member_limit
                        ? Math.max(0, wealthNumber(membership.member_limit) - memberSpent - payload.amount)
                        : null,
                },
            },
        });
    } catch (e: any) {
        const status = e.message === 'SHARED_BUDGET_SPEND_DENIED' ? 403 : 400;
        res.status(status).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/shared-budgets/:id/spend/settle', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = SharedBudgetSpendSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
        if (!canSpendFromSharedBudget(String(membership.role || ''))) {
            return res.status(403).json({ success: false, error: 'SHARED_BUDGET_SPEND_DENIED' });
        }
        const currentSpent = wealthNumber(budget.spent_amount);
        const budgetLimit = wealthNumber(budget.budget_limit);
        if (currentSpent + payload.amount > budgetLimit) {
            return res.status(400).json({ success: false, error: 'SHARED_BUDGET_LIMIT_EXCEEDED' });
        }
        const memberSpent = wealthNumber(membership.spent_amount || 0);
        if (membership.member_limit && memberSpent + payload.amount > wealthNumber(membership.member_limit)) {
            return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_LIMIT_EXCEEDED' });
        }
        if (String(budget.approval_mode || 'AUTO').toUpperCase() === 'REVIEW') {
            const { data, error } = await sb
                .from('shared_budget_approvals')
                .insert({
                    shared_budget_id: budget.id,
                    requester_user_id: session.sub,
                    amount: payload.amount,
                    currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
                    provider: payload.provider || null,
                    bill_category: payload.bill_category || null,
                    reference: payload.reference || null,
                    note: payload.description || null,
                    status: 'PENDING',
                    metadata: {
                        ...(payload.metadata || {}),
                        source_wallet_id: payload.source_wallet_id || null,
                        type: payload.type || 'EXTERNAL_PAYMENT',
                        shared_budget_name: budget.name,
                        requester_role: membership.role || 'SPENDER',
                        spend_origin: 'SHARED_BUDGET',
                        bill_provider: payload.provider || null,
                        bill_category: payload.bill_category || null,
                        bill_reference: payload.reference || null,
                        preview_required: true,
                    },
                })
                .select('*')
                .single();
            if (error) return res.status(400).json({ success: false, error: error.message });
            return res.json({ success: true, data: { approval: data, requires_approval: true } });
        }

        const data = await executeSharedBudgetSpend(sb, {
            budget,
            membership,
            actorUserId: session.sub,
            actorUser: session.user,
            payload,
        });
        res.json({ success: true, data });
    } catch (e: any) {
        const status = e.message === 'SHARED_BUDGET_SPEND_DENIED' ? 403 : 400;
        res.status(status).json({ success: false, error: e.message });
    }
});

v1.get('/wealth/allocation-rules', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { data, error } = await sb
            .from('allocation_rules')
            .select('*')
            .eq('user_id', session.sub)
            .order('priority', { ascending: true })
            .order('created_at', { ascending: false });
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data: { rules: data || [] } });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/wealth/allocation-rules', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = AllocationRuleCreateSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const { data, error } = await sb
            .from('allocation_rules')
            .insert({
                user_id: session.sub,
                name: payload.name,
                trigger_type: payload.trigger_type,
                source_wallet_id: payload.source_wallet_id,
                target_type: payload.target_type,
                target_id: payload.target_id,
                mode: payload.mode,
                fixed_amount: payload.fixed_amount,
                percentage: payload.percentage,
                priority: payload.priority || 1,
                is_active: true,
                metadata: { created_from: 'mobile_app' },
            })
            .select('*')
            .single();
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.patch('/wealth/allocation-rules/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const payload = AllocationRuleUpdateSchema.parse(req.body);
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
        const updatePayload: any = {
            updated_at: new Date().toISOString(),
        };
        if (payload.name !== undefined) updatePayload.name = payload.name;
        if (payload.trigger_type !== undefined) updatePayload.trigger_type = payload.trigger_type;
        if (payload.source_wallet_id !== undefined) updatePayload.source_wallet_id = payload.source_wallet_id;
        if (payload.target_type !== undefined) updatePayload.target_type = payload.target_type;
        if (payload.target_id !== undefined) updatePayload.target_id = payload.target_id;
        if (payload.mode !== undefined) updatePayload.mode = payload.mode;
        if (payload.fixed_amount !== undefined) updatePayload.fixed_amount = payload.fixed_amount;
        if (payload.percentage !== undefined) updatePayload.percentage = payload.percentage;
        if (payload.priority !== undefined) updatePayload.priority = payload.priority;
        if (payload.is_active !== undefined) updatePayload.is_active = payload.is_active;
        const { data, error } = await sb
            .from('allocation_rules')
            .update(updatePayload)
            .eq('id', req.params.id)
            .eq('user_id', session.sub)
            .select('*')
            .single();
        if (error) return res.status(400).json({ success: false, error: error.message });
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.get('/tasks', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getTasks(session.sub);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/tasks', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.postTask({ ...req.body, user_id: session.sub });
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/tasks/:id', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.updateTask({ ...req.body, id: req.params.id });
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.delete('/tasks/:id', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.deleteTask(req.params.id);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/goals/:id/allocate', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    const { amount, sourceWalletId } = req.body;
    if (!amount) return res.status(400).json({ success: false, error: 'MISSING_PARAMS' });

    try {
        const result = await LogicCore.allocateToGoal(req.params.id, amount, sourceWalletId, authToken || undefined);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/goals/:id/withdraw', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    const { amount, destinationWalletId, verification } = req.body;
    if (!amount || !destinationWalletId) {
        return res.status(400).json({ success: false, error: 'MISSING_PARAMS' });
    }

    const otpRequestId = verification?.otpRequestId || verification?.requestId || req.body.otpRequestId;
    const otpCode = verification?.otpCode || req.body.otpCode;
    if (!otpRequestId || !otpCode) {
        return res.status(403).json({ success: false, error: 'SECURITY_VERIFICATION_REQUIRED' });
    }

    try {
        const verified = await OTPService.verify(String(otpRequestId), String(otpCode), session.sub);
        if (!verified) {
            return res.status(403).json({ success: false, error: 'SECURITY_VERIFICATION_FAILED' });
        }

        const result = await LogicCore.withdrawFromGoal(req.params.id, amount, destinationWalletId, {
            verifiedVia: verification?.verifiedVia || 'otp',
            pinVerified: verification?.pinVerified === true,
            deliveryType: verification?.deliveryType || null,
            otpRequestId: String(otpRequestId),
            otpVerifiedAt: new Date().toISOString(),
            verifiedByUserId: session.sub
        }, authToken || undefined);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/goals/auto-allocate/replay', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    const sourceTransactionId = String(req.body?.sourceTransactionId || '').trim();
    if (!sourceTransactionId) {
        return res.status(400).json({ success: false, error: 'SOURCE_TRANSACTION_REQUIRED' });
    }

    try {
        const result = await LogicCore.replayGoalAutoAllocations(session.sub, sourceTransactionId, authToken || undefined);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

import { SandboxController } from '../../backend/sandbox/sandboxController.js';

// ... existing imports ...

// ... inside v1 routes ...

if (sandboxRoutesEnabled) v1.post('/sandbox/activate', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    
    // Default to current user if not provided
    if (!req.body.userId) req.body.userId = session.sub;

    // Security Check: Only admins can activate other users
    if (req.body.userId !== session.sub) {
        const role = session.role || session.user?.role;
        if (role !== 'ADMIN' && role !== 'SUPER_ADMIN') {
            return res.status(403).json({ success: false, error: 'ACCESS_DENIED: You can only activate your own account.' });
        }
    }

    await SandboxController.activateUser(req, res);
});

// --- Enterprise B2B Domain ---
v1.get('/enterprise/organizations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getOrganizations(session.sub);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/enterprise/organizations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.createOrganization(req.body, session.sub);
        if (result.error) return res.status(400).json({ success: false, error: result.error });
        res.json(result);
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/enterprise/organizations/:id', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.getOrganizationDetails(req.params.id);
        if (result.error) return res.status(404).json({ success: false, error: result.error });
        res.json(result);
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/enterprise/users/link', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const { userId, organizationId, role } = req.body;
    try {
        const result = await LogicCore.linkUserToOrganization(userId, organizationId, role, session.sub);
        if (result.error) return res.status(400).json({ success: false, error: result.error });
        res.json(result);
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/enterprise/users/invite', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const { email, organizationId, role } = req.body;
    try {
        const result = await LogicCore.inviteUserByEmail(email, organizationId, role, session.sub);
        if (result.error) return res.status(400).json({ success: false, error: result.error });
        res.json(result);
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/enterprise/treasury/withdraw/request', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const { goalId, amount, destinationWalletId, reason } = req.body;
    try {
        const result = await LogicCore.requestTreasuryWithdrawal(session.sub, goalId, amount, destinationWalletId, reason);
        if (result.error) return res.status(400).json({ success: false, error: result.error });
        res.json(result);
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/enterprise/treasury/withdraw/approve', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const { txId } = req.body;
    try {
        const result = await LogicCore.approveTreasuryWithdrawal(session.sub, txId);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.get('/enterprise/treasury/approvals', authenticate as any, async (req, res) => {
    const orgId = req.query.orgId as string;
    if (!orgId) return res.status(400).json({ success: false, error: 'MISSING_ORG_ID' });
    try {
        const result = await LogicCore.getPendingApprovals(orgId);
        res.json(result);
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/enterprise/treasury/autosweep', authenticate as any, async (req, res) => {
    const { goalId, enabled, threshold } = req.body;
    try {
        const result = await LogicCore.configureAutoSweep(goalId, enabled, threshold);
        res.json(result);
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * --- TRUSTBRIDGE: CONDITIONAL ESCROW APIs ---
 */
v1.get('/escrow', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getEscrows(session.sub);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/escrow/:id', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.getEscrow(req.params.id);
        if (!result) return res.status(404).json({ success: false, error: 'ESCROW_NOT_FOUND' });
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/escrow/create', authenticate as any, async (req, res) => {
    const { recipientCustomerId, amount, description, conditions } = req.body;
    const userId = (req as any).user.id;
    try {
        const referenceId = await LogicCore.createEscrow(userId, recipientCustomerId, amount, description, conditions);
        res.json({ success: true, referenceId });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.post('/escrow/release', authenticate as any, async (req, res) => {
    const { referenceId } = req.body;
    const userId = (req as any).user.id;
    try {
        const success = await LogicCore.releaseEscrow(referenceId, userId);
        res.json({ success });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.post('/escrow/dispute', authenticate as any, async (req, res) => {
    const { referenceId, reason } = req.body;
    const userId = (req as any).user.id;
    try {
        await LogicCore.disputeEscrow(referenceId, userId, reason);
        res.json({ success: true });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.post('/escrow/refund', authenticate as any, async (req, res) => {
    const { referenceId } = req.body;
    const userId = (req as any).user.id;
    const role = (req as any).user.role;

    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN') {
        return res.status(403).json({ success: false, error: 'UNAUTHORIZED_ADMIN_ONLY' });
    }

    try {
        await LogicCore.refundEscrow(referenceId, userId);
        res.json({ success: true });
    } catch (e: any) {
        res.status(400).json({ success: false, error: e.message });
    }
});

v1.get('/enterprise/budgets/alerts', authenticate as any, async (req, res) => {
    const orgId = req.query.orgId as string;
    if (!orgId) return res.status(400).json({ success: false, error: 'MISSING_ORG_ID' });
    try {
        const result = await LogicCore.getBudgetAlerts(orgId);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- RECONCILIATION ENGINE ---
v1.post('/admin/reconciliation/run', authenticate as any, requireSessionPermission(['reconciliation.run'], ['ADMIN', 'SUPER_ADMIN', 'AUDIT']), async (req, res) => {
    try {
        await LogicCore.runFullReconciliation();
        res.json({ success: true, message: 'Full reconciliation cycle triggered.' });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/admin/reconciliation/reports', authenticate as any, requireSessionPermission(['reconciliation.read', 'reconciliation.run'], ['ADMIN', 'SUPER_ADMIN', 'AUDIT', 'ACCOUNTANT']), async (req, res) => {
    const limit = Number(req.query.limit || 50);
    try {
        const result = await LogicCore.getReconciliationReports(limit);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- ADMIN CONFIGURATION APIs ---
v1.get('/admin/config/ledger', authenticate as any, requireSessionPermission(['config.ledger.read', 'config.ledger.write'], ['ADMIN', 'SUPER_ADMIN']), async (req, res) => {
    try {
        const config = await ConfigClient.getRuleConfig(true);
        res.json({ success: true, data: config.transaction_limits });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/admin/config/ledger', authenticate as any, requireSessionPermission(['config.ledger.write'], ['ADMIN', 'SUPER_ADMIN']), async (req, res) => {
    try {
        const currentConfig = await ConfigClient.getRuleConfig();
        const newLimits = req.body;
        
        const updatedConfig = {
            ...currentConfig,
            transaction_limits: {
                ...currentConfig.transaction_limits,
                ...newLimits
            }
        };
        
        await ConfigClient.saveConfig(updatedConfig);
        res.json({ success: true, message: 'Ledger configuration updated successfully.' });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/admin/config/commissions', authenticate as any, requireSessionPermission(['config.commissions.read', 'config.commissions.write'], ['ADMIN', 'SUPER_ADMIN', 'ACCOUNTANT']), async (req, res) => {
    try {
        const config = await ConfigClient.getRuleConfig(true);
        res.json({ success: true, data: config.commission_programs || {} });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/admin/config/commissions', authenticate as any, requireSessionPermission(['config.commissions.write'], ['ADMIN', 'SUPER_ADMIN']), async (req, res) => {
    try {
        const currentConfig = await ConfigClient.getRuleConfig();
        const updatedConfig = {
            ...currentConfig,
            commission_programs: {
                ...(currentConfig.commission_programs || {}),
                ...(req.body || {})
            }
        };
        await ConfigClient.saveConfig(updatedConfig);
        res.json({ success: true, message: 'Commission configuration updated successfully.' });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/admin/config/fx-rates', authenticate as any, requireSessionPermission(['config.fx.read', 'config.fx.write'], ['ADMIN', 'SUPER_ADMIN', 'ACCOUNTANT', 'IT']), async (req, res) => {
    try {
        const config = await ConfigClient.getRuleConfig(true);
        res.json({ success: true, data: config.exchange_rates });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/admin/config/fx-rates', authenticate as any, requireSessionPermission(['config.fx.write'], ['ADMIN', 'SUPER_ADMIN']), async (req, res) => {
    try {
        const currentConfig = await ConfigClient.getRuleConfig();
        const newRates = req.body;
        
        const updatedConfig = {
            ...currentConfig,
            exchange_rates: {
                ...currentConfig.exchange_rates,
                ...newRates
            }
        };
        
        await ConfigClient.saveConfig(updatedConfig);
        res.json({ success: true, message: 'Exchange rates updated successfully.' });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/admin/kms/rewrap', authenticate as any, adminOnly as any, async (req, res) => {
    try {
        const confirm = String(req.body?.confirm || '').trim().toUpperCase();
        if (confirm !== 'REWRAP_KEYS') {
            return res.status(400).json({
                success: false,
                error: 'CONFIRMATION_REQUIRED',
                message: 'Set confirm=REWRAP_KEYS to proceed.'
            });
        }

        const newMasterKey = String(req.body?.newMasterKey || '').trim();
        const resolvedMasterKey = newMasterKey || String(process.env.KMS_MASTER_KEY || '').trim();
        if (!resolvedMasterKey) {
            return res.status(400).json({
                success: false,
                error: 'KMS_MASTER_KEY_MISSING',
                message: 'No master key provided or configured.'
            });
        }

        await KMS.reWrapAllKeys(resolvedMasterKey);
        res.json({ success: true, message: 'KMS keys re-wrapped successfully.' });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/admin/kms/health', authenticate as any, adminOnly as any, async (_req, res) => {
    try {
        const probe = { ping: 'pong', ts: Date.now() };
        const cipher = await DataVault.encrypt(probe);
        const decoded = await DataVault.decrypt(cipher);
        const ok =
            decoded &&
            typeof decoded === 'object' &&
            (decoded as any).ping === 'pong';
        res.json({
            success: ok,
            data: {
                ok,
                ts: Date.now()
            }
        });
    } catch (e: any) {
        res.status(500).json({
            success: false,
            error: e.message
        });
    }
});

v1.post('/admin/kms/diagnose', authenticate as any, adminOnly as any, async (req, res) => {
    try {
        const masterKey = String(req.body?.masterKey || process.env.KMS_MASTER_KEY || '').trim();
        if (!masterKey) {
            return res.status(400).json({
                success: false,
                error: 'KMS_MASTER_KEY_MISSING'
            });
        }

        const configuredSalt = process.env.KMS_SALT || '';
        const defaultSalt = 'orbi-kms-wrapping-salt-v1';

        const matchConfigured = await KMS.testUnwrapWithSecret(masterKey, configuredSalt || undefined);
        const matchDefault = await KMS.testUnwrapWithSecret(masterKey, defaultSalt);

        res.json({
            success: true,
            data: {
                matchConfiguredSalt: matchConfigured,
                matchDefaultSalt: matchDefault,
                configuredSalt: configuredSalt ? 'SET' : 'EMPTY'
            }
        });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- System Domain ---
v1.get('/sys/bootstrap', authenticate as any, async (req, res) => {
    const token = req.headers.authorization?.substring(7);
    try {
        const result = await LogicCore.getBootstrapData(token);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/sys/metrics', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.getSystemMetrics();
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/transactions/secure-sign', authenticate as any, async (req, res) => {
    try {
        const { transactionPayload, signature, publicKey } = req.body;
        
        const hash = TransactionSigning.generateTransactionHash(transactionPayload);
        const isValid = TransactionSigning.verifySecureEnclaveSignature(hash, signature, publicKey);

        if (!isValid) {
            return res.status(403).json({ success: false, error: "SECURE_ENCLAVE_SIGNATURE_INVALID" });
        }

        // Proceed to process the transaction securely
        const result = await LogicCore.processSecurePayment(transactionPayload, (req as any).session.user);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

mountPublicRoutes(app, v1, globalIpLimiter as any);

registerLegacyGatewayRoute(app, {
    enabled: legacyApiGatewayEnabled,
    globalIpLimiter: globalIpLimiter as any,
    WAF,
    Sentinel,
    LogicCore,
    PolicyEngine,
});

registerTerminalHandlers(app);

export { app, httpServer, PORT, gatewayBackgroundJobsEnabled, ALLOWED_ORIGINS, globalIpLimiter, legacyApiGatewayEnabled };
