import 'dotenv/config';
import { registerInternalRoutes, mountInternalRoutes } from '../routes/internal/index.js';
import { registerAdminRoutes, mountAdminRoutes } from '../routes/admin/index.js';
import { mountPublicRoutes, registerLegacyGatewayRoute, registerMonitoringRoutes, registerTerminalHandlers, registerTopLevelPublicRoutes } from '../routes/public/index.js';
import { registerAuthUserRoutes } from '../routes/public/authUser.js';
import { registerSupportOpsRoutes } from '../routes/public/supportOps.js';
import { registerAdminOpsRoutes } from '../routes/public/adminOps.js';
import { registerCommerceRoutes } from '../routes/public/commerce.js';
import { registerCoreFinanceRoutes } from '../routes/public/coreFinance.js';
import { registerEngagementRoutes } from '../routes/public/engagement.js';
import { registerStrategyRoutes } from '../routes/public/strategy.js';
import { registerOperationsRoutes } from '../routes/public/operations.js';
import { registerWealthRoutes } from '../routes/public/wealth.js';
import { wealthNumber, resolveWealthSourceWallet, assertBillPaymentSourceAllowed, billReserveValuesMatch, resolveBillReserveReference, BillReservePaymentSchema } from '../routes/public/wealthShared.js';
import { registerProviderRoutes, mountProviderRoutes } from '../routes/providers/index.js';
import { validate } from '../middleware/validation/validate.js';
import { authenticate, adminOnly, resolveSessionRole, requireRole, resolveSessionRegistryType, mapServiceRoleToRegistryType, requireSessionPermission } from '../middleware/auth/sessionAuth.js';
import { ALLOWED_ORIGINS, configureCoreSecurityMiddleware, createGlobalIpLimiter } from '../middleware/security/setup.js';
import express from 'express';
import { createServer } from 'http';
import { Server as LogicCore } from '../../backend/server.js';
import { Sentinel } from '../../backend/security/sentinel.js';
import { WAF } from '../../backend/security/waf.js';
import { getSupabase, getAdminSupabase } from '../../backend/supabaseClient.js';
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
// emailService removed as per user request
import multer from 'multer';
import { Auth as NewAuth } from '../../backend/src/modules/auth/auth.controller.js';
import { ReconciliationEngine as ReconEngine } from '../../backend/ledger/reconciliationEngine.js';
import { authenticateApiKey } from '../../backend/middleware/apiKeyAuth.js';
import { TransactionService } from '../../ledger/transactionService.js';
import { FXEngine } from '../../backend/ledger/FXEngine.js';
import { continuousSessionMonitor } from '../../backend/src/middleware/session-monitor.middleware.js';
import { TransactionSigning } from '../../backend/src/modules/transaction/signing.service.js';
import { OTPService } from '../../backend/security/otpService.js';
import { ServiceActorOps } from '../../backend/features/ServiceActorOps.js';
import gatewayRoutes from '../../backend/payments/gatewayRoutes.js';
import { settlementScheduler } from '../../backend/payments/settlementScheduler.js';
import { KMS } from '../../backend/security/kms.js';
import { DataVault } from '../../backend/security/encryption.js';
import { SandboxController } from '../../backend/sandbox/sandboxController.js';

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

// 11. ADMIN PARTNER REGISTRY ROUTES
const admin = express.Router();
registerAdminRoutes(admin, authenticate as any);
mountAdminRoutes(app, admin);

const v1 = express.Router();
const gatewayV1 = express.Router();

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

registerCoreFinanceRoutes(v1, {
    authenticate: authenticate as any,
    authenticateApiKey: authenticateApiKey as any,
    validate,
    requireRole,
    LogicCore,
    getSupabase,
    PolicyEngine,
    FXEngine,
    TransactionService,
    WalletCreateSchema,
    WalletLockSchema,
    WalletUnlockSchema,
    PaymentIntentSchema,
    TransactionIssueSchema,
});
registerEngagementRoutes(v1, {
    authenticate: authenticate as any,
    upload,
    LogicCore,
    getAdminSupabase,
});
registerStrategyRoutes(v1, {
    authenticate: authenticate as any,
    validate,
    LogicCore,
    OTPService,
    GoalCreateSchema,
    GoalUpdateSchema,
});
registerOperationsRoutes(v1, {
    authenticate: authenticate as any,
    adminOnly: adminOnly as any,
    requireSessionPermission,
    LogicCore,
    ConfigClient,
    KMS,
    DataVault,
    TransactionSigning,
    SandboxController,
    sandboxRoutesEnabled,
});

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

registerWealthRoutes(v1, {
    authenticate: authenticate as any,
    LogicCore,
    getSupabase,
    getAdminSupabase,
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
