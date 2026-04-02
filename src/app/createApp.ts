import 'dotenv/config';
import { validateStartupEnvironment } from '../bootstrap/validation.js';
import { createAppContext } from './context.js';
import { syncUserIdentityClassification } from './identity.js';
import { registerAppPublicRoutes } from './registerPublicRoutes.js';
import { registerSystemRoutes } from './registerSystemRoutes.js';
import { wealthNumber, resolveWealthSourceWallet, assertBillPaymentSourceAllowed, billReserveValuesMatch, resolveBillReserveReference, BillReservePaymentSchema } from '../routes/public/wealthShared.js';
import { validate } from '../middleware/validation/validate.js';
import { authenticate, adminOnly, resolveSessionRole, requireRole, resolveSessionRegistryType, mapServiceRoleToRegistryType, requireSessionPermission } from '../middleware/auth/sessionAuth.js';
import { ALLOWED_ORIGINS } from '../middleware/security/setup.js';
import { createRuntime } from './runtime.js';
import { Server as LogicCore } from '../../backend/server.js';
import { getSupabase, getAdminSupabase } from '../../backend/supabaseClient.js';
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
// emailService removed as per user request
import { Auth as NewAuth } from '../../backend/src/modules/auth/auth.controller.js';
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

validateStartupEnvironment();

const { app, httpServer, upload, port: PORT } = createRuntime();

/**
 * ORBI SOVEREIGN GATEWAY (V28.0 Platinum)
 * ---------------------------------------
 * Production-hardened RESTful API with Zod validation and Sentinel AI.
 */

const {
    gatewayBackgroundJobsEnabled,
    legacyApiGatewayEnabled,
    legacyBiometricAliasesEnabled,
    sandboxRoutesEnabled,
    messagingTestRoutesEnabled,
    globalIpLimiter,
} = createAppContext(app);

// Continuous Session Monitoring Middleware
app.use('/api/v1', continuousSessionMonitor);

registerSystemRoutes({
    app,
    authenticate: authenticate as any,
});

registerAppPublicRoutes({
    app,
    globalIpLimiter: globalIpLimiter as any,
    legacyApiGatewayEnabled,
    legacyBiometricAliasesEnabled,
    messagingTestRoutesEnabled,
    sandboxRoutesEnabled,
    authenticate: authenticate as any,
    adminOnly: adminOnly as any,
    validate,
    requireRole,
    requireSessionPermission,
    authenticateApiKey: authenticateApiKey as any,
    upload,
    LogicCore,
    NewAuth,
    getSupabase,
    getAdminSupabase,
    resolveSessionRole,
    resolveSessionRegistryType,
    mapServiceRoleToRegistryType,
    syncUserIdentityClassification,
    PolicyEngine,
    FXEngine,
    TransactionService,
    OTPService,
    ConfigClient,
    KMS,
    DataVault,
    TransactionSigning,
    SandboxController,
    Webhooks,
    resolveWealthSourceWallet,
    assertBillPaymentSourceAllowed,
    billReserveValuesMatch,
    resolveBillReserveReference,
    wealthNumber,
    LoginSchema,
    BootstrapAdminSchema,
    SignUpSchema,
    KYCSubmitSchema,
    ServiceAccessRequestCreateSchema,
    KYCReviewSchema,
    DeviceRegisterSchema,
    DeviceTrustSchema,
    DocumentUploadSchema,
    DocumentVerifySchema,
    StaffCreateSchema,
    StaffAdminUpdateSchema,
    StaffPasswordResetSchema,
    ManagedIdentityCreateSchema,
    ServiceAccessRequestReviewSchema,
    AccountStatusUpdateSchema,
    UserProfileUpdateSchema,
    WalletCreateSchema,
    WalletLockSchema,
    WalletUnlockSchema,
    PaymentIntentSchema,
    GoalCreateSchema,
    GoalUpdateSchema,
    ServiceCustomerRegistrationSchema,
    BillReservePaymentSchema,
});

export { app, httpServer, PORT, gatewayBackgroundJobsEnabled, ALLOWED_ORIGINS, globalIpLimiter, legacyApiGatewayEnabled };
