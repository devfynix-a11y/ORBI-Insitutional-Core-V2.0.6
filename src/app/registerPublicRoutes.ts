import express from 'express';
import type { Express, RequestHandler } from 'express';
import { mountPublicRoutes, registerLegacyGatewayRoute, registerTerminalHandlers } from '../routes/public/index.js';
import { registerAuthUserRoutes } from '../routes/public/authUser.js';
import { registerSupportOpsRoutes } from '../routes/public/supportOps.js';
import { registerAdminOpsRoutes } from '../routes/public/adminOps.js';
import { registerCommerceRoutes } from '../routes/public/commerce.js';
import { registerCoreFinanceRoutes } from '../routes/public/coreFinance.js';
import { registerEngagementRoutes } from '../routes/public/engagement.js';
import { registerStrategyRoutes } from '../routes/public/strategy.js';
import { registerOperationsRoutes } from '../routes/public/operations.js';
import { registerWealthRoutes } from '../routes/public/wealth.js';
import { registerProviderRoutes, mountProviderRoutes } from '../routes/providers/index.js';
import gatewayRoutes from '../../backend/payments/gatewayRoutes.js';
import { WAF } from '../../backend/security/waf.js';
import { Sentinel } from '../../backend/security/sentinel.js';
import { queryStringValue, TransactionAuditDecisionSchema, TransactionIssueSchema } from './helpers.js';

type Deps = {
  app: Express;
  globalIpLimiter: RequestHandler;
  legacyApiGatewayEnabled: boolean;
  legacyBiometricAliasesEnabled: boolean;
  messagingTestRoutesEnabled: boolean;
  sandboxRoutesEnabled: boolean;
  authenticate: RequestHandler;
  adminOnly: RequestHandler;
  validate: (schema: any) => RequestHandler;
  requireSessionPermission: (permissions: string[], roles?: string[]) => RequestHandler;
  authenticateApiKey: RequestHandler;
  upload: any;
  LogicCore: any;
  NewAuth: any;
  getSupabase: () => any;
  getAdminSupabase: () => any;
  resolveSessionRole: (...args: any[]) => any;
  resolveSessionRegistryType: (...args: any[]) => any;
  mapServiceRoleToRegistryType: (role: string) => string;
  syncUserIdentityClassification: (userId: string, updates: { role: string; registryType: string; metadata?: Record<string, any> }) => Promise<void>;
  PolicyEngine: any;
  FXEngine: any;
  TransactionService: any;
  OTPService: any;
  ConfigClient: any;
  KMS: any;
  DataVault: any;
  TransactionSigning: any;
  SandboxController: any;
  Webhooks: any;
  resolveWealthSourceWallet: any;
  assertBillPaymentSourceAllowed: any;
  billReserveValuesMatch: any;
  resolveBillReserveReference: any;
  wealthNumber: any;
  LoginSchema: any;
  BootstrapAdminSchema: any;
  SignUpSchema: any;
  KYCSubmitSchema: any;
  ServiceAccessRequestCreateSchema: any;
  KYCReviewSchema: any;
  DeviceRegisterSchema: any;
  DeviceTrustSchema: any;
  DocumentUploadSchema: any;
  DocumentVerifySchema: any;
  StaffCreateSchema: any;
  StaffAdminUpdateSchema: any;
  StaffPasswordResetSchema: any;
  ManagedIdentityCreateSchema: any;
  ServiceAccessRequestReviewSchema: any;
  AccountStatusUpdateSchema: any;
  UserProfileUpdateSchema: any;
  WalletCreateSchema: any;
  WalletLockSchema: any;
  WalletUnlockSchema: any;
  PaymentIntentSchema: any;
  GoalCreateSchema: any;
  GoalUpdateSchema: any;
  ServiceCustomerRegistrationSchema: any;
  BillReservePaymentSchema: any;
};

const sessionHasAnyRole = (session: any, roles: string[]) => {
  const role = session?.role || session?.user?.role;
  return roles.includes(role);
};

export const registerAppPublicRoutes = (deps: Deps) => {
  const {
    app,
    globalIpLimiter,
    legacyApiGatewayEnabled,
    legacyBiometricAliasesEnabled,
    messagingTestRoutesEnabled,
    sandboxRoutesEnabled,
    authenticate,
    adminOnly,
    validate,
    requireSessionPermission,
    authenticateApiKey,
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
  } = deps;

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
    requireRole: sessionHasAnyRole,
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
    requireRole: sessionHasAnyRole,
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
};
