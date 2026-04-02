import type { Express, RequestHandler } from 'express';
import { wealthNumber, resolveWealthSourceWallet, assertBillPaymentSourceAllowed, billReserveValuesMatch, resolveBillReserveReference, BillReservePaymentSchema } from '../routes/public/wealthShared.js';
import {
  LoginSchema,
  SignUpSchema,
  PaymentIntentSchema,
  WalletCreateSchema,
  WalletLockSchema,
  WalletUnlockSchema,
  GoalCreateSchema,
  GoalUpdateSchema,
  KYCSubmitSchema,
  KYCReviewSchema,
  AccountStatusUpdateSchema,
  UserProfileUpdateSchema,
  StaffCreateSchema,
  StaffAdminUpdateSchema,
  StaffPasswordResetSchema,
  ManagedIdentityCreateSchema,
  BootstrapAdminSchema,
  DeviceRegisterSchema,
  DeviceTrustSchema,
  DocumentUploadSchema,
  DocumentVerifySchema,
  ServiceCustomerRegistrationSchema,
  ServiceAccessRequestCreateSchema,
  ServiceAccessRequestReviewSchema,
} from '../../backend/security/schemas.js';
import { Auth as NewAuth } from '../../backend/src/modules/auth/auth.controller.js';
import { authenticateApiKey } from '../../backend/middleware/apiKeyAuth.js';
import { Server as LogicCore } from '../../backend/server.js';
import { getSupabase, getAdminSupabase } from '../../backend/supabaseClient.js';
import { Webhooks } from '../../backend/payments/webhookHandler.js';
import { PolicyEngine } from '../../backend/ledger/PolicyEngine.js';
import { ConfigClient } from '../../backend/infrastructure/RulesConfigClient.js';
import { TransactionService } from '../../ledger/transactionService.js';
import { FXEngine } from '../../backend/ledger/FXEngine.js';
import { TransactionSigning } from '../../backend/src/modules/transaction/signing.service.js';
import { OTPService } from '../../backend/security/otpService.js';
import { KMS } from '../../backend/security/kms.js';
import { DataProtection } from '../../backend/security/DataProtection.js';
import { SandboxController } from '../../backend/sandbox/sandboxController.js';
import { syncUserIdentityClassification } from './identity.js';

export const buildPublicRouteDeps = ({
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
  upload,
  resolveSessionRole,
  resolveSessionRegistryType,
  mapServiceRoleToRegistryType,
}: {
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
  upload: any;
  resolveSessionRole: (...args: any[]) => any;
  resolveSessionRegistryType: (...args: any[]) => any;
  mapServiceRoleToRegistryType: (role: string) => string;
}) => ({
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
  DataProtection,
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
