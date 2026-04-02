import type { Express } from 'express';
import { registerMonitoringRoutes, registerTopLevelPublicRoutes } from '../routes/public/index.js';
import { configureCoreSecurityMiddleware, createGlobalIpLimiter } from '../middleware/security/setup.js';
import { authenticateApiKey } from '../../backend/middleware/apiKeyAuth.js';
import { RedisClusterFactory } from '../../backend/infrastructure/RedisClusterFactory.js';
import { ResilienceEngine } from '../../backend/infrastructure/ResilienceEngine.js';
import { operationalHealthService } from '../../backend/infrastructure/OperationalHealthService.js';
import { Server as LogicCore } from '../../backend/server.js';
import { ReconciliationEngine as ReconEngine } from '../../backend/ledger/reconciliationEngine.js';

export const createAppContext = (app: Express) => {
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

  configureCoreSecurityMiddleware(app, {
    redisAvailable,
    redisClient,
    allowProcessLocalIdempotency,
    idempotencyTtlSeconds,
  });

  registerMonitoringRoutes(app, {
    authenticateApiKey,
    ReconEngine,
    OperationalHealthService: operationalHealthService,
  });

  const globalIpLimiter = createGlobalIpLimiter(redisAvailable, redisClient);

  registerTopLevelPublicRoutes(app, {
    ResilienceEngine,
    LogicCore,
    OperationalHealthService: operationalHealthService,
  });

  return {
    gatewayBackgroundJobsEnabled,
    legacyApiGatewayEnabled,
    legacyBiometricAliasesEnabled,
    sandboxRoutesEnabled,
    messagingTestRoutesEnabled,
    globalIpLimiter,
  };
};
