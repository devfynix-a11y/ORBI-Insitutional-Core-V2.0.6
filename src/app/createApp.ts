import 'dotenv/config';
import { validateStartupEnvironment } from '../bootstrap/validation.js';
import { createAppContext } from './context.js';
import { buildPublicRouteDeps } from './publicRouteDeps.js';
import { registerAppPublicRoutes } from './registerPublicRoutes.js';
import { registerSystemRoutes } from './registerSystemRoutes.js';
import { validate } from '../middleware/validation/validate.js';
import { authenticate, adminOnly, resolveSessionRole, resolveSessionRegistryType, mapServiceRoleToRegistryType, requireSessionPermission } from '../middleware/auth/sessionAuth.js';
import { ALLOWED_ORIGINS } from '../middleware/security/setup.js';
import { createRuntime } from './runtime.js';
import { continuousSessionMonitor } from '../../backend/src/middleware/session-monitor.middleware.js';

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
    ...buildPublicRouteDeps({
        app,
        globalIpLimiter: globalIpLimiter as any,
        legacyApiGatewayEnabled,
        legacyBiometricAliasesEnabled,
        messagingTestRoutesEnabled,
        sandboxRoutesEnabled,
        authenticate: authenticate as any,
        adminOnly: adminOnly as any,
        validate,
        requireSessionPermission,
        upload,
        resolveSessionRole,
        resolveSessionRegistryType,
        mapServiceRoleToRegistryType,
    }),
});

export { app, httpServer, PORT, gatewayBackgroundJobsEnabled, ALLOWED_ORIGINS, globalIpLimiter, legacyApiGatewayEnabled };
