import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import { createServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import cors from 'cors';
import helmet from 'helmet';
import { Server as LogicCore } from './backend/server.js';
import { Sentinel } from './backend/security/sentinel.js';
import { WAF } from './backend/security/waf.js';
import { rateLimit } from 'express-rate-limit';
import { getSupabase, getAdminSupabase } from './backend/supabaseClient.js';
import { BankingEngineService } from './backend/ledger/transactionEngine.js';
import { Audit } from './backend/security/audit.js';
import { ResilienceEngine } from './backend/infrastructure/ResilienceEngine.js';
import { Webhooks } from './backend/payments/webhookHandler.js';
import { SanitizerService } from './backend/security/sanitizer.js';
import { RiskEngine } from './backend/security/RiskEngine.js';
import { PolicyEngine } from './backend/ledger/PolicyEngine.js';
import { ConfigClient } from './backend/infrastructure/RulesConfigClient.js';
import { 
    LoginSchema, SignUpSchema, PaymentIntentSchema, 
    WalletCreateSchema, GoalCreateSchema, KYCSubmitSchema, KYCReviewSchema,
    AccountStatusUpdateSchema, UserProfileUpdateSchema, StaffCreateSchema,
    DeviceRegisterSchema, DeviceTrustSchema, DocumentUploadSchema, DocumentVerifySchema
} from './backend/security/schemas.js';
import { z } from 'zod';
import { RedisClusterFactory } from './backend/infrastructure/RedisClusterFactory.js';
import { RedisStore } from 'rate-limit-redis';
import { AuthService } from './iam/authService.js';
// emailService removed as per user request
import multer from 'multer';
import { Auth as NewAuth } from './backend/src/modules/auth/auth.controller.js';
import { ReconEngine as LegacyRecon } from './backend/ledger/reconciliationService.js';
import { ReconciliationEngine as ReconEngine } from './backend/ledger/reconciliationEngine.js';
import { authenticateApiKey } from './backend/middleware/apiKeyAuth.js';
import { EntProcessor } from './backend/enterprise/wealth/EnterprisePaymentProcessor.js';
import { PartnerRegistry } from './backend/admin/partnerRegistry.js';
import { TransactionService } from './ledger/transactionService.js';
import { FXEngine } from './backend/ledger/FXEngine.js';
import { NotificationSubscriber } from './backend/infrastructure/NotificationSubscriber.js';
import { OrbiKnowledge } from './src/constants/orbiKnowledge.js';
import { continuousSessionMonitor } from './backend/src/middleware/session-monitor.middleware.js';
import { TransactionSigning } from './backend/src/modules/transaction/signing.service.js';
import { GoogleGenAI, Type } from "@google/genai";
import { appTrustMiddleware } from './backend/middleware/appTrust.js';
import { RecoveryService } from './services/security/recoveryService.js';

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

function getDeviceNameFromUA(userAgent?: string): string {
    if (!userAgent) return 'Unknown Device';
    if (userAgent.includes('Android')) return 'Android Device';
    if (userAgent.includes('iPhone')) return 'iPhone';
    if (userAgent.includes('iPad')) return 'iPad';
    if (userAgent.includes('Windows')) return 'Windows PC';
    if (userAgent.includes('Macintosh')) return 'Mac';
    if (userAgent.includes('Linux')) return 'Linux Device';
    return 'Web Browser';
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

// Dynamically serve assetlinks.json to support Android App Passkeys on dynamic domains
app.get('/.well-known/assetlinks.json', (req, res, next) => {
    const base64Hash = process.env.ORBI_ANDROID_APP_HASH?.replace(/['"]/g, '');
    if (!base64Hash) {
        return next(); // Fallback to static file if env var is missing
    }

    let hexHash = '';
    try {
        const buffer = Buffer.from(base64Hash, 'base64');
        const hexString = buffer.toString('hex').toUpperCase();
        hexHash = hexString.match(/.{1,2}/g)?.join(':') || '';
    } catch (e) {
        console.error("Failed to convert ORBI_ANDROID_APP_HASH to hex format", e);
        hexHash = base64Hash;
    }

    res.json([{
        "relation": [
            "delegate_permission/common.handle_all_urls",
            "delegate_permission/common.get_login_creds"
        ],
        "target": {
            "namespace": "android_app",
            "package_name": "com.example.orbi_mobileapp",
            "sha256_cert_fingerprints": [hexHash]
        }
    }]);
});

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

// IDEMPOTENCY CACHE (In-memory fallback, Redis preferred)
const idempotencyCache = new Map<string, { status: number, body: any }>();

const idempotencyMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    const key = req.header('Idempotency-Key');
    if (!key) return next();

    // Check if we've processed this key before
    const cached = idempotencyCache.get(key);
    if (cached) {
        console.info(`[Idempotency] Duplicate request detected for key: ${key}`);
        return res.status(cached.status).json(cached.body);
    }

    // Wrap res.json to cache the response
    const originalJson = res.json;
    res.json = function(body: any) {
        idempotencyCache.set(key, { status: res.statusCode, body });
        // Keep cache small for this demo
        if (idempotencyCache.size > 1000) {
            const firstKey = idempotencyCache.keys().next().value;
            if (firstKey !== undefined) idempotencyCache.delete(firstKey);
        }
        return originalJson.call(this, body);
    };

    next();
};

app.use(idempotencyMiddleware);

// --- FORENSIC MONITORING API ---
app.get('/api/admin/monitor/ledger-health', authenticateApiKey, async (req, res) => {
    try {
        const auditResult = await ReconEngine.runFullAudit();
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            status: auditResult.discrepancies.length === 0 ? 'HEALTHY' : 'CRITICAL_DISCREPANCY',
            data: auditResult
        });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/admin/monitor/wallet-forensics/:walletId', authenticateApiKey, async (req, res) => {
    try {
        const walletId = String(req.params.walletId);
        const result = await ReconEngine.auditWalletTimeline(walletId);
        res.json({
            success: true,
            walletId,
            ...result
        });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

const globalIpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 2000, 
    standardHeaders: true, 
    legacyHeaders: false,
    message: { success: false, error: 'INFRA_RATE_LIMIT_EXCEEDED' },
    validate: { xForwardedForHeader: false },
    store: (redisAvailable && redisClient) ? new RedisStore({
        sendCommand: (...args: string[]) => redisClient.call(args[0], ...args.slice(1)) as any,
    }) : undefined
});

// 2. MIDDLEWARE STACK
const ALLOWED_ORIGINS = [
    'https://orbi-financial-technologies-c0re-v2026.onrender.com',
    'https://orbi-backend-v2-0-1.onrender.com',
    'https://fynix-backend-v2-0-1.onrender.com',
    'https://ais-dev-otadbk3zs67js4adfe3zhb-131722823335.europe-west2.run.app',
    'https://ais-pre-otadbk3zs67js4adfe3zhb-131722823335.europe-west2.run.app',
    'https://ais-dev-egx2rrccp653yh67wk47za-20006156269.europe-west2.run.app',
    'https://ais-pre-egx2rrccp653yh67wk47za-20006156269.europe-west2.run.app'
];

app.use(cors({
    origin: (origin, callback) => {
        // In production, we strictly enforce the allowlist
        if (!origin) {
            // Allow requests with no origin (like mobile apps or curl)
            // but appTrustMiddleware will handle the deeper validation
            return callback(null, true);
        }
        
        if (ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`[CORS] Rejection for origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'x-orbi-app-id', 
        'x-orbi-trace', 
        'x-idempotency-key',
        'x-orbi-apk-hash'
    ]
}));

app.use(helmet());

// 2.5 APP TRUST GATEKEEPER
// Ensures requests only come from official Orbi applications or trusted domains.
app.use(appTrustMiddleware);

app.use(express.json({ limit: '20mb' }) as any);

// WAF Deep Packet Inspection Middleware
const wafInspect = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (req.body && Object.keys(req.body).length > 0) {
            await WAF.inspect(req.body, req.ip);
        }
        next();
    } catch (err: any) {
        res.status(403).json({ success: false, error: 'WAF_REJECTION', message: err.message });
    }
};

app.use(wafInspect);

// Content Sanitization Middleware
const sanitizeContent = (req: Request, res: Response, next: NextFunction) => {
    if (req.body && Object.keys(req.body).length > 0) {
        req.body = SanitizerService.sanitize(req.body);
    }
    next();
};

app.use(sanitizeContent);

// Risk Assessment Middleware
const riskAssessment = async (req: Request, res: Response, next: NextFunction) => {
    // Skip risk check for health and public assets
    if (req.path === '/health' || req.path.startsWith('/public')) return next();

    try {
        const context = {
            userId: (req as any).user?.sub,
            ip: req.ip || '0.0.0.0',
            appId: req.headers['x-orbi-app-id'] as string || 'anonymous-node'
        };

        const risk = await RiskEngine.evaluateRequest(req, context);

        if (risk.action === 'BLOCK') {
            return res.status(403).json({ 
                success: false, 
                error: 'SECURITY_BLOCK', 
                message: 'Request blocked by Risk Engine',
                score: risk.score
            });
        }

        // Attach risk info to request for downstream logic
        (req as any).risk = risk;
        next();
    } catch (err: any) {
        // Fail-safe: allow but log error
        console.error("[RiskEngine] Evaluation Fault:", err.message);
        next();
    }
};

app.use(riskAssessment);

// Validation Middleware
const validate = (schema: z.ZodSchema) => (req: Request, res: Response, next: NextFunction) => {
    try {
        schema.parse(req.body);
        next();
    } catch (err: any) {
        res.status(400).json({ 
            success: false, 
            error: 'VALIDATION_FAILED', 
            details: err.errors?.map((e: any) => ({ path: e.path, message: e.message })) || []
        });
    }
};

// Auth Middleware
const authenticate = async (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null;
    try {
        const session = await LogicCore.getSession(token || undefined);
        if (!session) throw new Error("IDENTITY_REQUIRED");
        
        // HARDENING: Enforce Account Status
        const status = session.user.user_metadata?.account_status || 'active';
        if (status === 'blocked' || status === 'frozen') {
            return res.status(403).json({ 
                success: false, 
                error: 'IDENTITY_LOCKED', 
                message: `Your account has been ${status.toUpperCase()} by Cluster Governance.` 
            });
        }

        // WAF Throttling
        const operation = req.path.replace(/\//g, '_').substring(1);
        await WAF.throttle(session.user.id, operation);

        (req as any).session = session;
        next();
    } catch (err: any) {
        if (err.message.startsWith('RATE_LIMIT_EXCEEDED')) {
            return res.status(429).json({ success: false, error: 'RATE_LIMIT_EXCEEDED', message: err.message });
        }
        res.status(401).json({ success: false, error: 'AUTH_REQUIRED', message: err.message });
    }
};

// Continuous Session Monitoring Middleware
app.use('/api/v1', continuousSessionMonitor);

const adminOnly = async (req: Request, res: Response, next: NextFunction) => {
    const session = (req as any).session;
    if (!session) return res.status(401).json({ success: false, error: 'AUTH_REQUIRED' });

    const role = session.user.user_metadata?.role;
    const orgRole = session.user.user_metadata?.org_role;

    if (role === 'ADMIN' || role === 'STAFF' || orgRole === 'ADMIN') {
        next();
    } else {
        res.status(403).json({ success: false, error: 'ADMIN_ACCESS_REQUIRED' });
    }
};

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

/**
 * WORKER AUTHENTICATION MIDDLEWARE
 * Enforces x-worker-secret header validation for all internal endpoints.
 */
const workerAuth = (req: Request, res: Response, next: NextFunction) => {
    const secret = req.headers['x-worker-secret'];
    const expected = process.env.WORKER_SECRET;
    
    if (secret && expected && secret === expected) {
        next();
    } else {
        console.warn(`[Internal] Unauthorized worker access attempt from ${req.ip}`);
        res.status(401).json({ success: false, error: 'UNAUTHORIZED_WORKER' });
    }
};

internal.use(workerAuth);

/**
 * 1. CLAIM PENDING TRANSACTIONS
 * Finds and locks pending transactions for processing.
 */
internal.post('/transactions/claim', async (req, res) => {
    const limit = req.body.limit || 100;
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) return res.status(500).json({ success: false, error: 'DB_OFFLINE' });

    try {
        // Atomic claim using update with returning to prevent double-processing
        const { data, error } = await sb
            .from('transactions')
            .update({ status: 'processing', updated_at: new Date().toISOString() })
            .eq('status', 'pending')
            .order('created_at', { ascending: true })
            .limit(limit)
            .select();

        if (error) throw error;
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * 2. RESOLVE TRANSACTION
 * Finalizes a transaction and updates balances if completed.
 */
internal.put('/transactions/:id/resolve', async (req, res) => {
    const { id } = req.params;
    const { status } = req.body; // 'completed' or 'failed'
    
    try {
        const engine = new BankingEngineService();
        if (status === 'completed') {
            const success = await engine.completeSettlement(id);
            res.json({ success });
        } else {
            const sb = getAdminSupabase() || getSupabase();
            const { error } = await sb!.from('transactions').update({ status: 'failed' }).eq('id', id);
            res.json({ success: !error });
        }
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * 3. GET REVERSIBLE TRANSACTIONS
 * Identifies failed or stuck transactions that need reversal.
 */
internal.get('/transactions/reversible', async (req, res) => {
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) return res.status(500).json({ success: false, error: 'DB_OFFLINE' });

    const fifteenMinsAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();

    try {
        const { data, error } = await sb
            .from('transactions')
            .select('*')
            .or(`status.eq.failed,and(status.eq.processing,updated_at.lt.${fifteenMinsAgo})`);

        if (error) throw error;
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * 4. REVERSE TRANSACTION
 * Executes financial reversal logic and logs audit trail.
 */
internal.post('/transactions/:id/reverse', async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;
    
    try {
        const sb = getAdminSupabase() || getSupabase();
        const { data: tx } = await sb!.from('transactions').select('*').eq('id', id).single();
        if (!tx) return res.status(404).json({ success: false, error: 'NOT_FOUND' });

        // Update status and metadata
        const { error } = await sb!.from('transactions').update({ 
            status: 'reversed', 
            metadata: { ...tx.metadata, reversal_reason: reason, reversed_at: new Date().toISOString() } 
        }).eq('id', id);

        if (error) throw error;

        await Audit.log('FINANCIAL', tx.user_id, 'TRANSACTION_REVERSED', { txId: id, reason });
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * 5. GET RECENT TRANSACTIONS
 * Fetches transactions from a recent time window for security analysis.
 */
internal.get('/transactions/recent', async (req, res) => {
    const minutes = parseInt(req.query.minutes as string) || 5;
    const sb = getAdminSupabase() || getSupabase();
    const startTime = new Date(Date.now() - minutes * 60 * 1000).toISOString();

    try {
        const { data, error } = await sb!.from('transactions').select('*').gte('created_at', startTime);
        if (error) throw error;
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * 6. REPORT ANOMALY
 * Records security anomalies and triggers alerts.
 */
internal.post('/security/anomalies', async (req, res) => {
    const { transactionId, severity, description } = req.body;
    try {
        const sb = getAdminSupabase() || getSupabase();
        const { data: tx } = await sb!.from('transactions').select('*').eq('id', transactionId).single();
        
        await Audit.log('FRAUD', tx?.user_id || 'SYSTEM', 'WORKER_ANOMALY_REPORTED', {
            transactionId, severity, description
        });

        if (sb) {
            await sb.from('provider_anomalies').insert({
                transaction_id: transactionId,
                risk_score: severity === 'high' ? 90 : 50,
                detection_flags: ['WORKER_REPORTED'],
                status: 'OPEN',
                metadata: { description }
            });
        }
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * 7. GET PENDING TASKS
 * Retrieves system tasks awaiting execution.
 */
internal.get('/tasks/pending', async (req, res) => {
    const sb = getAdminSupabase() || getSupabase();
    try {
        const { data, error } = await sb!.from('tasks').select('*').eq('status', 'pending');
        if (error) throw error;
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * 8. UPDATE TASK STATUS
 * Updates the execution state of a system task.
 */
internal.put('/tasks/:id/status', async (req, res) => {
    const { id } = req.params;
    const { status, result } = req.body;
    try {
        const sb = getAdminSupabase() || getSupabase();
        const { error } = await sb!.from('tasks').update({ 
            status, 
            metadata: result ? { result } : undefined,
            updated_at: new Date().toISOString()
        }).eq('id', id);
        if (error) throw error;
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * 9. GET QUEUED MESSAGES
 * Fetches messages waiting to be dispatched.
 */
internal.get('/messages/queued', async (req, res) => {
    const sb = getAdminSupabase() || getSupabase();
    try {
        const { data, error } = await sb!.from('user_messages').select('*').eq('status', 'queued');
        if (error) throw error;
        res.json({ success: true, data });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * 10. UPDATE MESSAGE STATUS
 * Marks a message as sent or failed.
 */
internal.put('/messages/:id/status', async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    try {
        const sb = getAdminSupabase() || getSupabase();
        const { error } = await sb!.from('user_messages').update({ 
            status, 
            sent_at: status === 'sent' ? new Date().toISOString() : undefined 
        }).eq('id', id);
        if (error) throw error;
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * 11. TEST EMAIL CONFIGURATION (DISABLED)
 */
internal.post('/email/test', async (req, res) => {
    res.status(403).json({ success: false, error: 'EMAIL_SERVICE_DISABLED' });
});

/**
 * 12. VERIFY EMAIL CONNECTION (DISABLED)
 */
internal.get('/email/verify', async (req, res) => {
    res.status(403).json({ success: false, error: 'EMAIL_SERVICE_DISABLED' });
});

app.use('/api/internal', internal);

// 11. ADMIN PARTNER REGISTRY ROUTES
const admin = express.Router();
admin.use(authenticate as any); // Require authentication

// Middleware to check for Admin role
const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
    const session = (req as any).session;
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN' && role !== 'IT') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    next();
};

admin.use(requireAdmin);

admin.get('/partners', async (req, res) => {
    try {
        const { data, error } = await PartnerRegistry.listPartners();
        if (error) return res.status(500).json({ success: false, error: error.message });
        res.json({ success: true, data });
    } catch (e: any) {
        console.error(`[Admin] List Partners Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

admin.post('/partners', async (req, res) => {
    try {
        const { data, error } = await PartnerRegistry.addPartner(req.body);
        if (error) return res.status(500).json({ success: false, error: error.message });
        res.json({ success: true, data });
    } catch (e: any) {
        console.error(`[Admin] Add Partner Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

admin.put('/partners/:id', async (req, res) => {
    try {
        const { data, error } = await PartnerRegistry.updatePartner(req.params.id, req.body);
        if (error) return res.status(500).json({ success: false, error: error.message });
        res.json({ success: true, data });
    } catch (e: any) {
        console.error(`[Admin] Update Partner Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

admin.delete('/partners/:id', async (req, res) => {
    try {
        const { error } = await PartnerRegistry.deletePartner(req.params.id);
        if (error) return res.status(500).json({ success: false, error: error.message });
        res.json({ success: true });
    } catch (e: any) {
        console.error(`[Admin] Delete Partner Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

admin.get('/fees', async (req, res) => {
    try {
        const feeType = req.query.feeType as string;
        const service = new TransactionService();
        const data = await service.getFeeTransactions(feeType);
        res.json({ success: true, data });
    } catch (e: any) {
        console.error(`[Admin] Get Fees Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

admin.get('/balances', async (req, res) => {
    try {
        const service = new TransactionService();
        const data = await service.getAggregatedWalletBalances(['Orbi', 'PaySafe']);
        res.json({ success: true, data });
    } catch (e: any) {
        console.error(`[Admin] Get Balances Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

admin.get('/metrics/daily-movements', async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        if (!startDate || !endDate) {
            return res.status(400).json({ success: false, error: 'MISSING_DATE_RANGE' });
        }
        const service = new TransactionService();
        const data = await service.getDailyNetMovements(startDate as string, endDate as string);
        res.json({ success: true, data });
    } catch (e: any) {
        console.error(`[Admin] Get Daily Movements Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

app.use('/api/admin', admin);

const v1 = express.Router();

// --- Biometric Authentication (New Architecture) ---
v1.post('/auth/passkey/register/start', authenticate as any, (req, res) => NewAuth.startPasskeyRegistration(req, res));
v1.post('/auth/passkey/register/finish', authenticate as any, (req, res) => NewAuth.completePasskeyRegistration(req, res));
v1.post('/auth/passkey/login/start', (req, res) => NewAuth.startPasskeyLogin(req, res));
v1.post('/auth/passkey/login/finish', (req, res) => NewAuth.completePasskeyLogin(req, res));

// --- Legacy/Mobile App Aliases for Biometric Auth ---
v1.post('/auth/biometric/register/start', authenticate as any, (req, res) => NewAuth.startPasskeyRegistration(req, res));
v1.post('/auth/biometric/register/finish', authenticate as any, (req, res) => NewAuth.completePasskeyRegistration(req, res));
v1.post('/auth/biometric/login/start', (req, res) => NewAuth.startPasskeyLogin(req, res));
v1.post('/auth/biometric/login/finish', (req, res) => NewAuth.completePasskeyLogin(req, res));

v1.post('/auth/behavior/record', authenticate as any, (req, res) => NewAuth.recordBehavior(req, res));

v1.post('/auth/biometric/cleanup', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const sb = getAdminSupabase();
    if (!sb) return res.status(500).json({ error: "DB_OFFLINE" });
    
    const { data: user } = await sb.auth.admin.getUserById(session.sub);
    const metadata = user?.user?.user_metadata || {};
    delete metadata.authenticators;
    delete metadata.currentChallenge;
    
    await sb.auth.admin.updateUserById(session.sub, { user_metadata: metadata });
    res.json({ success: true, message: "Legacy biometric registrations cleaned." });
});

// --- IAM Domain ---
v1.get('/user/lookup/:customerId', authenticate as any, async (req, res) => {
    try {
        const profile = await LogicCore.lookupUser(req.params.customerId);
        if (!profile) {
            return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
        }
        res.json({ success: true, data: profile });
    } catch (e: any) {
        console.error(`[User Lookup] Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

v1.get('/user/lookup', authenticate as any, async (req, res) => {
    try {
        const query = req.query.q as string;
        if (!query || query.length < 3) {
            return res.status(400).json({ success: false, error: 'QUERY_TOO_SHORT' });
        }

        const profile = await LogicCore.lookupUser(query);
        if (!profile) {
            return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
        }

        res.json({ success: true, data: profile });
    } catch (e: any) {
        console.error(`[User Lookup] Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

v1.post('/auth/verify', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const { requestId, code } = req.body;
    try {
        const result = await LogicCore.verifySensitiveAction(requestId, code, session.sub);
        res.json(result);
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/auth/login', validate(LoginSchema), async (req, res) => {
    console.log(`[Auth] Login attempt for: ${req.body.email || req.body.e}`);
    try {
        const email = req.body.email || req.body.e;
        const password = req.body.password || req.body.p;
        
        // Extract Device Fingerprint from headers
        const fingerprint = req.headers['x-orbi-fingerprint'] as string;
        const ip = req.ip;
        const userAgent = req.headers['user-agent'];

        const result = await LogicCore.login(email, password, { fingerprint, ip, userAgent });
        
        if (result.error) {
            console.warn(`[Auth] Login failed for ${email}: ${result.error.message}`);
            return res.status(401).json({ success: false, error: result.error.message || 'Authentication failed' });
        }

        if (result.two_factor_required) {
            return res.json({ success: true, data: result });
        }

        res.json({ success: true, data: result });
    } catch (e: any) {
        console.error(`[Auth] Login exception for ${req.body.email}:`, e);
        res.status(500).json({ success: false, error: 'LOGIN_ERROR', message: e.message });
    }
});

v1.post('/auth/otp/initiate', async (req, res) => {
    let { userId, contact, action, type } = req.body;
    if (!userId || !action) return res.status(400).json({ success: false, error: 'MISSING_FIELDS' });
    
    try {
        if (!contact) {
            const sb = getAdminSupabase();
            if (sb) {
                const { data } = await sb.auth.admin.getUserById(userId);
                if (data?.user?.email) {
                    contact = data.user.email;
                } else if (data?.user?.phone) {
                    contact = data.user.phone;
                }
            }
        }

        if (!contact) {
            return res.status(400).json({ success: false, error: 'NO_CONTACT_AVAILABLE' });
        }

        const deviceName = getDeviceNameFromUA(req.get('user-agent'));
        const result = await LogicCore.initiateSensitiveAction(userId, contact, action, type, deviceName);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/auth/password/reset/initiate', async (req, res) => {
    try {
        const { identifier } = req.body;
        if (!identifier) return res.status(400).json({ success: false, error: 'MISSING_IDENTIFIER' });
        
        const result = await LogicCore.initiatePasswordReset(identifier);
        if (result.error) return res.status(400).json({ success: false, error: result.error.message });
        
        res.json({ success: true, message: 'Password reset email sent.' });
    } catch (e: any) {
        console.error(`[Auth] Password Reset Initiate Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

v1.post('/auth/password/reset/complete', authenticate as any, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ success: false, error: 'MISSING_PASSWORD' });
        
        const result = await LogicCore.completePasswordReset(password);
        if (result.error) return res.status(400).json({ success: false, error: result.error.message });
        
        res.json({ success: true, message: 'Password updated successfully.' });
    } catch (e: any) {
        console.error(`[Auth] Password Reset Complete Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

v1.post('/auth/refresh', async (req, res) => {
    try {
        const { refresh_token } = req.body;
        if (!refresh_token) return res.status(400).json({ success: false, error: 'MISSING_REFRESH_TOKEN' });

        const fingerprint = req.headers['x-orbi-fingerprint'] as string;
        const ip = req.ip;

        const result = await LogicCore.refreshSession(refresh_token, { fingerprint, ip });
        
        if (result.error) {
            return res.status(401).json({ success: false, error: result.error.message });
        }

        res.json({ success: true, data: result });
    } catch (e: any) {
        console.error(`[Auth] Refresh Session Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

v1.post('/auth/signup', validate(SignUpSchema), async (req, res) => {
    try {
        const appId = String(req.headers['x-orbi-app-id'] || 'anonymous');
        const email = req.body.email || req.body.e;
        const password = req.body.password || req.body.p;
        const { metadata, ...profileFields } = req.body;
        
        // Remove shorthand keys from profileFields to avoid saving them in metadata
        delete (profileFields as any).e;
        delete (profileFields as any).p;
        delete (profileFields as any).email;
        delete (profileFields as any).password;

        // Merge profileFields into metadata so they are available for user profile creation
        const fullMetadata = { ...metadata, ...profileFields };
        const result = await LogicCore.signUp(email, password, fullMetadata, appId);

        if (result.error) {
            return res.status(400).json({ success: false, error: result.error.message || 'Registration failed' });
        }

        res.json({ success: true, data: result.data });
    } catch (e: any) {
        console.error(`[Auth] Signup Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

v1.get('/auth/session', authenticate as any, async (req, res) => {
    try {
        res.json({ success: true, data: (req as any).session });
    } catch (e: any) {
        console.error(`[Auth] Session Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

v1.get('/user/profile', authenticate as any, async (req, res) => {
    try {
        const session = (req as any).session;
        const result = await LogicCore.getUserProfile(session.sub);
        if (result.error) {
            // If DB fetch fails, fallback to session metadata
            return res.json({ success: true, data: session.user.user_metadata });
        }
        res.json({ success: true, data: result.data });
    } catch (e: any) {
        console.error(`[User] Profile Get Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

v1.patch('/user/profile', authenticate as any, async (req, res) => {
    try {
        const session = (req as any).session;
        const result = await LogicCore.updateUserProfile(session.sub, req.body, session.user.user_metadata);
        if (result.error) return res.status(403).json({ success: false, error: result.error });
        res.json({ success: true, data: result });
    } catch (e: any) {
        console.error(`[User] Profile Update Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

v1.patch('/user/login-info', authenticate as any, async (req, res) => {
    try {
        const session = (req as any).session;
        const { email, password } = req.body;
        
        if (!email && !password) {
            return res.status(400).json({ success: false, error: 'MISSING_FIELDS: Provide email or password.' });
        }
        
        const result = await LogicCore.updateLoginInfo(session.sub, email, password);
        if (result.error) return res.status(400).json({ success: false, error: result.error });
        
        res.json({ success: true, message: 'Login information updated successfully.' });
    } catch (e: any) {
        console.error(`[User] Login Info Update Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});



v1.post('/user/avatar', authenticate as any, upload.single('file'), express.raw({ type: ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/heic', 'image/heif', 'application/octet-stream'], limit: '20mb' }), async (req, res) => {
    const session = (req as any).session;
    let file: Buffer | undefined;
    let contentType = req.headers['content-type'] || 'image/png';

    if (req.file) {
        file = req.file.buffer;
        contentType = req.file.mimetype;
    } else if (req.body instanceof Buffer) {
        file = req.body;
    } else if (typeof req.body === 'object' && (req.body.image || req.body.file)) {
        const rawData = req.body.image || req.body.file;
        if (typeof rawData === 'string' && rawData.includes('base64,')) {
            const base64Data = rawData.split('base64,')[1];
            file = Buffer.from(base64Data, 'base64');
        }
    }
    
    if (!file || !(file instanceof Buffer)) {
        return res.status(400).json({ success: false, error: 'INVALID_FILE_FORMAT', message: 'Please upload a valid image file (PNG, JPEG, WEBP, HEIC) as raw binary, multipart/form-data, or base64.' });
    }

    try {
        const oldUrl = session.user.user_metadata?.avatar_url;
        const newUrl = await LogicCore.uploadAvatar(session.sub, file, contentType, oldUrl);
        
        if (!newUrl) {
            return res.status(500).json({ success: false, error: 'UPLOAD_FAILED' });
        }

        // Update user profile with new avatar URL
        const updateResult = await LogicCore.updateUserProfile(session.sub, { avatar_url: newUrl }, session.user.user_metadata);
        
        if (updateResult.error) {
             return res.status(500).json({ success: false, error: updateResult.error });
        }

        res.json({ success: true, data: { avatar_url: newUrl } });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/user/kyc', authenticate as any, validate(KYCSubmitSchema), async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.submitKYC(session.sub, req.body);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/user/kyc/status', authenticate as any, async (req, res) => {
    try {
        const session = (req as any).session;
        const result = await LogicCore.getKYCStatus(session.sub);
        res.json({ success: true, data: result });
    } catch (e: any) {
        console.error(`[User] KYC Status Error:`, e);
        res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
});

v1.post('/user/kyc/scan', authenticate as any, upload.single('file'), express.raw({ type: ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/heic', 'image/heif', 'application/octet-stream'], limit: '20mb' }), async (req, res) => {
    let file: Buffer | undefined;
    let contentType = req.headers['content-type'] || 'image/png';

    if (req.file) {
        file = req.file.buffer;
        contentType = req.file.mimetype;
    } else if (req.body instanceof Buffer) {
        file = req.body;
    } else if (typeof req.body === 'object' && (req.body.image || req.body.file)) {
        const rawData = req.body.image || req.body.file;
        if (typeof rawData === 'string' && rawData.includes('base64,')) {
            const base64Data = rawData.split('base64,')[1];
            file = Buffer.from(base64Data, 'base64');
        }
    }
    
    if (!file || !(file instanceof Buffer)) {
        return res.status(400).json({ success: false, error: 'INVALID_FILE_FORMAT', message: 'Please upload a valid document image as raw binary, multipart/form-data, or base64.' });
    }

    try {
        const result = await LogicCore.scanKYC(file, contentType);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/user/kyc/upload', authenticate as any, upload.single('file'), express.raw({ type: ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/heic', 'image/heif', 'application/pdf', 'application/octet-stream'], limit: '20mb' }), async (req, res) => {
    const session = (req as any).session;
    let file: Buffer | undefined;
    let contentType = req.headers['content-type'] || 'image/png';
    const fileName = req.headers['x-file-name'] as string || 'kyc_document';

    if (req.file) {
        file = req.file.buffer;
        contentType = req.file.mimetype;
    } else if (req.body instanceof Buffer) {
        file = req.body;
    } else if (typeof req.body === 'object' && (req.body.image || req.body.file)) {
        const rawData = req.body.image || req.body.file;
        if (typeof rawData === 'string' && rawData.includes('base64,')) {
            const base64Data = rawData.split('base64,')[1];
            file = Buffer.from(base64Data, 'base64');
        }
    }
    
    if (!file || !(file instanceof Buffer)) {
        return res.status(400).json({ success: false, error: 'INVALID_FILE_FORMAT', message: 'Please upload a valid document as raw binary, multipart/form-data, or base64.' });
    }

    try {
        const url = await LogicCore.uploadKYCDocument(session.sub, file, fileName, contentType);
        res.json({ success: true, data: { url } });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/admin/kyc/requests', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN' && role !== 'HUMAN_RESOURCE') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    const status = req.query.status as string;
    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);

    try {
        const result = await LogicCore.getKYCRequests(status, limit, offset);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/admin/kyc/review', authenticate as any, validate(KYCReviewSchema), async (req, res) => {
    const session = (req as any).session;
    // Check role in session.user.role or session.role depending on mapping
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN' && role !== 'HUMAN_RESOURCE') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    
    try {
        const { requestId, decision, reason } = req.body;
        const result = await LogicCore.reviewKYC(requestId, session.sub, decision, reason);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- Devices Domain ---
v1.post('/user/devices', authenticate as any, validate(DeviceRegisterSchema), async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.registerDevice(session.sub, req.body);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/user/devices', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getUserDevices(session.sub);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.delete('/user/devices/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        await LogicCore.removeDevice(session.sub, req.params.id);
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/admin/devices', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN' && role !== 'IT' && role !== 'FRAUD') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);

    try {
        const result = await LogicCore.getAllDevices(limit, offset);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/admin/devices/:id/status', authenticate as any, validate(DeviceTrustSchema), async (req, res) => {
    const session = (req as any).session;
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN' && role !== 'IT') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
        const result = await LogicCore.updateDeviceStatus(req.params.id as string, req.body);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- Documents Domain ---
v1.post('/user/documents', authenticate as any, validate(DocumentUploadSchema), async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.uploadDocument(session.sub, req.body);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/user/documents', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getUserDocuments(session.sub);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.delete('/user/documents/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        await LogicCore.removeDocument(session.sub, req.params.id);
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/admin/documents', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN' && role !== 'CUSTOMER_CARE' && role !== 'AUDIT') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);

    try {
        const result = await LogicCore.getAllDocuments(limit, offset);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/admin/transactions', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN' && role !== 'AUDIT' && role !== 'CUSTOMER_CARE') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    const limit = Number(req.query.limit || 100);
    const offset = Number(req.query.offset || 0);

    try {
        const result = await LogicCore.getAllTransactions(limit, offset);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/admin/transactions/:id/ledger', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN' && role !== 'AUDIT' && role !== 'CUSTOMER_CARE') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
        const result = await LogicCore.getLedgerEntries(req.params.id);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/admin/documents/:id/verify', authenticate as any, validate(DocumentVerifySchema), async (req, res) => {
    const session = (req as any).session;
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN' && role !== 'CUSTOMER_CARE') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
        const result = await LogicCore.verifyDocument(req.params.id as string, session.sub, req.body);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/admin/staff', authenticate as any, validate(StaffCreateSchema), async (req, res) => {
    const session = (req as any).session;
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
        const result = await LogicCore.createStaff(req.body, session.sub);
        if (result.error) return res.status(400).json({ success: false, error: result.error });
        res.json({ success: true, data: result.data });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/admin/users/:id/status', authenticate as any, validate(AccountStatusUpdateSchema), async (req, res) => {
    const session = (req as any).session;
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN' && role !== 'HUMAN_RESOURCE') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
        await LogicCore.updateAccountStatus(req.params.id as string, req.body.status, session.sub);
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/admin/users/:id/profile', authenticate as any, validate(UserProfileUpdateSchema), async (req, res) => {
    const session = (req as any).session;
    const role = session.role || session.user?.role;
    if (role !== 'ADMIN' && role !== 'SUPER_ADMIN' && role !== 'HUMAN_RESOURCE') {
        return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
        const result = await LogicCore.adminUpdateUserProfile(req.params.id as string, req.body, session.sub);
        if (result.error) return res.status(400).json({ success: false, error: result.error });
        res.json({ success: true });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- Messaging Domain ---
v1.post('/messaging/email', authenticate as any, async (req, res) => {
    res.status(403).json({ success: false, error: 'EMAIL_SERVICE_DISABLED' });
});

// --- Wealth Domain ---
v1.post('/webhooks/:partnerId', async (req, res) => {
    const { partnerId } = req.params;
    try {
        // Webhooks are public endpoints but secured by provider signatures (handled inside handleCallback if needed)
        // or by secret tokens in URL/headers.
        // For now, we allow the call and let the handler validate.
        await Webhooks.handleCallback(req.body, partnerId);
        res.json({ success: true });
    } catch (e: any) {
        console.error(`[Webhook] Error processing webhook for ${partnerId}:`, e);
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/merchants/categories', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.getMerchantCategories();
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/merchants', authenticate as any, async (req, res) => {
    const category = req.query.category;
    try {
        const result = await LogicCore.getMerchants(category);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- MULTI-TENANT MERCHANT ACCOUNTS ---
v1.post('/merchants/accounts', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.createMerchantAccount(session.sub, req.body);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/merchants/accounts/my', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getUserMerchantAccounts(session.sub);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/merchants/accounts/:id', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.getMerchantAccountById(req.params.id);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/merchants/accounts/:id/settlement', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.updateMerchantSettlement(req.params.id, req.body);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
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
            .select('name, target_amount, current_amount')
            .eq('user_id', userId);

        const context = { transactions, goals };

        // 2. Generate insights using Gemini
        const systemInstruction = `
            You are the Orbi Financial Advisor. 
            Analyze the provided transaction history and savings goals to provide personalized financial advice.
            
            Return the response in the following JSON format:
            {
                "spendingAlerts": ["string"],
                "budgetSuggestions": ["string"],
                "financialAdvice": ["string"]
            }
            
            GUIDELINES:
            - Base all advice ONLY on the provided user activity (transactions and goals).
            - Focus on spending habits, savings progress, and helpful tips.
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
    try {
        const result = await LogicCore.postGoal({ ...req.body, user_id: session.sub });
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/goals', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getGoals(session.sub);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.delete('/goals/:id', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.deleteGoal(req.params.id);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/categories', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.getCategories(session.sub);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/categories', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
        const result = await LogicCore.postCategory({ ...req.body, user_id: session.sub });
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.patch('/categories/:id', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.updateCategory({ ...req.body, id: req.params.id });
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.delete('/categories/:id', authenticate as any, async (req, res) => {
    try {
        const result = await LogicCore.deleteCategory(req.params.id);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
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
    const { amount, sourceWalletId } = req.body;
    if (!amount || !sourceWalletId) return res.status(400).json({ success: false, error: 'MISSING_PARAMS' });

    try {
        const result = await LogicCore.allocateToGoal(req.params.id, amount, sourceWalletId);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

import { SandboxController } from './backend/sandbox/sandboxController.js';

// ... existing imports ...

// ... inside v1 routes ...

// --- SANDBOX / DEMO TOOLS ---
v1.post('/sandbox/fund', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    
    // Default to current user if not provided
    if (!req.body.userId) req.body.userId = session.sub;

    // Security Check: Only admins can fund other users
    if (req.body.userId !== session.sub) {
        const role = session.role || session.user?.role;
        if (role !== 'ADMIN' && role !== 'SUPER_ADMIN') {
            return res.status(403).json({ success: false, error: 'ACCESS_DENIED: You can only fund your own wallet.' });
        }
    }

    await SandboxController.fundWallet(req, res);
});

v1.post('/sandbox/activate', authenticate as any, async (req, res) => {
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
v1.post('/admin/reconciliation/run', authenticate as any, adminOnly as any, async (req, res) => {
    try {
        await LogicCore.runFullReconciliation();
        res.json({ success: true, message: 'Full reconciliation cycle triggered.' });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.get('/admin/reconciliation/reports', authenticate as any, adminOnly as any, async (req, res) => {
    const limit = Number(req.query.limit || 50);
    try {
        const result = await LogicCore.getReconciliationReports(limit);
        res.json({ success: true, data: result });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- ADMIN CONFIGURATION APIs ---
v1.get('/admin/config/ledger', authenticate as any, adminOnly as any, async (req, res) => {
    try {
        const config = await ConfigClient.getRuleConfig(true);
        res.json({ success: true, data: config.transaction_limits });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/admin/config/ledger', authenticate as any, adminOnly as any, async (req, res) => {
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

v1.get('/admin/config/fx-rates', authenticate as any, adminOnly as any, async (req, res) => {
    try {
        const config = await ConfigClient.getRuleConfig(true);
        res.json({ success: true, data: config.exchange_rates });
    } catch (e: any) {
        res.status(500).json({ success: false, error: e.message });
    }
});

v1.post('/admin/config/fx-rates', authenticate as any, adminOnly as any, async (req, res) => {
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

app.use('/v1', globalIpLimiter as any, v1);
// Alias for clients expecting /api/v1
app.use('/api/v1', globalIpLimiter as any, v1);
// Alias for clients omitting version prefix (Fallback)
app.use('/', globalIpLimiter as any, v1);

// 5. LEGACY GATEWAY (Backward Compatibility)
app.post('/api', globalIpLimiter as any, async (req: any, res: any) => {
    const operation = String(req.query.operation || '');
    const payload = req.body || {};
    const token = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null;
    const appId = String(req.headers['x-orbi-app-id'] || 'anonymous');
    const idempotencyKey = req.headers['x-idempotency-key'];

    try {
        await WAF.inspect(payload, operation);
        const session = await LogicCore.getSession(token || undefined).catch(() => null);
        
        // Neural Risk Scoring
        const threat = await Sentinel.inspectOperation(session as any, operation, { ...payload, appId });
        if (threat.recommendation === 'BLOCK') {
            return res.status(403).json({ success: false, error: 'SENTINEL_BLOCK', risk: threat.riskScore });
        }

        const domain = operation.split('_')[0];

        // Require session for non-IAM operations
        if (!domain.startsWith('iam') && !session?.sub) {
            return res.status(401).json({ success: false, error: 'UNAUTHORIZED_SESSION_REQUIRED' });
        }

        let result;
        
        switch (domain) {
            case 'iam': 
                if (operation === 'iam_login') result = await LogicCore.login(payload.e, payload.p);
                else if (operation === 'iam_signup') result = await LogicCore.signUp(payload.email, payload.password, payload.metadata, appId);
                else if (operation === 'iam_session') result = await LogicCore.getSession(token || undefined);
                break;
            case 'wealth': 
                if (operation === 'wealth_settlement') {
                    // Policy Engine Guard
                    const policy = await PolicyEngine.evaluateTransaction(session!.sub, payload.amount || 0, payload.currency || 'TZS', 'legacy_settlement');
                    if (!policy.allowed) {
                        return res.status(403).json({ success: false, error: 'POLICY_VIOLATION', message: policy.reason });
                    }
                    result = await LogicCore.processSecurePayment(payload);
                    if (result.success) await PolicyEngine.commitMetrics(session!.sub, payload.amount || 0, payload.currency || 'TZS');
                }
                else if (operation === 'wealth_wallet_list') result = await LogicCore.getWallets(payload.userId || session!.sub);
                break;
            case 'escrow':
                if (operation === 'escrow_create') result = await LogicCore.createEscrow(session!.sub, payload.recipientId, payload.amount, payload.description, payload.conditions);
                else if (operation === 'escrow_release') result = await LogicCore.releaseEscrow(payload.referenceId, session!.sub);
                else if (operation === 'escrow_dispute') result = await LogicCore.disputeEscrow(payload.referenceId, session!.sub, payload.reason);
                break;
            case 'treasury':
                if (operation === 'treasury_withdraw') result = await LogicCore.requestTreasuryWithdrawal(payload.orgId, payload.amount, payload.currency, payload.destination, session!.sub);
                else if (operation === 'treasury_approve') result = await LogicCore.approveTreasuryWithdrawal(payload.withdrawalId, session!.sub);
                break;
            case 'strategy':
                if (operation === 'strategy_goal_list') result = await LogicCore.getGoals(session!.sub);
                else if (operation === 'strategy_task_list') result = await LogicCore.getTasks(session!.sub);
                break;
            case 'enterprise':
                if (operation === 'enterprise_org_create') result = await LogicCore.createOrganization(payload, session!.sub);
                break;
            default:
                return res.status(404).json({ success: false, error: 'UNKNOWN_OP' });
        }

        res.json({ success: true, data: result, ts: Date.now() });
    } catch (err: any) {
        res.status(500).json({ success: false, error: 'EXECUTION_FAULT', message: err.message });
    }
});

// 6. GLOBAL ERROR HANDLERS
// Catch 404 and forward to error handler
app.use((req, res, next) => {
    res.status(404).json({ success: false, error: 'NOT_FOUND', path: req.path });
});

// Global Error Handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error('[System] Unhandled Error:', err);
    res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: err.message || 'Unknown error' });
});

import { SocketRegistry } from './backend/infrastructure/SocketRegistry.js';

// 7. REAL-TIME NEXUS (WSS)
const wss = new WebSocketServer({ 
    server: httpServer, 
    path: '/nexus-stream',
    verifyClient: (info, cb) => {
        const origin = info.origin || info.req.headers.origin;
        // Allow mobile apps (no origin) or our specific allowed origins
        if (!origin || ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes(origin.replace('http://', 'https://'))) {
            cb(true);
        } else {
            console.warn(`[Nexus] Rejected connection from unauthorized origin: ${origin}`);
            cb(false, 403, 'Forbidden');
        }
    }
});

wss.on('connection', (ws: WebSocket, req) => {
    (ws as any).isAlive = true;
    ws.on('pong', () => { (ws as any).isAlive = true; });

    console.info(`[Nexus] New Node connection from ${req.socket.remoteAddress}`);
    ws.on('message', async (msg) => {
        try {
            const data = JSON.parse(msg.toString());
            if (data.event === 'PING') ws.send(JSON.stringify({ event: 'PONG', ts: Date.now() }));
            
            // AUTH HANDLER: Register user to socket
            if (data.event === 'AUTH') {
                let userId = data.userId;

                // Secure Token Auth (Preferred)
                if (data.token) {
                    try {
                        const authService = new AuthService();
                        const session = await authService.getSession(data.token);
                        if (session) {
                            userId = session.user.id;
                        }
                    } catch (e) {
                        console.error('[Nexus] Auth Token Verification Failed', e);
                    }
                }

                if (userId) {
                    (ws as any).userId = userId;
                    SocketRegistry.register(userId, ws);
                    ws.send(JSON.stringify({ event: 'AUTH_SUCCESS', ts: Date.now() }));
                }
            }
        } catch (e) {}
    });
    
    ws.on('close', () => {
        if ((ws as any).userId) {
            SocketRegistry.remove((ws as any).userId);
        }
    });
});

// Clean up dead WebSocket connections to prevent memory leaks at scale
const wsPingInterval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if ((ws as any).isAlive === false) return ws.terminate();
        (ws as any).isAlive = false;
        ws.ping();
    });
}, 30000);

wss.on('close', () => {
    clearInterval(wsPingInterval);
});

await LogicCore.warmup();
NotificationSubscriber.init();

try {
    console.log("[System] Initializing Fintech Security Core...");
    await RecoveryService.recover();
    console.log("[System] WAL Recovery Complete.");
} catch (e) {
    console.error("[System] WAL Recovery Failed:", e);
}

httpServer.listen(PORT, '0.0.0.0', () => {
    console.info(`ORBI SOVEREIGN NODE v28.0 - RESTFUL API ACTIVE ON PORT ${PORT}`);
});

// 8. BACKGROUND REAPER & SETTLEMENT ENGINE (V1.0)
const backgroundInterval = setInterval(async () => {
    try {
        await LegacyRecon.reapStuckTransactions();
        await EntProcessor.settleProcessingTransactions();
    } catch (e) {
        console.error('[System] Background Cycle Error:', e);
    }
}, 60000); // Run every minute

// 7. GRACEFUL SHUTDOWN (Scale Ready)

const gracefulShutdown = async () => {
    console.info('\n[System] SIGTERM/SIGINT received. Initiating graceful shutdown...');
    
    clearInterval(wsPingInterval);
    clearInterval(backgroundInterval);
    wss.close(() => {
        console.info('[Nexus] WebSocket server closed.');
    });

    try {
        await RedisClusterFactory.shutdownAll();
        console.info('[System] Redis connections closed.');
    } catch (e) {
        console.error('[System] Error closing Redis connections:', e);
    }

    httpServer.close(() => {
        console.info('[System] HTTP server closed. All connections drained.');
        process.exit(0);
    });

    // Force shutdown if connections don't drain within 10 seconds
    setTimeout(() => {
        console.error('[System] Force shutdown after 10s timeout.');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
