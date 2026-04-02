import type { Express, NextFunction, Request, Response, Router } from 'express';
import {
  createInternalWorkerMiddleware,
  extractBearerToken,
  getInternalAuditMetadata,
} from '../../middleware/auth/authorization.js';

let lastBrokerHeartbeat: any = null;

type MonitoringDeps = {
  authenticateApiKey: any;
  ReconEngine: { runFullAudit: () => Promise<any>; auditWalletTimeline: (walletId: string) => Promise<any> };
  OperationalHealthService: {
    captureSnapshot: () => Promise<any>;
    persistSnapshot: (snapshot?: any) => Promise<any>;
    renderPrometheus: (snapshot: any) => string;
  };
};

type TopLevelDeps = {
  ResilienceEngine: { getCircuitStates: () => any };
  LogicCore: { getAuditTrail: () => Promise<any[]> };
  OperationalHealthService: {
    captureSnapshot: () => Promise<any>;
    persistSnapshot: (snapshot?: any) => Promise<any>;
    renderPrometheus: (snapshot: any) => string;
  };
};

type LegacyGatewayDeps = {
  enabled: boolean;
  globalIpLimiter: any;
  WAF: { inspect: (payload: any, operation: string) => Promise<any> };
  Sentinel: { inspectOperation: (session: any, operation: string, payload: any) => Promise<any> };
  LogicCore: any;
  PolicyEngine: any;
};

export const registerMonitoringRoutes = (app: Express, deps: MonitoringDeps) => {
  const { authenticateApiKey, ReconEngine, OperationalHealthService } = deps;

  app.get('/api/admin/monitor/ledger-health', authenticateApiKey, async (_req, res) => {
    try {
      const auditResult = await ReconEngine.runFullAudit();
      res.json({
        success: true,
        timestamp: new Date().toISOString(),
        status: auditResult.discrepancies.length === 0 ? 'HEALTHY' : 'CRITICAL_DISCREPANCY',
        data: auditResult,
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
        ...result,
      });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  app.get('/api/admin/monitor/operational-health', authenticateApiKey, async (_req, res) => {
    try {
      const snapshot = await OperationalHealthService.captureSnapshot();
      res.json({ success: true, data: snapshot });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  app.get('/api/admin/monitor/operational-metrics', authenticateApiKey, async (_req, res) => {
    try {
      const snapshot = await OperationalHealthService.captureSnapshot();
      res.json({
        success: true,
        timestamp: snapshot.capturedAt,
        status: snapshot.status,
        connectivity: snapshot.connectivity,
        jobs: snapshot.jobs,
        metrics: snapshot.metrics,
      });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  app.get('/api/admin/monitor/operational-metrics/prometheus', authenticateApiKey, async (_req, res) => {
    try {
      const snapshot = await OperationalHealthService.captureSnapshot();
      res.type('text/plain').send(OperationalHealthService.renderPrometheus(snapshot));
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  app.post('/api/admin/monitor/operational-metrics/snapshot', authenticateApiKey, async (_req, res) => {
    try {
      const snapshot = await OperationalHealthService.persistSnapshot();
      res.json({ success: true, data: snapshot });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
};

export const registerTopLevelPublicRoutes = (app: Express, deps: TopLevelDeps) => {
  const { ResilienceEngine, LogicCore, OperationalHealthService } = deps;

  app.get('/.well-known/assetlinks.json', (_req, res, next) => {
    const base64Hash = process.env.ORBI_ANDROID_APP_HASH?.replace(/['"]/g, '');
    const packageName = process.env.ORBI_ANDROID_PACKAGE_NAME?.trim();
    if (!base64Hash || !packageName) {
      return next();
    }

    let hexHash = '';
    try {
      const buffer = Buffer.from(base64Hash, 'base64');
      const hexString = buffer.toString('hex').toUpperCase();
      hexHash = hexString.match(/.{1,2}/g)?.join(':') || '';
    } catch (e) {
      console.error('Failed to convert ORBI_ANDROID_APP_HASH to hex format', e);
      hexHash = base64Hash;
    }

    res.json([{
      relation: [
        'delegate_permission/common.handle_all_urls',
        'delegate_permission/common.get_login_creds',
      ],
      target: {
        namespace: 'android_app',
        package_name: packageName,
        sha256_cert_fingerprints: [hexHash],
      },
    }]);
  });

  app.get('/', (_req, res) => {
    res.json({
      status: 'ONLINE',
      service: 'ORBI SOVEREIGN NODE',
      version: '28.0.0',
      docs: '/v1/docs',
    });
  });

  app.get(['/health', '/heath'], async (_req, res) => {
    const breakerStates = ResilienceEngine.getCircuitStates();
    const ledgerIntegrity = await LogicCore.getAuditTrail().then((logs) => logs.length > 0).catch(() => false);
    const operational = await OperationalHealthService.captureSnapshot().catch(() => null);

    res.json({
      status: operational?.status || 'NOMINAL',
      node: process.env.RENDER_INSTANCE_ID || 'DPS-PRIMARY-RELAY',
      version: '28.0.0',
      uptime: (process as any).uptime(),
      circuits: breakerStates,
      ledger: ledgerIntegrity ? 'VERIFIED' : 'PENDING_SYNC',
      connectivity: operational?.connectivity,
      jobs: operational?.jobs,
      metrics: operational?.metrics,
      ts: Date.now(),
    });
  });

  app.post('/api/broker/heartbeat', createInternalWorkerMiddleware({ requiredScopes: ['broker:heartbeat'] }), (req, res) => {
    lastBrokerHeartbeat = {
      ...req.body,
      receivedAt: new Date().toISOString(),
      requestIdentity: getInternalAuditMetadata(req),
    };
    res.json({ success: true });
  });

  app.get('/api/broker/health', (_req, res) => {
    if (!lastBrokerHeartbeat) {
      return res.status(503).json({ status: 'OFFLINE', error: 'No heartbeat received from broker' });
    }

    const lastSeen = new Date(lastBrokerHeartbeat.receivedAt).getTime();
    const now = Date.now();
    const diff = (now - lastSeen) / 1000;

    if (diff > 120) {
      return res.status(503).json({
        status: 'STALE',
        lastSeen: lastBrokerHeartbeat.receivedAt,
        error: `Broker heartbeat is ${Math.round(diff)}s old`,
      });
    }

    res.json({
      status: 'HEALTHY',
      lastSeen: lastBrokerHeartbeat.receivedAt,
      broker: lastBrokerHeartbeat,
      latency: Math.round(diff * 1000) + 'ms',
    });
  });
};

export const mountPublicRoutes = (app: Express, v1: Router, globalIpLimiter: any) => {
  app.use('/v1', globalIpLimiter, v1);
  app.use('/api/v1', globalIpLimiter, v1);
  app.use('/', globalIpLimiter, v1);
};

export const registerLegacyGatewayRoute = (app: Express, deps: LegacyGatewayDeps) => {
  const { enabled, globalIpLimiter, WAF, Sentinel, LogicCore, PolicyEngine } = deps;
  if (!enabled) return;

  app.post('/api', globalIpLimiter, async (req: any, res: any) => {
    const operation = String(req.query.operation || '');
    const payload = req.body || {};
    const token = extractBearerToken(req);
    const appId = String(req.headers['x-orbi-app-id'] || 'anonymous');

    try {
      await WAF.inspect(payload, operation);
      const session = await LogicCore.getSession(token || undefined).catch(() => null);
      const threat = await Sentinel.inspectOperation(session as any, operation, { ...payload, appId });
      if (threat.recommendation === 'BLOCK') {
        return res.status(403).json({ success: false, error: 'SENTINEL_BLOCK', risk: threat.riskScore });
      }

      const domain = operation.split('_')[0];
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
            const policy = await PolicyEngine.evaluateTransaction(session!.sub, payload.amount || 0, payload.currency || 'TZS', 'legacy_settlement');
            if (!policy.allowed) {
              return res.status(403).json({ success: false, error: 'POLICY_VIOLATION', message: policy.reason });
            }
            result = await LogicCore.processSecurePayment(payload);
            if (result.success) await PolicyEngine.commitMetrics(session!.sub, payload.amount || 0, payload.currency || 'TZS');
          } else if (operation === 'wealth_wallet_list') result = await LogicCore.getWallets(payload.userId || session!.sub);
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
          if (operation === 'strategy_goal_list') result = await LogicCore.getGoals(session!.sub, token || undefined);
          else if (operation === 'strategy_task_list') result = await LogicCore.getTasks(session!.sub);
          break;
        case 'enterprise':
          if (operation === 'enterprise_org_create') result = await LogicCore.createOrganization(payload, session!.sub);
          break;
        default:
          return res.status(404).json({ success: false, error: 'UNKNOWN_OP' });
      }

      res.json({ success: true, data: result, ts: Date.now() });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message || 'OPERATION_FAILED' });
    }
  });
};

export const registerTerminalHandlers = (app: Express) => {
  app.use((req, res) => {
    res.status(404).json({
      success: false,
      error: 'ROUTE_NOT_FOUND',
      path: req.originalUrl,
    });
  });

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    res.status(err?.status || 500).json({
      success: false,
      error: err?.message || 'INTERNAL_SERVER_ERROR',
    });
  });
};
