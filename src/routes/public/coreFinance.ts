import { type RequestHandler, type Router } from 'express';

type Deps = {
  authenticate: RequestHandler;
  authenticateApiKey: RequestHandler;
  validate: (schema: any) => RequestHandler;
  requireRole: (session: any, roles: string[]) => boolean;
  LogicCore: any;
  getSupabase: () => any;
  PolicyEngine: any;
  FXEngine: any;
  TransactionService: any;
  WalletCreateSchema: any;
  WalletLockSchema: any;
  WalletUnlockSchema: any;
  PaymentIntentSchema: any;
  TransactionIssueSchema: any;
};

export const registerCoreFinanceRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    authenticateApiKey,
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
  } = deps;

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

  v1.get('/external/wallets', authenticateApiKey as any, async (req, res) => {
    const tenantId = (req as any).tenantId;
    try {
      const sb = getSupabase();
      if (!sb) throw new Error('Database not connected');

      const { data, error } = await sb.from('wallets').select('*').eq('tenant_id', tenantId);

      if (error) throw new Error(error.message);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

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

  v1.get('/wallets/linked', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const allWallets = await LogicCore.getWallets(session.sub);
      const linked = allWallets.filter((w: any) => w.management_tier === 'linked');
      res.json({ success: true, data: linked });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/wallets/sovereign', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const allWallets = await LogicCore.getWallets(session.sub);
      const sovereign = allWallets.filter((w: any) => w.management_tier === 'sovereign');
      res.json({ success: true, data: sovereign });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/user/dashboard', authenticate as any, async (req, res) => {
    const token = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.getBootstrapData(token);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/dashboard', authenticate as any, async (req, res) => {
    const token = (req as any).authToken as string | null;
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
        isAdmin,
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
        isAdmin,
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

    const kycStatus = session.user.user_metadata?.kyc_status || 'unverified';
    const amount = req.body.amount || 0;
    const currency = req.body.currency || 'TZS';

    const policyResult = await PolicyEngine.evaluateTransaction(session.sub, amount, currency, 'settlement');
    if (!policyResult.allowed) {
      return res.status(403).json({
        success: false,
        error: 'POLICY_VIOLATION',
        message: policyResult.reason,
      });
    }

    if (kycStatus !== 'verified' && amount > 1000000) {
      return res.status(403).json({
        success: false,
        error: 'KYC_LIMIT_EXCEEDED',
        message: 'Unverified accounts are limited to 1,000,000 TZS per transaction. Please complete KYC.',
      });
    }

    try {
      req.body.idempotencyKey = idempotencyKey || `tx-${Date.now()}-${Math.random()}`;

      const result = await LogicCore.processSecurePayment(req.body, session.user);

      if (!result.success) {
        if (result.error === 'SECURITY_CHALLENGE') {
          return res.status(403).json(result);
        }

        const isTransient =
          result.error?.includes('LOCK_TIMEOUT') ||
          result.error?.includes('LEDGER_COMMIT_FAILED') ||
          result.error?.includes('LEDGER_FAULT') ||
          result.error?.includes('INFRASTRUCTURE_ERROR');

        const statusCode = isTransient ? 500 : 400;
        return res.status(statusCode).json(result);
      }

      await PolicyEngine.commitMetrics(session.sub, amount, currency);
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

  v1.get('/transactions/:id/receipt', authenticate as any, async (req, res) => {
    const { id } = req.params;
    const session = (req as any).session;

    try {
      const service = new TransactionService();
      const transactions = await service.getLatestTransactions(session.sub, 100, 0);
      const tx = transactions.find((t: any) => t.internalId === id || t.referenceId === id || t.id === id);

      if (!tx) {
        return res.status(404).json({ success: false, error: 'TRANSACTION_NOT_FOUND' });
      }

      res.json({
        success: true,
        data: {
          ...tx,
          generatedAt: new Date().toISOString(),
          issuer: 'ORBI FINANCIAL TECHNOLOGIES',
        },
      });
    } catch (e: any) {
      console.error(`[Receipt Data] Fetch failed for ${id}:`, e);
      res.status(500).json({ success: false, error: 'RECEIPT_DATA_FAULT', message: e.message });
    }
  });
};
