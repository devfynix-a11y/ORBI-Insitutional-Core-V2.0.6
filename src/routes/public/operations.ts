import { type RequestHandler, type Router } from 'express';

type Deps = {
  authenticate: RequestHandler;
  adminOnly: RequestHandler;
  requireSessionPermission: (permissions: string[], roles?: string[]) => RequestHandler;
  LogicCore: any;
  ConfigClient: any;
  KMS: any;
  DataVault: any;
  TransactionSigning: any;
  SandboxController: any;
  sandboxRoutesEnabled: boolean;
};

export const registerOperationsRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    adminOnly,
    requireSessionPermission,
    LogicCore,
    ConfigClient,
    KMS,
    DataVault,
    TransactionSigning,
    SandboxController,
    sandboxRoutesEnabled,
  } = deps;

  if (sandboxRoutesEnabled) {
    v1.post('/sandbox/activate', authenticate as any, async (req, res) => {
      const session = (req as any).session;

      if (!req.body.userId) req.body.userId = session.sub;

      if (req.body.userId !== session.sub) {
        const role = session.role || session.user?.role;
        if (role !== 'ADMIN' && role !== 'SUPER_ADMIN') {
          return res.status(403).json({ success: false, error: 'ACCESS_DENIED: You can only activate your own account.' });
        }
      }

      await SandboxController.activateUser(req, res);
    });
  }

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

  v1.post('/admin/reconciliation/run', authenticate as any, requireSessionPermission(['reconciliation.run'], ['ADMIN', 'SUPER_ADMIN', 'AUDIT']), async (_req, res) => {
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

  v1.get('/admin/config/ledger', authenticate as any, requireSessionPermission(['config.ledger.read', 'config.ledger.write'], ['ADMIN', 'SUPER_ADMIN']), async (_req, res) => {
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
          ...newLimits,
        },
      };

      await ConfigClient.saveConfig(updatedConfig);
      res.json({ success: true, message: 'Ledger configuration updated successfully.' });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/config/commissions', authenticate as any, requireSessionPermission(['config.commissions.read', 'config.commissions.write'], ['ADMIN', 'SUPER_ADMIN', 'ACCOUNTANT']), async (_req, res) => {
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
          ...(req.body || {}),
        },
      };
      await ConfigClient.saveConfig(updatedConfig);
      res.json({ success: true, message: 'Commission configuration updated successfully.' });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/config/fx-rates', authenticate as any, requireSessionPermission(['config.fx.read', 'config.fx.write'], ['ADMIN', 'SUPER_ADMIN', 'ACCOUNTANT', 'IT']), async (_req, res) => {
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
          ...newRates,
        },
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
          message: 'Set confirm=REWRAP_KEYS to proceed.',
        });
      }

      const newMasterKey = String(req.body?.newMasterKey || '').trim();
      const resolvedMasterKey = newMasterKey || String(process.env.KMS_MASTER_KEY || '').trim();
      if (!resolvedMasterKey) {
        return res.status(400).json({
          success: false,
          error: 'KMS_MASTER_KEY_MISSING',
          message: 'No master key provided or configured.',
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
      const ok = decoded && typeof decoded === 'object' && (decoded as any).ping === 'pong';
      res.json({
        success: ok,
        data: {
          ok,
          ts: Date.now(),
        },
      });
    } catch (e: any) {
      res.status(500).json({
        success: false,
        error: e.message,
      });
    }
  });

  v1.post('/admin/kms/diagnose', authenticate as any, adminOnly as any, async (req, res) => {
    try {
      const masterKey = String(req.body?.masterKey || process.env.KMS_MASTER_KEY || '').trim();
      if (!masterKey) {
        return res.status(400).json({
          success: false,
          error: 'KMS_MASTER_KEY_MISSING',
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
          configuredSalt: configuredSalt ? 'SET' : 'EMPTY',
        },
      });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/sys/bootstrap', authenticate as any, async (req, res) => {
    const token = req.headers.authorization?.substring(7);
    try {
      const result = await LogicCore.getBootstrapData(token);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/sys/metrics', authenticate as any, async (_req, res) => {
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
        return res.status(403).json({ success: false, error: 'SECURE_ENCLAVE_SIGNATURE_INVALID' });
      }

      const result = await LogicCore.processSecurePayment(transactionPayload, (req as any).session.user);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
};
