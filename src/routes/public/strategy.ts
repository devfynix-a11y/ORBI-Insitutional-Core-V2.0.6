import { type RequestHandler, type Router } from 'express';

type Deps = {
  authenticate: RequestHandler;
  validate: (schema: any) => RequestHandler;
  LogicCore: any;
  OTPService: any;
  GoalCreateSchema: any;
  GoalUpdateSchema: any;
};

export const registerStrategyRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    validate,
    LogicCore,
    OTPService,
    GoalCreateSchema,
    GoalUpdateSchema,
  } = deps;

  v1.post('/goals', authenticate as any, validate(GoalCreateSchema), async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.postGoal({ ...req.body, user_id: session.sub }, authToken || undefined);
      res.json({ success: true, data: result?.data ?? result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/goals', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.getGoals(session.sub, authToken || undefined);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/goals/:id', authenticate as any, validate(GoalUpdateSchema), async (req, res) => {
    const authToken = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.updateGoal({ ...req.body, id: req.params.id }, authToken || undefined);
      res.json({ success: true, data: result?.data ?? result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.delete('/goals/:id', authenticate as any, async (req, res) => {
    const authToken = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.deleteGoal(req.params.id, authToken || undefined);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/categories', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.getCategories(session.sub, authToken || undefined);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/categories', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.postCategory({ ...req.body, user_id: session.sub }, authToken || undefined);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/categories/:id', authenticate as any, async (req, res) => {
    const authToken = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.updateCategory({ ...req.body, id: req.params.id }, authToken || undefined);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.delete('/categories/:id', authenticate as any, async (req, res) => {
    const authToken = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.deleteCategory(req.params.id, authToken || undefined);
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
    const authToken = (req as any).authToken as string | null;
    const { amount, sourceWalletId } = req.body;
    if (!amount) return res.status(400).json({ success: false, error: 'MISSING_PARAMS' });

    try {
      const result = await LogicCore.allocateToGoal(req.params.id, amount, sourceWalletId, authToken || undefined);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/goals/:id/withdraw', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    const { amount, destinationWalletId, verification } = req.body;
    if (!amount || !destinationWalletId) {
      return res.status(400).json({ success: false, error: 'MISSING_PARAMS' });
    }

    const otpRequestId = verification?.otpRequestId || verification?.requestId || req.body.otpRequestId;
    const otpCode = verification?.otpCode || req.body.otpCode;
    if (!otpRequestId || !otpCode) {
      return res.status(403).json({ success: false, error: 'SECURITY_VERIFICATION_REQUIRED' });
    }

    try {
      const verified = await OTPService.verify(String(otpRequestId), String(otpCode), session.sub);
      if (!verified) {
        return res.status(403).json({ success: false, error: 'SECURITY_VERIFICATION_FAILED' });
      }

      const result = await LogicCore.withdrawFromGoal(
        req.params.id,
        amount,
        destinationWalletId,
        {
          verifiedVia: verification?.verifiedVia || 'otp',
          pinVerified: verification?.pinVerified === true,
          deliveryType: verification?.deliveryType || null,
          otpRequestId: String(otpRequestId),
          otpVerifiedAt: new Date().toISOString(),
          verifiedByUserId: session.sub,
        },
        authToken || undefined,
      );
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/goals/auto-allocate/replay', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const authToken = (req as any).authToken as string | null;
    const sourceTransactionId = String(req.body?.sourceTransactionId || '').trim();
    if (!sourceTransactionId) {
      return res.status(400).json({ success: false, error: 'SOURCE_TRANSACTION_REQUIRED' });
    }

    try {
      const result = await LogicCore.replayGoalAutoAllocations(session.sub, sourceTransactionId, authToken || undefined);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });
};
