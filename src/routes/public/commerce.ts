import type { RequestHandler, Router } from 'express';

type Deps = {
  authenticate: RequestHandler;
  validate: (schema: any) => RequestHandler;
  requireRole: (session: any, roles: string[]) => boolean;
  LogicCore: any;
  Webhooks: any;
  getAdminSupabase: () => any;
  getSupabase: () => any;
  resolveWealthSourceWallet: (sb: any, userId: string, sourceWalletId?: string) => Promise<any>;
  assertBillPaymentSourceAllowed: (sourceRecord: any) => void;
  billReserveValuesMatch: (left: any, right: any) => boolean;
  resolveBillReserveReference: (reserve: any) => string | null;
  wealthNumber: (value: any) => number;
  ServiceCustomerRegistrationSchema: any;
  PaymentIntentSchema: any;
  BillReservePaymentSchema: any;
};

export const registerCommerceRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    validate,
    requireRole,
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
  } = deps;

  v1.post('/webhooks/:partnerId', async (req, res) => {
    const { partnerId } = req.params;
    try {
      const signatureHeader = req.get('x-signature') || req.get('x-webhook-signature') || req.get('x-orbi-signature') || undefined;
      const eventId = req.get('x-event-id') || req.get('x-webhook-id') || req.get('x-provider-event-id') || undefined;
      await Webhooks.handleCallback(req.body, partnerId, {
        signature: signatureHeader,
        rawPayload: (req as any).rawBody,
        explicitEventId: eventId,
        headers: Object.fromEntries(
          Object.entries(req.headers).map(([key, value]) => [
            key,
            Array.isArray(value) ? value.join(',') : value ? String(value) : undefined,
          ]),
        ),
        sourceIp: req.ip,
      });
      res.json({ success: true });
    } catch (e: any) {
      console.error(`[Webhook] Error processing webhook for ${partnerId}:`, e);
      const status = ['INVALID_SIGNATURE', 'MISSING_SIGNATURE', 'WEBHOOK_SECRET_NOT_CONFIGURED', 'REPLAY_DETECTED'].includes(e.message) ? 403 : 500;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchants/categories', authenticate, async (_req, res) => {
    try {
      const result = await LogicCore.getMerchantCategories();
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchants', authenticate, async (req, res) => {
    const category = req.query.category;
    try {
      const result = await LogicCore.getMerchants(category);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/merchants/accounts', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'CONSUMER', 'USER', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.createMerchantAccount(session.sub, req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchants/accounts/my', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getUserMerchantAccounts(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchants/accounts/:id', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getMerchantAccountById(req.params.id);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/merchants/accounts/:id/settlement', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.updateMerchantSettlement(req.params.id, req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchant/transactions', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);
    try {
      const result = await LogicCore.getMerchantTransactions(session.sub, limit, offset);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchant/wallets', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getMerchantWallets(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/merchant/customers/register', authenticate, validate(ServiceCustomerRegistrationSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.registerCustomerByServiceActor(session.user, 'MERCHANT', req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchant/customers', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getServiceLinkedCustomers(session.sub, 'MERCHANT');
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/merchant/payments/preview', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getTransactionPreview(session.sub, {
        ...req.body,
        metadata: { ...(req.body.metadata || {}), service_context: 'MERCHANT' },
      });
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/merchant/payments/settle', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.processMerchantPayment(req.body, session.user);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/orbi-pay/preview', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.previewOrbiPayPayment(session.sub, req.body);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/orbi-pay/settle', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.processOrbiPayPayment(req.body, session.user);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/payments/bills/providers', authenticate, async (_req, res) => {
    try {
      const result = LogicCore.getBillPaymentProviders();
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/bills/preview', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const sourceWalletId = String(req.body?.sourceWalletId || req.body?.source_wallet_id || '').trim();
      const { sourceRecord } = await resolveWealthSourceWallet(sb, session.sub, sourceWalletId || undefined);
      assertBillPaymentSourceAllowed(sourceRecord);
      const result = await LogicCore.previewBillPayment(session.sub, req.body);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(e.message === 'GOAL_FUNDS_BILL_PAYMENT_NOT_ALLOWED' ? 400 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/bills/settle', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const sourceWalletId = String(req.body?.sourceWalletId || req.body?.source_wallet_id || '').trim();
      const { sourceRecord } = await resolveWealthSourceWallet(sb, session.sub, sourceWalletId || undefined);
      assertBillPaymentSourceAllowed(sourceRecord);
      const result = await LogicCore.processBillPayment(req.body, session.user);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(e.message === 'GOAL_FUNDS_BILL_PAYMENT_NOT_ALLOWED' ? 400 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/bills/preview-from-reserve', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const payload = BillReservePaymentSchema.parse(req.body);
      const reserveId = String(payload.bill_reserve_id || payload.reserve_id || '').trim();
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const { data: reserve, error: reserveError } = await sb.from('bill_reserves').select('*').eq('id', reserveId).eq('user_id', session.sub).single();
      if (reserveError || !reserve) return res.status(404).json({ success: false, error: 'BILL_RESERVE_NOT_FOUND' });
      if (String(reserve.status || 'ACTIVE').toUpperCase() !== 'ACTIVE' || reserve.is_active === false) {
        return res.status(400).json({ success: false, error: 'BILL_RESERVE_INACTIVE' });
      }

      const { sourceRecord } = await resolveWealthSourceWallet(sb, session.sub, String(reserve.source_wallet_id || '').trim() || undefined);
      assertBillPaymentSourceAllowed(sourceRecord);
      if (!billReserveValuesMatch(payload.provider, reserve.provider_name || reserve.provider)) {
        return res.status(400).json({ success: false, error: 'BILL_RESERVE_PROVIDER_MISMATCH' });
      }
      if (payload.billCategory && reserve.bill_type && !billReserveValuesMatch(payload.billCategory, reserve.bill_type)) {
        return res.status(400).json({ success: false, error: 'BILL_RESERVE_CATEGORY_MISMATCH' });
      }
      const reserveReference = resolveBillReserveReference(reserve);
      if (payload.reference && reserveReference && !billReserveValuesMatch(payload.reference, reserveReference)) {
        return res.status(400).json({ success: false, error: 'BILL_RESERVE_REFERENCE_MISMATCH' });
      }

      const lockedBalance = wealthNumber(reserve.locked_balance || reserve.reserve_amount || 0);
      if (lockedBalance < payload.amount) {
        return res.status(400).json({ success: false, error: 'BILL_RESERVE_INSUFFICIENT_BALANCE' });
      }

      res.json({
        success: true,
        data: {
          success: true,
          funding_mode: 'RESERVE',
          reserve_id: reserve.id,
          amount: payload.amount,
          totalAmount: payload.amount,
          netAmount: payload.amount,
          currency: String(payload.currency || reserve.currency || sourceRecord.currency || 'TZS').toUpperCase(),
          provider: payload.provider,
          billCategory: payload.billCategory || reserve.bill_type,
          reference: payload.reference || reserveReference,
          description: payload.description || `Bill payment from reserve: ${payload.provider}`,
          reserveBalanceBefore: lockedBalance,
          reserveBalanceAfter: lockedBalance - payload.amount,
          sourceWalletId: sourceRecord.id,
        },
      });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/bills/settle-from-reserve', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const payload = BillReservePaymentSchema.parse(req.body);
      const reserveId = String(payload.bill_reserve_id || payload.reserve_id || '').trim();
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb.rpc('settle_bill_payment_from_reserve_v1', {
        p_user_id: session.sub,
        p_reserve_id: reserveId,
        p_amount: payload.amount,
        p_currency: String(payload.currency || 'TZS').toUpperCase(),
        p_provider: payload.provider,
        p_bill_category: payload.billCategory || null,
        p_reference: payload.reference || null,
        p_description: payload.description || null,
      });
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/agent/transactions', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);
    try {
      const result = await LogicCore.getAgentTransactions(session.sub, limit, offset);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/agent/wallets', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getAgentWallets(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/agent/lookup', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['USER', 'AGENT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const query = String(req.query.q || '').trim();
      const result = await LogicCore.lookupAgentByCode(query);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/agent/customers/register', authenticate, validate(ServiceCustomerRegistrationSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.registerCustomerByServiceActor(session.user, 'AGENT', req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/agent/customers', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getServiceLinkedCustomers(session.sub, 'AGENT');
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/agent/commissions', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT', 'ACCOUNTANT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getServiceCommissions(session.sub, 'AGENT');
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/agent/cash/deposit/preview', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getTransactionPreview(session.sub, {
        ...req.body,
        type: 'DEPOSIT',
        metadata: { ...(req.body.metadata || {}), service_context: 'AGENT_CASH', cash_direction: 'deposit' },
      });
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/agent/cash/deposit/settle', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.processAgentCashOperation(req.body, session.user, 'deposit');
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/agent/cash/withdraw/preview', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getTransactionPreview(session.sub, {
        ...req.body,
        type: 'WITHDRAWAL',
        metadata: { ...(req.body.metadata || {}), service_context: 'AGENT_CASH', cash_direction: 'withdrawal' },
      });
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/agent/cash/withdraw/settle', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.processAgentCashOperation(req.body, session.user, 'withdrawal');
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
};
