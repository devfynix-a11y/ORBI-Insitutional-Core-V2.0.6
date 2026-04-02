import type { Express, RequestHandler, Router } from 'express';
import { z } from 'zod';
import { getAdminSupabase, getSupabase } from '../../../backend/supabaseClient.js';
import { PartnerRegistry } from '../../../backend/admin/partnerRegistry.js';
import { TransactionService } from '../../../ledger/transactionService.js';
import { Server as LogicCore } from '../../../backend/server.js';
import { requireSessionPermission } from '../../middleware/auth/sessionAuth.js';
import { createAuthorizationMiddleware } from '../../middleware/auth/authorization.js';

const InstitutionalAccountSchema = z.object({
  role: z.enum(['MAIN_COLLECTION', 'FEE_COLLECTION', 'TAX_COLLECTION', 'TRANSFER_SAVINGS']),
  providerId: z.string().uuid().optional(),
  bankName: z.string().min(1),
  accountName: z.string().min(1),
  accountNumber: z.string().min(1),
  currency: z.string().length(3).optional(),
  countryCode: z.string().min(2).max(3).optional(),
  status: z.enum(['ACTIVE', 'INACTIVE']).optional(),
  isPrimary: z.boolean().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

const ProviderRoutingRuleSchema = z.object({
  rail: z.enum(['MOBILE_MONEY', 'BANK', 'CARD_GATEWAY', 'CRYPTO', 'WALLET']),
  countryCode: z.string().min(2).max(3).optional(),
  currency: z.string().length(3).optional(),
  operationCode: z.enum([
    'AUTH',
    'ACCOUNT_LOOKUP',
    'COLLECTION_REQUEST',
    'COLLECTION_STATUS',
    'DISBURSEMENT_REQUEST',
    'DISBURSEMENT_STATUS',
    'PAYOUT_REQUEST',
    'PAYOUT_STATUS',
    'REVERSAL_REQUEST',
    'REVERSAL_STATUS',
    'BALANCE_INQUIRY',
    'TRANSACTION_LOOKUP',
    'WEBHOOK_VERIFY',
    'BENEFICIARY_VALIDATE',
  ]),
  providerId: z.string().uuid(),
  priority: z.coerce.number().int().min(1).optional(),
  status: z.enum(['ACTIVE', 'INACTIVE']).optional(),
  conditions: z.record(z.string(), z.unknown()).optional(),
});

const PlatformFeeConfigSchema = z.object({
  name: z.string().min(1),
  flowCode: z.enum([
    'CORE_TRANSACTION',
    'INTERNAL_TRANSFER',
    'EXTERNAL_PAYMENT',
    'WITHDRAWAL',
    'DEPOSIT',
    'EXTERNAL_TO_INTERNAL',
    'INTERNAL_TO_EXTERNAL',
    'EXTERNAL_TO_EXTERNAL',
    'CARD_SETTLEMENT',
    'GATEWAY_SETTLEMENT',
    'FX_CONVERSION',
    'TENANT_SETTLEMENT_PAYOUT',
    'MERCHANT_PAYMENT',
    'AGENT_CASH_DEPOSIT',
    'AGENT_CASH_WITHDRAWAL',
    'AGENT_REFERRAL_COMMISSION',
    'AGENT_CASH_COMMISSION',
    'SYSTEM_OPERATION',
  ]),
  transactionType: z.string().optional(),
  operationType: z.string().optional(),
  direction: z.string().optional(),
  rail: z.enum(['MOBILE_MONEY', 'BANK', 'CARD_GATEWAY', 'CRYPTO', 'WALLET']).optional(),
  channel: z.string().optional(),
  providerId: z.string().uuid().optional(),
  currency: z.string().length(3).optional(),
  countryCode: z.string().min(2).max(3).optional(),
  percentageRate: z.coerce.number().min(0).optional(),
  fixedAmount: z.coerce.number().min(0).optional(),
  minimumFee: z.coerce.number().min(0).optional(),
  maximumFee: z.coerce.number().min(0).optional(),
  taxRate: z.coerce.number().min(0).optional(),
  govFeeRate: z.coerce.number().min(0).optional(),
  stampDutyFixed: z.coerce.number().min(0).optional(),
  priority: z.coerce.number().int().min(0).optional(),
  status: z.enum(['ACTIVE', 'INACTIVE']).optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

const queryStringValue = (value: unknown) => {
  if (Array.isArray(value)) {
    return value.length ? String(value[0]) : undefined;
  }
  if (typeof value === 'string') {
    return value;
  }
  return undefined;
};

export const registerAdminRoutes = (admin: Router, authenticate: RequestHandler) => {
  admin.use(authenticate);

  admin.use(createAuthorizationMiddleware({ allowedRoles: ['ADMIN', 'SUPER_ADMIN', 'IT'] }));

  admin.get('/partners', requireSessionPermission(['provider.read', 'provider.write'], ['ADMIN', 'SUPER_ADMIN', 'IT']), async (_req, res) => {
    try {
      const { data, error } = await PartnerRegistry.listPartners();
      if (error) return res.status(500).json({ success: false, error: error.message });
      res.json({ success: true, data });
    } catch (e: any) {
      console.error(`[Admin] List Partners Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  admin.post('/partners', requireSessionPermission(['provider.write'], ['ADMIN', 'SUPER_ADMIN', 'IT']), async (req, res) => {
    try {
      const session = (req as any).session;
      const auditMetadata = { updated_by: session.sub, updated_at: new Date().toISOString() };
      const payload = {
        ...req.body,
        provider_metadata: {
          ...(req.body?.provider_metadata || {}),
          admin_audit: {
            ...((req.body?.provider_metadata || {}).admin_audit || {}),
            ...auditMetadata,
          },
        },
      };
      const { data, error } = await PartnerRegistry.addPartner(payload);
      if (error) return res.status(500).json({ success: false, error: error.message });
      res.json({ success: true, data });
    } catch (e: any) {
      console.error(`[Admin] Add Partner Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  admin.put('/partners/:id', requireSessionPermission(['provider.write'], ['ADMIN', 'SUPER_ADMIN', 'IT']), async (req, res) => {
    try {
      const partnerId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const session = (req as any).session;
      const auditMetadata = { updated_by: session.sub, updated_at: new Date().toISOString() };
      const payload = {
        ...req.body,
        provider_metadata: {
          ...(req.body?.provider_metadata || {}),
          admin_audit: {
            ...((req.body?.provider_metadata || {}).admin_audit || {}),
            ...auditMetadata,
          },
        },
      };
      const { data, error } = await PartnerRegistry.updatePartner(partnerId, payload);
      if (error) return res.status(500).json({ success: false, error: error.message });
      res.json({ success: true, data });
    } catch (e: any) {
      console.error(`[Admin] Update Partner Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  admin.delete('/partners/:id', requireSessionPermission(['provider.write'], ['ADMIN', 'SUPER_ADMIN', 'IT']), async (req, res) => {
    try {
      const partnerId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const { error } = await PartnerRegistry.deletePartner(partnerId);
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

  admin.get('/balances', async (_req, res) => {
    try {
      const service = new TransactionService();
      const data = await service.getAggregatedWalletBalances(['Orbi', 'PaySafe']);
      res.json({ success: true, data });
    } catch (e: any) {
      console.error(`[Admin] Get Balances Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  admin.get('/institutional-payment-accounts', requireSessionPermission(['institutional_account.read', 'institutional_account.write'], ['ADMIN', 'SUPER_ADMIN', 'IT']), async (req, res) => {
    try {
      const data = await LogicCore.getInstitutionalPaymentAccounts({
        role: queryStringValue(req.query.role),
        status: queryStringValue(req.query.status),
        providerId: queryStringValue(req.query.providerId || req.query.provider_id),
        currency: queryStringValue(req.query.currency),
      });
      res.json({ success: true, data });
    } catch (e: any) {
      console.error('[Admin] List Institutional Accounts Error:', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  admin.post('/institutional-payment-accounts', requireSessionPermission(['institutional_account.write'], ['ADMIN', 'SUPER_ADMIN', 'IT']), async (req, res) => {
    try {
      const payload = InstitutionalAccountSchema.parse(req.body);
      const session = (req as any).session;
      const data = await LogicCore.upsertInstitutionalPaymentAccount(payload, session.sub);
      res.json({ success: true, data });
    } catch (e: any) {
      console.error('[Admin] Create Institutional Account Error:', e);
      res.status(400).json({ success: false, error: e.message });
    }
  });

  admin.patch('/institutional-payment-accounts/:id', requireSessionPermission(['institutional_account.write'], ['ADMIN', 'SUPER_ADMIN', 'IT']), async (req, res) => {
    try {
      const payload = InstitutionalAccountSchema.partial().parse(req.body);
      const session = (req as any).session;
      const accountId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const data = await LogicCore.upsertInstitutionalPaymentAccount(payload, session.sub, accountId);
      res.json({ success: true, data });
    } catch (e: any) {
      console.error('[Admin] Update Institutional Account Error:', e);
      res.status(400).json({ success: false, error: e.message });
    }
  });

  admin.get('/platform-fees', async (req, res) => {
    try {
      const data = await LogicCore.getPlatformFeeConfigs({
        flowCode: req.query.flowCode || req.query.flow_code,
        status: req.query.status,
        providerId: req.query.providerId || req.query.provider_id,
        currency: req.query.currency,
        countryCode: req.query.countryCode || req.query.country_code,
        rail: req.query.rail,
      });
      res.json({ success: true, data });
    } catch (e: any) {
      console.error('[Admin] List Platform Fees Error:', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  admin.post('/platform-fees', async (req, res) => {
    try {
      const payload = PlatformFeeConfigSchema.parse(req.body);
      const session = (req as any).session;
      const data = await LogicCore.upsertPlatformFeeConfig(payload, session.sub);
      res.json({ success: true, data });
    } catch (e: any) {
      console.error('[Admin] Create Platform Fee Error:', e);
      res.status(400).json({ success: false, error: e.message });
    }
  });

  admin.patch('/platform-fees/:id', async (req, res) => {
    try {
      const payload = PlatformFeeConfigSchema.partial().parse(req.body);
      const session = (req as any).session;
      const data = await LogicCore.upsertPlatformFeeConfig(payload, session.sub, req.params.id);
      res.json({ success: true, data });
    } catch (e: any) {
      console.error('[Admin] Update Platform Fee Error:', e);
      res.status(400).json({ success: false, error: e.message });
    }
  });

  admin.get('/provider-routing-rules', requireSessionPermission(['provider_routing.read', 'provider_routing.write'], ['ADMIN', 'SUPER_ADMIN', 'IT']), async (_req, res) => {
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb
        .from('provider_routing_rules')
        .select('*, financial_partners(id, name, type, provider_metadata)')
        .order('priority', { ascending: true })
        .order('created_at', { ascending: false });
      if (error) return res.status(500).json({ success: false, error: error.message });
      res.json({ success: true, data: data || [] });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  admin.post('/provider-routing-rules', requireSessionPermission(['provider_routing.write'], ['ADMIN', 'SUPER_ADMIN', 'IT']), async (req, res) => {
    try {
      const payload = ProviderRoutingRuleSchema.parse(req.body);
      const session = (req as any).session;
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb
        .from('provider_routing_rules')
        .insert({
          rail: payload.rail,
          country_code: payload.countryCode || null,
          currency: payload.currency?.toUpperCase() || null,
          operation_code: payload.operationCode,
          provider_id: payload.providerId,
          priority: payload.priority ?? 100,
          conditions: {
            ...(payload.conditions || {}),
            admin_audit: {
              ...(((payload.conditions || {}).admin_audit) || {}),
              updated_by: session.sub,
              updated_at: new Date().toISOString(),
            },
          },
          status: payload.status || 'ACTIVE',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .select('*')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  admin.patch('/provider-routing-rules/:id', requireSessionPermission(['provider_routing.write'], ['ADMIN', 'SUPER_ADMIN', 'IT']), async (req, res) => {
    try {
      const payload = ProviderRoutingRuleSchema.partial().parse(req.body);
      const session = (req as any).session;
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb
        .from('provider_routing_rules')
        .update({
          rail: payload.rail,
          country_code: payload.countryCode,
          currency: payload.currency?.toUpperCase(),
          operation_code: payload.operationCode,
          provider_id: payload.providerId,
          priority: payload.priority,
          conditions: payload.conditions === undefined
            ? undefined
            : {
                ...(payload.conditions || {}),
                admin_audit: {
                  ...(((payload.conditions || {}).admin_audit) || {}),
                  updated_by: session.sub,
                  updated_at: new Date().toISOString(),
                },
              },
          status: payload.status,
          updated_at: new Date().toISOString(),
        })
        .eq('id', req.params.id)
        .select('*')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  admin.delete('/provider-routing-rules/:id', requireSessionPermission(['provider_routing.write'], ['ADMIN', 'SUPER_ADMIN', 'IT']), async (req, res) => {
    try {
      const ruleId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { error } = await sb.from('provider_routing_rules').delete().eq('id', ruleId);
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
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
};

export const mountAdminRoutes = (app: Express, admin: Router) => {
  app.use('/api/admin', admin);
};
