/**
 * PAYMENT GATEWAY ROUTES
 * ======================
 * Mounted at the API root, so paths resolve like:
 * - /v1/gateway/providers
 * - /v1/gateway/payment/initiate
 * - /v1/webhooks/gateway/:providerId
 */

import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { getSupabase } from '../supabaseClient.js';
import { Audit } from '../security/audit.js';
import { UUID } from '../../services/utils.js';
import { FinancialPartnerMetadata, ProviderGroup } from '../../types.js';
import { GatewayService } from './gatewayService.js';
import { settlementLifecycleManager } from './settlementLifecycleManager.js';
import { settlementScheduler } from './settlementScheduler.js';
import { Webhooks } from './webhookHandler.js';

const router = Router();
const gatewayService = new GatewayService();

const InitiatePaymentSchema = z.object({
  amount: z.number().positive('Amount must be positive'),
  currency: z.string().length(3).toUpperCase(),
  paymentMethodId: z.string().min(1, 'Payment method required'),
  providerId: z.string().min(1, 'Provider ID required'),
  description: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

const SettlePaymentSchema = z.object({
  providerId: z.string().min(1, 'Provider ID required'),
  targetWalletId: z.string().uuid('Invalid wallet ID'),
  autoSettleMinutes: z.number().int().positive().max(1440).optional(),
});

const RefundSchema = z.object({
  providerId: z.string().min(1, 'Provider ID required'),
  reason: z.string().optional(),
});

type GatewayActor = {
  id: string;
  role?: string;
};

function readRouteParam(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value[0] || '';
  return value || '';
}

function getGatewayActor(req: Request): GatewayActor | null {
  const directUser = (req as any).user;
  if (directUser?.id) {
    return {
      id: String(directUser.id),
      role: directUser.role ? String(directUser.role) : undefined,
    };
  }

  const session = (req as any).session;
  if (!session) return null;

  const sessionUser = session.user || {};
  const userId = session.sub || sessionUser.id || sessionUser.user_id;
  const role =
    session.role ||
    sessionUser.role ||
    sessionUser.user_metadata?.role ||
    sessionUser.org_role;

  if (!userId) return null;

  return {
    id: String(userId),
    role: role ? String(role) : undefined,
  };
}

function resolveProviderGroup(partner: any): ProviderGroup {
  const metadataGroup = String(
    partner?.provider_metadata?.group ||
      partner?.provider_metadata?.provider_group ||
      partner?.provider_metadata?.category ||
      '',
  )
    .trim()
    .toLowerCase();
  const type = String(partner?.type || '')
    .trim()
    .toLowerCase();

  if (metadataGroup === 'mobile' || metadataGroup === 'mobile_money') {
    return 'Mobile';
  }
  if (metadataGroup === 'bank' || metadataGroup === 'banking') {
    return 'Bank';
  }
  if (
    metadataGroup === 'gateway' ||
    metadataGroup === 'gateways' ||
    metadataGroup === 'processor' ||
    metadataGroup === 'payment_gateway'
  ) {
    return 'Gateways';
  }
  if (metadataGroup === 'crypto') {
    return 'Crypto';
  }

  if (type === 'mobile_money') return 'Mobile';
  if (type === 'bank') return 'Bank';
  if (type === 'crypto') return 'Crypto';

  return 'Gateways';
}

function normalizeProviderMetadata(partner: any): FinancialPartnerMetadata {
  const metadata = (partner?.provider_metadata || {}) as FinancialPartnerMetadata;
  return {
    ...metadata,
    group: resolveProviderGroup(partner),
    brand_name:
      metadata.brand_name ||
      metadata.display_name ||
      partner?.name ||
      '',
    display_icon:
      metadata.display_icon ||
      metadata.icon ||
      partner?.icon ||
      '',
    color: metadata.color || partner?.color || '',
    channels: Array.isArray(metadata.channels) ? metadata.channels : [],
    checkout_mode: metadata.checkout_mode || 'server_to_server',
  };
}

router.get('/gateway/providers', async (_req: Request, res: Response) => {
  try {
    const sb = getSupabase();
    if (!sb) return res.status(503).json({ error: 'DB_OFFLINE' });

    const { data: partners, error } = await sb
      .from('financial_partners')
      .select(
        'id, name, type, status, supported_currencies, logic_type, provider_metadata, icon, color',
      )
      .eq('status', 'ACTIVE');

    if (error) throw error;

    res.json({
      success: true,
      providers: (partners || []).map((partner: any) => ({
        id: partner.id,
        name: partner.name,
        brandName:
          partner.provider_metadata?.brand_name ||
          partner.provider_metadata?.display_name ||
          partner.name,
        type: partner.type || 'card',
        group: resolveProviderGroup(partner),
        logicType: partner.logic_type || 'REGISTRY',
        status: partner.status,
        supportedCurrencies: partner.supported_currencies || [],
        icon:
          partner.provider_metadata?.display_icon ||
          partner.provider_metadata?.icon ||
          partner.icon ||
          null,
        color: partner.provider_metadata?.color || partner.color || null,
        checkoutMode:
          partner.provider_metadata?.checkout_mode || 'server_to_server',
        channels: Array.isArray(partner.provider_metadata?.channels)
          ? partner.provider_metadata.channels
          : [],
        sortOrder:
          Number(partner.provider_metadata?.sort_order) || 0,
        metadata: normalizeProviderMetadata(partner),
      })),
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/gateway/payment/initiate', async (req: Request, res: Response) => {
  try {
    const { amount, currency, paymentMethodId, providerId, metadata } =
      InitiatePaymentSchema.parse(req.body);
    const actor = getGatewayActor(req);
    if (!actor?.id) return res.status(401).json({ error: 'Unauthorized' });

    const sb = getSupabase();
    if (!sb) return res.status(503).json({ error: 'DB_OFFLINE' });

    const orderId = `order_${UUID.generate()}`;
    const { data: partner, error: partnerError } = await sb
      .from('financial_partners')
      .select('*')
      .eq('id', providerId)
      .eq('status', 'ACTIVE')
      .single();

    if (partnerError) throw partnerError;
    if (!partner) return res.status(404).json({ error: 'Provider not found or inactive' });

    const authorization = await gatewayService.initiateStkPush(
      partner,
      paymentMethodId,
      amount,
      orderId,
    );

    const { error: orderError } = await sb.from('payment_orders').insert({
      id: orderId,
      user_id: actor.id,
      provider_id: providerId,
      amount,
      currency,
      status: 'INITIATED',
      authorization_id: authorization.provider_ref,
      metadata: { paymentMethodId, ...(metadata || {}) },
      created_at: new Date().toISOString(),
    });

    if (orderError) throw orderError;

    await Audit.log('FINANCIAL', actor.id, 'PAYMENT_INITIATED', {
      orderId,
      providerId,
      amount,
      currency,
    });

    res.json({
      success: true,
      orderId,
      transactionId: authorization.provider_ref,
      status: 'PENDING',
      amount,
      currency,
    });
  } catch (error: any) {
    console.error('[GatewayAPI] Initiate payment error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

router.post('/gateway/payment/:orderId/settle', async (req: Request, res: Response) => {
  try {
    const orderId = readRouteParam(req.params.orderId);
    const { providerId, targetWalletId, autoSettleMinutes } =
      SettlePaymentSchema.parse(req.body);
    const actor = getGatewayActor(req);
    if (!actor?.id) return res.status(401).json({ error: 'Unauthorized' });

    const sb = getSupabase();
    if (!sb) return res.status(503).json({ error: 'DB_OFFLINE' });

    const { data: order, error: orderError } = await sb
      .from('payment_orders')
      .select('*')
      .eq('id', orderId)
      .eq('user_id', actor.id)
      .single();

    if (orderError) throw orderError;
    if (!order) return res.status(404).json({ error: 'Order not found' });

    const { data: wallet, error: walletError } = await sb
      .from('wallets')
      .select('*')
      .eq('id', targetWalletId)
      .eq('user_id', actor.id)
      .single();

    if (walletError) throw walletError;
    if (!wallet) return res.status(404).json({ error: 'Wallet not found or unauthorized' });

    const lifecycle = await settlementLifecycleManager.recordExternalPayment(
      actor.id,
      orderId,
      order.authorization_id,
      providerId,
      order.amount,
      order.currency,
      targetWalletId,
      autoSettleMinutes || 5,
    );

    const { error: updateError } = await sb
      .from('payment_orders')
      .update({
        status: 'SETTLEMENT_PENDING',
        settlement_id: lifecycle.settlementId,
        updated_at: new Date().toISOString(),
      })
      .eq('id', orderId);

    if (updateError) throw updateError;

    await Audit.log('FINANCIAL', actor.id, 'PAYMENT_PHASE1_RECORDED', {
      orderId,
      settlementId: lifecycle.settlementId,
      amount: order.amount,
      phase: 'EXTERNAL_PENDING',
      autoSettleAt: lifecycle.autoSettleAt,
    });

    res.json({
      success: true,
      phase: 'EXTERNAL_PENDING',
      settlementId: lifecycle.settlementId,
      orderId,
      amount: order.amount,
      currency: order.currency,
      status: 'EXTERNAL_PENDING',
      walletId: targetWalletId,
      autoSettleMinutes: lifecycle.autoSettleAfterMinutes,
      autoSettleAt: lifecycle.autoSettleAt,
      message: `Payment recorded externally from ${providerId}. Will be verified and settled to wallet in ${lifecycle.autoSettleAfterMinutes} minutes.`,
    });
  } catch (error: any) {
    console.error('[GatewayAPI] Settlement error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

router.post('/gateway/payment/:orderId/refund', async (req: Request, res: Response) => {
  try {
    const { orderId } = req.params;
    const { providerId, reason } = RefundSchema.parse(req.body);
    const actor = getGatewayActor(req);
    if (!actor?.id) return res.status(401).json({ error: 'Unauthorized' });

    const sb = getSupabase();
    if (!sb) return res.status(503).json({ error: 'DB_OFFLINE' });

    const { data: order, error: orderError } = await sb
      .from('payment_orders')
      .select('*')
      .eq('id', orderId)
      .eq('user_id', actor.id)
      .single();

    if (orderError) throw orderError;
    if (!order) return res.status(404).json({ error: 'Order not found' });

    const { data: partner, error: partnerError } = await sb
      .from('financial_partners')
      .select('*')
      .eq('id', providerId)
      .single();

    if (partnerError) throw partnerError;
    if (!partner) return res.status(404).json({ error: 'Provider not found' });

    const { error: updateError } = await sb
      .from('payment_orders')
      .update({
        status: 'REFUNDED',
        refunded_at: new Date().toISOString(),
      })
      .eq('id', orderId);

    if (updateError) throw updateError;

    await Audit.log('FINANCIAL', actor.id, 'PAYMENT_REFUNDED', {
      orderId,
      amount: order.amount,
      reason,
      providerId,
    });

    res.json({
      success: true,
      refundId: `refund_${UUID.generate()}`,
      status: 'COMPLETED',
      amount: order.amount,
    });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

router.get('/gateway/orders', async (req: Request, res: Response) => {
  try {
    const actor = getGatewayActor(req);
    if (!actor?.id) return res.status(401).json({ error: 'Unauthorized' });

    const sb = getSupabase();
    if (!sb) return res.status(503).json({ error: 'DB_OFFLINE' });

    const { data: orders, error } = await sb
      .from('payment_orders')
      .select('*')
      .eq('user_id', actor.id)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) throw error;
    res.json({ success: true, orders: orders || [] });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/gateway/order/:orderId', async (req: Request, res: Response) => {
  try {
    const actor = getGatewayActor(req);
    if (!actor?.id) return res.status(401).json({ error: 'Unauthorized' });

    const sb = getSupabase();
    if (!sb) return res.status(503).json({ error: 'DB_OFFLINE' });

    const { data: order, error } = await sb
      .from('payment_orders')
      .select('*')
      .eq('id', readRouteParam(req.params.orderId))
      .eq('user_id', actor.id)
      .single();

    if (error) throw error;
    if (!order) return res.status(404).json({ error: 'Order not found' });

    res.json({ success: true, order });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/gateway/settlement/:settlementId/status', async (req: Request, res: Response) => {
  try {
    const actor = getGatewayActor(req);
    if (!actor?.id) return res.status(401).json({ error: 'Unauthorized' });

    const sb = getSupabase();
    if (!sb) return res.status(503).json({ error: 'DB_OFFLINE' });

    const { data: settlement, error } = await sb
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', readRouteParam(req.params.settlementId))
      .eq('user_id', actor.id)
      .single();

    if (error) throw error;
    if (!settlement) return res.status(404).json({ error: 'Settlement not found' });

    res.json({
      success: true,
      settlementId: settlement.id,
      currentPhase: settlement.current_phase,
      amount: settlement.amount,
      currency: settlement.currency,
      provider: settlement.provider_id,
      status: settlement.current_phase,
      message: getPhaseMessage(settlement.current_phase),
      autoSettleAt: settlement.auto_settle_at,
      settledAt: settlement.phase_completed_at,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/gateway/settlement/:settlementId/confirm', async (req: Request, res: Response) => {
  try {
    const actor = getGatewayActor(req);
    if (!actor?.id) return res.status(401).json({ error: 'Unauthorized' });

    const sb = getSupabase();
    if (!sb) return res.status(503).json({ error: 'DB_OFFLINE' });

    const { data: settlement, error } = await sb
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', readRouteParam(req.params.settlementId))
      .eq('user_id', actor.id)
      .single();

    if (error) throw error;
    if (!settlement) return res.status(404).json({ error: 'Settlement not found' });

    const settlementId = readRouteParam(req.params.settlementId);
    await settlementScheduler.settlementReceivedManually(settlementId);

    const { data: updated, error: updatedError } = await sb
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', settlementId)
      .single();

    if (updatedError) throw updatedError;

    await Audit.log('FINANCIAL', actor.id, 'SETTLEMENT_MANUALLY_CONFIRMED', {
      settlementId,
      amount: settlement.amount,
    });

    res.json({
      success: true,
      message: 'Settlement confirmed! Being processed now.',
      settlementId,
      newPhase: updated?.current_phase,
    });
  } catch (error: any) {
    console.error('[GatewayAPI] Confirm settlement error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

router.post('/gateway/settlement/:settlementId/dispute', async (req: Request, res: Response) => {
  try {
    const actor = getGatewayActor(req);
    const reason = String(req.body?.reason || '').trim();
    if (!actor?.id) return res.status(401).json({ error: 'Unauthorized' });
    if (!reason) return res.status(400).json({ error: 'Dispute reason required' });

    const sb = getSupabase();
    if (!sb) return res.status(503).json({ error: 'DB_OFFLINE' });

    const { data: settlement, error } = await sb
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', readRouteParam(req.params.settlementId))
      .eq('user_id', actor.id)
      .single();

    if (error) throw error;
    if (!settlement) return res.status(404).json({ error: 'Settlement not found' });

    const settlementId = readRouteParam(req.params.settlementId);
    await settlementScheduler.disputeSettlement(settlementId, actor.id, reason);

    await Audit.log('SECURITY', actor.id, 'SETTLEMENT_DISPUTED', {
      settlementId,
      amount: settlement.amount,
      reason,
    });

    res.json({
      success: true,
      message: 'Dispute filed. Admin will review within 24 hours.',
      settlementId,
      status: 'DISPUTE_UNDER_REVIEW',
    });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

router.get('/gateway/settlements', async (req: Request, res: Response) => {
  try {
    const actor = getGatewayActor(req);
    if (!actor?.id) return res.status(401).json({ error: 'Unauthorized' });

    const sb = getSupabase();
    if (!sb) return res.status(503).json({ error: 'DB_OFFLINE' });

    let query = sb
      .from('settlement_lifecycle')
      .select('*')
      .eq('user_id', actor.id)
      .order('created_at', { ascending: false })
      .limit(50);

    const phase = String(req.query.phase || '').trim();
    if (phase) {
      query = query.eq('current_phase', phase);
    }

    const { data: settlements, error } = await query;
    if (error) throw error;

    res.json({
      success: true,
      count: settlements?.length || 0,
      settlements: (settlements || []).map((settlement: any) => ({
        id: settlement.id,
        amount: settlement.amount,
        currency: settlement.currency,
        provider: settlement.provider_id,
        phase: settlement.current_phase,
        phaseStartedAt: settlement.phase_started_at,
        autoSettleAt: settlement.auto_settle_at,
        createdAt: settlement.created_at,
      })),
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/gateway/scheduler/health', async (req: Request, res: Response) => {
  try {
    const actor = getGatewayActor(req);
    if (actor?.role !== 'ADMIN' && actor?.role !== 'SUPER_ADMIN') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const health = await settlementScheduler.healthCheck();
    res.json({ success: true, ...health });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/webhooks/gateway/:providerId', async (req: Request, res: Response) => {
  try {
    const providerId = readRouteParam(req.params.providerId);
    if (!providerId) return res.status(400).json({ error: 'Provider ID required' });

    const signatureHeader =
      req.header('x-signature') ||
      req.header('x-webhook-signature') ||
      req.header('x-hub-signature-256') ||
      req.header('authorization') ||
      undefined;
    const eventId =
      req.header('x-event-id') ||
      req.header('x-webhook-id') ||
      req.header('x-request-id') ||
      undefined;

    console.info(`[GatewayWebhook] Received webhook from ${providerId}`);
    await Webhooks.handleCallback(req.body, providerId, signatureHeader, undefined, eventId);
    res.json({ success: true, provider: providerId });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

function getPhaseMessage(phase: string): string {
  const messages: Record<string, string> = {
    EXTERNAL_PENDING: 'Payment received from provider. Will be verified and settled automatically.',
    RECONCILIATION_RUNNING: 'Verifying payment with provider...',
    READY_FOR_INTERNAL_COMMIT: 'Verification passed. Finalizing settlement.',
    INTERNALLY_SETTLED: 'Payment settled. Funds are now in your wallet.',
    SETTLEMENT_FAILED: 'Settlement failed. Please retry or contact support.',
    DISPUTE_UNDER_REVIEW: 'Your dispute is under review.',
    REVERSED: 'Settlement was reversed.',
  };

  return messages[phase] || 'Processing settlement...';
}

export default router;
