import { z } from 'zod';
import type { RequestHandler, Router } from 'express';
import { Server as LogicCore } from '../../../backend/server.js';

const ExternalFundMovementSchema = z.object({
  direction: z.enum(['INTERNAL_TO_EXTERNAL', 'EXTERNAL_TO_INTERNAL', 'EXTERNAL_TO_EXTERNAL']),
  amount: z.coerce.number().positive(),
  currency: z.string().length(3).optional(),
  providerId: z.string().uuid().optional(),
  rail: z.enum(['MOBILE_MONEY', 'BANK', 'CARD_GATEWAY', 'CRYPTO', 'WALLET']).optional(),
  countryCode: z.string().min(2).max(3).optional(),
  operation: z.enum([
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
  ]).optional(),
  preferredProviderCode: z.string().optional(),
  description: z.string().optional(),
  transactionType: z.string().optional(),
  transaction_type: z.string().optional(),
  providerInput: z.string().optional(),
  provider_input: z.string().optional(),
  counterpartyType: z.string().optional(),
  counterparty_type: z.string().optional(),
  sourceWalletId: z.string().uuid().optional(),
  targetWalletId: z.string().uuid().optional(),
  sourceInstitutionalAccountId: z.string().uuid().optional(),
  targetInstitutionalAccountId: z.string().uuid().optional(),
  externalReference: z.string().optional(),
  sourceExternalRef: z.string().optional(),
  targetExternalRef: z.string().optional(),
  feeAmount: z.coerce.number().min(0).optional(),
  taxAmount: z.coerce.number().min(0).optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

const IncomingDepositIntentSchema = ExternalFundMovementSchema.omit({ direction: true }).extend({
  targetWalletId: z.string().uuid(),
});

export const registerProviderRoutes = (v1: Router, authenticate: RequestHandler) => {
  v1.post('/external-funds/preview', authenticate, async (req, res) => {
    try {
      const session = (req as any).session;
      const payload = ExternalFundMovementSchema.parse(req.body);
      const data = await LogicCore.previewExternalFundMovement(session.sub, payload);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/external-funds/deposit-intents', authenticate, async (req, res) => {
    try {
      const session = (req as any).session;
      const payload = IncomingDepositIntentSchema.parse(req.body);
      const data = await LogicCore.createIncomingDepositIntent(session.sub, payload);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/external-funds/settle', authenticate, async (req, res) => {
    try {
      const session = (req as any).session;
      const payload = ExternalFundMovementSchema.parse(req.body);
      const data = await LogicCore.processExternalFundMovement(session.sub, payload);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/external-funds/movements', authenticate, async (req, res) => {
    try {
      const session = (req as any).session;
      const limit = Number(req.query.limit || 50);
      const offset = Number(req.query.offset || 0);
      const data = await LogicCore.getUserExternalFundMovements(session.sub, limit, offset);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/external-funds/movements/:id', authenticate, async (req, res) => {
    try {
      const session = (req as any).session;
      const movementId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const data = await LogicCore.getUserExternalFundMovementById(session.sub, movementId);
      if (!data) {
        return res.status(404).json({ success: false, error: 'EXTERNAL_FUND_MOVEMENT_NOT_FOUND' });
      }
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
};

export const mountProviderRoutes = (
  v1: Router,
  gatewayV1: Router,
  gatewayRoutes: Router,
  authenticate: RequestHandler,
) => {
  gatewayV1.use((req, res, next) => {
    if (req.path.startsWith('/webhooks/gateway/')) {
      return next();
    }
    if (req.path.startsWith('/gateway')) {
      return authenticate(req, res, next);
    }
    return next();
  });

  gatewayV1.use(gatewayRoutes);
  v1.use(gatewayV1);
};
