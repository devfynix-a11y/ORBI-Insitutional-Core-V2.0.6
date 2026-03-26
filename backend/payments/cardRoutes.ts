import { Router, Request, Response } from 'express';
import { cardProcessor, CardTokenRequest, CardPaymentRequest } from './cardProcessor.js';
import { validationMiddleware } from '../middleware/validation.js';
import { z } from 'zod';
import { Audit } from '../security/audit.js';

type AuthenticatedRequest = Request & {
  user?: { id?: string; email?: string; role?: string };
  session?: {
    sub?: string;
    user?: { id?: string; user_id?: string };
  };
};

function getCardActorId(req: Request): string | null {
  const authReq = req as AuthenticatedRequest;
  return authReq.user?.id || authReq.session?.user?.id || authReq.session?.user?.user_id || authReq.session?.sub || null;
}

const cardRouter = Router();

/**
 * CARD PROCESSING API ENDPOINTS
 * ---------------------------
 * RESTful endpoints for payment card management and processing
 */

// ===== TOKENIZATION ENDPOINTS =====

/**
 * POST /v1/cards/tokenize
 * Tokenize a new payment card
 */
cardRouter.post(
  '/tokenize',
  validationMiddleware(
    z.object({
      cardNumber: z.string().regex(/^\d{13,19}$/, 'Invalid card number'),
      expiryMonth: z.number().min(1).max(12),
      expiryYear: z.number().min(2024).max(2099),
      cvv: z.string().regex(/^\d{3,4}$/, 'Invalid CVV'),
      cardholderName: z.string().min(2).max(50),
      billingAddress: z.optional(
        z.object({
          street: z.string(),
          city: z.string(),
          state: z.string(),
          postalCode: z.string(),
          country: z.string(),
        })
      ),
    })
  ),
  async (req: Request, res: Response) => {
    try {
      const userId = getCardActorId(req);
      if (!userId) return res.status(401).json({ error: 'Unauthorized' });

      const token = await cardProcessor.tokenizeCard(userId, req.body as CardTokenRequest);

      await Audit.log('FINANCIAL', userId, 'CARD_TOKENIZED_API', {
        cardBrand: token.cardBrand,
        last4: token.last4Digits,
      });

      res.status(201).json({
        success: true,
        data: {
          id: token.id,
          maskedCardNumber: token.maskedCardNumber,
          cardBrand: token.cardBrand,
          last4Digits: token.last4Digits,
          expiresAt: token.expiresAt,
          status: token.status,
        },
      });
    } catch (error: any) {
      console.error('[CardAPI] Tokenization error:', error.message);
      res.status(400).json({ error: error.message });
    }
  }
);

/**
 * GET /v1/cards
 * List all card tokens for authenticated user
 */
cardRouter.get('/', async (req: Request, res: Response) => {
  try {
    const userId = getCardActorId(req);
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const tokens = await cardProcessor.listCardTokens(userId);

    res.json({
      success: true,
      data: tokens.map((t: any) => ({
        id: t.id,
        maskedCardNumber: t.maskedCardNumber,
        cardBrand: t.cardBrand,
        last4Digits: t.last4Digits,
        expiresAt: t.expiresAt,
        status: t.status,
        isDefault: t.isDefault,
      })),
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * DELETE /v1/cards/:cardTokenId
 * Delete/deactivate a card token
 */
cardRouter.delete('/:cardTokenId', async (req: Request, res: Response) => {
  try {
    const userId = getCardActorId(req);
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    await cardProcessor.deleteCardToken(req.params.cardTokenId as string, userId);

    await Audit.log('FINANCIAL', userId, 'CARD_DELETED_API', {
      cardTokenId: req.params.cardTokenId,
    });

    res.json({ success: true, message: 'Card token deleted' });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

// ===== PAYMENT ENDPOINTS =====

/**
 * POST /v1/cards/authorize
 * Authorize a card payment (creates hold on card)
 */
cardRouter.post(
  '/authorize',
  validationMiddleware(
    z.object({
      cardTokenId: z.string(),
      amount: z.number().positive(),
      currency: z.string().length(3).default('TZS'),
      description: z.string().min(5),
      sourceWalletId: z.string().uuid(),
      targetWalletId: z.string().uuid(),
      merchantId: z.optional(z.string().uuid()),
      categoryId: z.optional(z.string().uuid()),
    })
  ),
  async (req: Request, res: Response) => {
    try {
      const userId = getCardActorId(req);
      if (!userId) return res.status(401).json({ error: 'Unauthorized' });

      const cardTx = await cardProcessor.authorizeCardPayment(
        userId,
        req.body as CardPaymentRequest
      );

      const statusCode = cardTx.status === 'AUTHORIZED' ? 201 : 400;

      res.status(statusCode).json({
        success: cardTx.status === 'AUTHORIZED',
        data: {
          id: cardTx.id,
          status: cardTx.status,
          amount: cardTx.amount,
          currency: cardTx.currency,
          authorizationCode: cardTx.authorizationCode,
          responseMessage: cardTx.responseMessage,
          riskScore: cardTx.riskScore,
          fraudFlags: cardTx.fraudFlags,
        },
      });
    } catch (error: any) {
      console.error('[CardAPI] Authorization error:', error.message);
      res.status(400).json({ error: error.message });
    }
  }
);

/**
 * POST /v1/cards/transactions/:cardTransactionId/settle
 * Settle an authorized card payment (capture funds)
 */
cardRouter.post(
  '/transactions/:cardTransactionId/settle',
  validationMiddleware(
    z.object({
      sourceWalletId: z.string().uuid(),
      targetWalletId: z.string().uuid(),
    })
  ),
  async (req: Request, res: Response) => {
    try {
      const userId = getCardActorId(req);
      if (!userId) return res.status(401).json({ error: 'Unauthorized' });

      const result = await cardProcessor.settleCardPayment(
        req.params.cardTransactionId as string,
        userId,
        req.body.sourceWalletId,
        req.body.targetWalletId
      );

      res.json({
        success: true,
        data: result,
      });
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  }
);

/**
 * POST /v1/cards/transactions/:cardTransactionId/refund
 * Refund a settled card payment
 */
cardRouter.post(
  '/transactions/:cardTransactionId/refund',
  validationMiddleware(z.object({ reason: z.optional(z.string()) })),
  async (req: Request, res: Response) => {
    try {
      const userId = getCardActorId(req);
      if (!userId) return res.status(401).json({ error: 'Unauthorized' });

      const result = await cardProcessor.refundCardPayment(
        req.params.cardTransactionId as string,
        userId,
        req.body.reason
      );

      await Audit.log('FINANCIAL', userId, 'CARD_REFUND_API', {
        originalTxId: req.params.cardTransactionId,
        refundId: result.refundId,
      });

      res.json({
        success: true,
        data: result,
      });
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  }
);

// ===== HEALTH CHECK =====

/**
 * GET /v1/cards/health
 * Card processing service health check
 */
cardRouter.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    service: 'CardProcessor',
    version: '2.0',
    features: ['TOKENIZATION', 'AUTHORIZATION', 'SETTLEMENT', 'REFUNDS', 'FRAUD_DETECTION'],
  });
});

export default cardRouter;
