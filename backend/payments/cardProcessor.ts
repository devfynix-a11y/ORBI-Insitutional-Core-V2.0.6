import { getSupabase, getAdminSupabase } from '../supabaseClient.js';
import { DataVault } from '../security/encryption.js';
import { Audit } from '../security/audit.js';
import { RiskEngine } from '../security/RiskEngine.js';
import { UUID } from '../../services/utils.js';
import { institutionalFundsService } from './InstitutionalFundsService.js';
import { EntProcessor } from '../enterprise/wealth/EnterprisePaymentProcessor.js';
import { platformFeeService } from './PlatformFeeService.js';
import crypto from 'crypto';

/**
 * ORBI PAYMENT CARD PROCESSOR (V2.0)
 * -----------------------------------
 * PCI-DSS compliant payment card processing with tokenization,
 * authorization, settlement, and fraud prevention.
 */

export interface CardTokenRequest {
  cardNumber: string;
  expiryMonth: number;
  expiryYear: number;
  cvv: string;
  cardholderName: string;
  billingAddress?: {
    street: string;
    city: string;
    state: string;
    postalCode: string;
    country: string;
  };
}

export interface CardToken {
  id: string;
  userId: string;
  maskedCardNumber: string;
  tokenizedCardNumber: string; // Encrypted
  expiryMonth: number;
  expiryYear: number;
  cardholderName: string;
  cardBrand: 'VISA' | 'MASTERCARD' | 'AMEX' | 'DISCOVERY';
  cardType: 'CREDIT' | 'DEBIT';
  last4Digits: string;
  fingerprint: string;
  isDefault: boolean;
  status: 'ACTIVE' | 'INACTIVE' | 'EXPIRED';
  createdAt: string;
  expiresAt: string;
  metadata?: any;
}

export interface CardPaymentRequest {
  cardTokenId: string;
  amount: number;
  currency: string;
  description: string;
  sourceWalletId: string;
  targetWalletId: string;
  merchantId?: string;
  categoryId?: string;
  cvv?: string; // Optional for stored tokens
  billingZipCode?: string; // For AVS verification
  metadata?: any;
}

export interface CardTransaction {
  id: string;
  cardTokenId: string;
  userId: string;
  merchantId?: string;
  amount: number;
  currency: string;
  status: 'PENDING' | 'AUTHORIZED' | 'SETTLED' | 'FAILED' | 'DECLINED' | 'REVERSED';
  authorizationCode?: string;
  rrn?: string; // Retrieval Reference Number
  stanNumber?: string; // System Trace Audit Number
  responseCode?: string;
  responseMessage?: string;
  riskScore?: number;
  fraudFlags?: string[];
  createdAt: string;
  updatedAt: string;
  settledAt?: string;
  metadata?: any;
}

export class CardProcessor {
  private readonly BIN_PATTERNS = {
    VISA: /^4[0-9]{12}(?:[0-9]{3})?$/,
    MASTERCARD: /^5[1-5][0-9]{14}$/,
    AMEX: /^3[47][0-9]{13}$/,
    DISCOVERY: /^6(?:011|5[0-9]{2})[0-9]{12}$/,
  };

  /**
   * TOKENIZE PAYMENT CARD
   * Securely stores card and returns token
   */
  async tokenizeCard(userId: string, cardRequest: CardTokenRequest): Promise<CardToken> {
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) throw new Error('Database connection required for card tokenization');

    console.info(`[CardProcessor] Tokenizing card for user ${userId}`);

    // 1. VALIDATE CARD NUMBER
    if (!this.validateCardNumber(cardRequest.cardNumber)) {
      throw new Error('Invalid card number (Luhn check failed)');
    }

    // 2. DETECT CARD BRAND
    const brand = this.detectCardBrand(cardRequest.cardNumber);
    const last4 = cardRequest.cardNumber.slice(-4);
    const maskedNumber = `****-****-****-${last4}`;
    const fingerprint = this.generateFingerprint(cardRequest.cardNumber);

    // 3. ENCRYPT SENSITIVE CARD DATA (PCI-DSS)
    const encryptedCardNumber = await DataVault.encrypt(cardRequest.cardNumber);
    const encryptedCVV = await DataVault.encrypt(cardRequest.cvv);

    // 4. STORE TOKENIZED CARD
    const cardTokenId = `ct_${UUID.generate()}`;
    const expiresAt = new Date(cardRequest.expiryYear, cardRequest.expiryMonth, 0);

    const { data: token, error } = await sb
      .from('card_tokens')
      .insert({
        id: cardTokenId,
        user_id: userId,
        masked_card_number: maskedNumber,
        tokenized_card_number: encryptedCardNumber,
        expiry_month: cardRequest.expiryMonth,
        expiry_year: cardRequest.expiryYear,
        cardholder_name: cardRequest.cardholderName,
        card_brand: brand,
        last_four_digits: last4,
        fingerprint,
        is_default: false,
        status: 'ACTIVE',
        encrypted_cvv: encryptedCVV,
        billing_address: cardRequest.billingAddress ? JSON.stringify(cardRequest.billingAddress) : null,
        created_at: new Date().toISOString(),
        expires_at: expiresAt.toISOString(),
      })
      .select()
      .single();

    if (error || !token) {
      await Audit.log('SECURITY', userId, 'CARD_TOKENIZATION_FAILED', { error: error?.message });
      throw new Error(`Card tokenization failed: ${error?.message}`);
    }

    await Audit.log('FINANCIAL', userId, 'CARD_TOKENIZED', { cardTokenId, brand, last4 });

    return this.formatCardToken(token);
  }

  /**
   * AUTHORIZE CARD PAYMENT (3D-Secure Ready)
   */
  async authorizeCardPayment(
    userId: string,
    paymentRequest: CardPaymentRequest
  ): Promise<CardTransaction> {
    const sb = getSupabase();
    if (!sb) throw new Error('Database connection required');

    console.info(`[CardProcessor] Authorizing card payment for user ${userId}: ${paymentRequest.amount} ${paymentRequest.currency}`);

    // 1. RETRIEVE CARD TOKEN
    const { data: token } = await sb
      .from('card_tokens')
      .select('*')
      .eq('id', paymentRequest.cardTokenId)
      .eq('user_id', userId)
      .single();

    if (!token || token.status !== 'ACTIVE') {
      throw new Error('Card token not found or inactive');
    }

    // 2. CHECK CARD EXPIRY
    if (this.isCardExpired(token.expiry_month, token.expiry_year)) {
      throw new Error('Card has expired');
    }

    // 3. PERFORM FRAUD RISK ASSESSMENT
    const riskAssessment = await RiskEngine.evaluateRequest({}, {
      userId,
      ip: '',
      appId: 'card_payment'
    });

    if (riskAssessment.score > 85) {
      return this.createFailedTransaction(paymentRequest, 'BLOCKED_BY_FRAUD_ENGINE', riskAssessment);
    }

    // 4. SIMULATE CARD AUTHORIZATION (In production, call real processor like Stripe/Square)
    const authResult = await this.performAuthorization(token, paymentRequest, riskAssessment);

    // 5. STORE TRANSACTION RECORD
    const cardTxId = `ctxn_${UUID.generate()}`;
    const stan = this.generateSTAN();
    const rrn = this.generateRRN();

    const { data: cardTx, error: txError } = await sb
      .from('card_transactions')
      .insert({
        id: cardTxId,
        card_token_id: paymentRequest.cardTokenId,
        user_id: userId,
        merchant_id: paymentRequest.merchantId || null,
        amount: paymentRequest.amount,
        currency: paymentRequest.currency,
        status: authResult.success ? 'AUTHORIZED' : 'DECLINED',
        authorization_code: authResult.authCode,
        rrn: rrn,
        stan_number: stan,
        response_code: authResult.responseCode,
        response_message: authResult.responseMessage,
        risk_score: riskAssessment.score,
        fraud_flags: JSON.stringify(riskAssessment.signals || []),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        metadata: paymentRequest.metadata || {},
      })
      .select()
      .single();

    if (txError) throw new Error(`Failed to record card transaction: ${txError.message}`);

    // 6. AUDIT LOG
    await Audit.log('FINANCIAL', userId, 'CARD_AUTHORIZATION', {
      cardTxId,
      status: cardTx.status,
      amount: paymentRequest.amount,
      riskScore: riskAssessment.score,
    });

    return this.formatCardTransaction(cardTx);
  }

  /**
   * SETTLE AUTHORIZED PAYMENT
   * Conditional ledger logic based on wallet types:
   * - External => External: No ledger, only record transaction
   * - External => Internal: Credit ledger
   * - Internal => External: Debit ledger
   * - Internal => Internal: Full ledger (debit + credit + fee)
   */
  async settleCardPayment(
    cardTransactionId: string,
    userId: string,
    sourceWalletId: string,
    targetWalletId: string
  ): Promise<any> {
    const sb = getSupabase();
    if (!sb) throw new Error('Database connection required');

    console.info(`[CardProcessor] Settling card transaction ${cardTransactionId}`);

    // 1. RETRIEVE CARD TRANSACTION
    const { data: cardTx, error: fetchError } = await sb
      .from('card_transactions')
      .select('*')
      .eq('id', cardTransactionId)
      .eq('user_id', userId)
      .single();

    if (fetchError || !cardTx) throw new Error('Card transaction not found');
    if (cardTx.status !== 'AUTHORIZED') throw new Error('Only authorized transactions can be settled');

    // 2. VERIFY AND DETERMINE WALLET TYPES
    const sourceWallet = await this.getSettlementWallet(sourceWalletId, userId, true);
    const targetWallet = await this.getSettlementWallet(targetWalletId, null, false);

    // Determine wallet types (INTERNAL or EXTERNAL)
    const sourceType = sourceWallet.wallet_type || 'INTERNAL';
    const targetType = targetWallet.wallet_type || 'INTERNAL';

    // 3. CALCULATE TRANSACTION DETAILS
    const transactionAmount = cardTx.amount;
    const transactionCurrency = String(cardTx.currency || '').trim().toUpperCase();
    if (!transactionCurrency) {
      throw new Error('CARD_SETTLEMENT_CURRENCY_REQUIRED');
    }
    const feeComputation = await platformFeeService.resolveFee({
      flowCode: 'CARD_SETTLEMENT',
      amount: transactionAmount,
      currency: transactionCurrency,
      providerId: cardTx.merchant_id || undefined,
      rail: 'CARD_GATEWAY',
      transactionType: 'CARD_SETTLEMENT',
      metadata: {
        card_transaction_id: cardTransactionId,
      },
    });
    const transactionFee = feeComputation.serviceFee;
    const transactionTax = feeComputation.taxAmount + feeComputation.govFeeAmount + feeComputation.stampDutyFixed;
    const totalAmount = transactionAmount + transactionFee + transactionTax;
    const settlementContext = {
      service_context: 'CARD_PROCESSOR',
      card_transaction_id: cardTransactionId,
      card_token_id: cardTx.card_token_id,
      authorization_code: cardTx.authorization_code,
      rrn: cardTx.rrn,
      stan: cardTx.stan_number,
      source_wallet_type: sourceType,
      target_wallet_type: targetType,
      processor_fee_estimate: transactionFee,
      processor_tax_estimate: transactionTax,
      fee_config_id: feeComputation.configId || null,
    };

    try {
      let financialTxId: string | null = null;
      let movementId: string | null = null;
      let ledgerEntriesCreated = 0;

      if (sourceType === 'EXTERNAL' || targetType === 'EXTERNAL') {
        const direction =
          sourceType === 'EXTERNAL' && targetType === 'INTERNAL'
            ? 'EXTERNAL_TO_INTERNAL'
            : sourceType === 'INTERNAL' && targetType === 'EXTERNAL'
              ? 'INTERNAL_TO_EXTERNAL'
              : 'EXTERNAL_TO_EXTERNAL';

        const movementResult = await institutionalFundsService.processMovement(userId, {
          direction,
          amount: transactionAmount,
          currency: transactionCurrency,
          providerId: cardTx.merchant_id || undefined,
          description: `Card payment settlement for transaction ${cardTransactionId}`,
          sourceWalletId: direction !== 'EXTERNAL_TO_INTERNAL' ? sourceWalletId : undefined,
          targetWalletId: direction !== 'INTERNAL_TO_EXTERNAL' ? targetWalletId : undefined,
          feeAmount: transactionFee,
          taxAmount: transactionTax,
          metadata: settlementContext,
          sourceExternalRef: sourceType === 'EXTERNAL' ? sourceWalletId : undefined,
          targetExternalRef: targetType === 'EXTERNAL' ? targetWalletId : undefined,
          externalReference: cardTx.rrn || cardTransactionId,
        });

        financialTxId = 'transactionId' in movementResult ? movementResult.transactionId || null : null;
        movementId = movementResult.movement?.id || null;
        ledgerEntriesCreated = movementResult.ledgerPosted ? direction === 'EXTERNAL_TO_EXTERNAL' ? 0 : transactionFee > 0 ? 3 : 2 : 0;
      } else {
        const enterpriseResult = await EntProcessor.process(
          { id: userId, user_metadata: {} } as any,
          {
            idempotencyKey: `card_${cardTransactionId}`,
            referenceId: cardTx.rrn || `CARD-${cardTransactionId}`,
            sourceWalletId,
            targetWalletId,
            amount: transactionAmount,
            currency: transactionCurrency,
            description: `Card payment settlement for transaction ${cardTransactionId}`,
            type: 'INTERNAL_TRANSFER',
            metadata: settlementContext,
          } as any,
        );

        if (!enterpriseResult?.success) {
          throw new Error(enterpriseResult?.error || 'CARD_ENTERPRISE_SETTLEMENT_FAILED');
        }

        financialTxId =
          enterpriseResult?.transaction?.id ||
          enterpriseResult?.data?.transaction?.id ||
          enterpriseResult?.id ||
          null;
        ledgerEntriesCreated = 0;
      }

      const settledAt = new Date().toISOString();
      const { error: cardUpdateError } = await sb
        .from('card_transactions')
        .update({
          status: 'SETTLED',
          settled_at: settledAt,
          updated_at: settledAt,
          metadata: {
            ...(cardTx.metadata || {}),
            ...settlementContext,
            settlement_transaction_id: financialTxId,
            external_movement_id: movementId,
          },
        })
        .eq('id', cardTransactionId);

      if (cardUpdateError) throw cardUpdateError;

      await Audit.log('FINANCIAL', userId, 'CARD_SETTLEMENT_COMPLETED', {
        cardTxId: cardTransactionId,
        financialTxId,
        movementId,
        amount: transactionAmount,
        fee: transactionFee,
        tax: transactionTax,
        sourceWallet: sourceWalletId,
        sourceWalletType: sourceType,
        targetWallet: targetWalletId,
        targetWalletType: targetType,
        ledgerEntriesCreated,
        rrn: cardTx.rrn,
        status: 'SETTLED',
      });

      console.info(`[CardProcessor] ✅ Settlement completed: ${financialTxId || movementId || cardTransactionId} (${sourceType} => ${targetType})`);

      return {
        success: true,
        cardTxId: cardTransactionId,
        financialTxId,
        movementId,
        status: 'SETTLED',
        amount: transactionAmount,
        fee: transactionFee,
        tax: transactionTax,
        totalSettled: totalAmount,
        sourceWalletType: sourceType,
        targetWalletType: targetType,
        ledgerEntriesCreated,
        settledAt,
      };
    } catch (error: any) {
      await Audit.log('SECURITY', userId, 'CARD_SETTLEMENT_FAILED', {
        cardTxId: cardTransactionId,
        error: error.message,
        sourceWalletType: sourceType,
        targetWalletType: targetType,
        timestamp: new Date().toISOString(),
      });
      throw error;
    }
  }

  private async getSettlementWallet(walletId: string, ownerUserId?: string | null, requireOwnership: boolean = false) {
    const sb = getSupabase();
    if (!sb) throw new Error('Database connection required');

    let walletQuery = sb
      .from('wallets')
      .select('id, user_id, balance, wallet_type, currency')
      .eq('id', walletId);

    if (requireOwnership && ownerUserId) {
      walletQuery = walletQuery.eq('user_id', ownerUserId);
    }

    const { data: wallet, error } = await walletQuery.maybeSingle();
    if (error) throw new Error(error.message);
    if (wallet) return wallet;

    let vaultQuery = sb
      .from('platform_vaults')
      .select('id, user_id, balance, currency, vault_role')
      .eq('id', walletId);

    if (requireOwnership && ownerUserId) {
      vaultQuery = vaultQuery.eq('user_id', ownerUserId);
    }

    const { data: vault, error: vaultError } = await vaultQuery.maybeSingle();
    if (vaultError) throw new Error(vaultError.message);
    if (vault) {
      return {
        ...vault,
        wallet_type: 'INTERNAL',
      };
    }

    throw new Error(requireOwnership ? 'Source wallet not found or unauthorized' : 'Target wallet not found');
  }

  /**
   * REFUND CARD PAYMENT
   */
  async refundCardPayment(cardTransactionId: string, userId: string, reason?: string): Promise<any> {
    const sb = getSupabase();
    if (!sb) throw new Error('Database connection required');

    console.info(`[CardProcessor] Processing refund for card transaction ${cardTransactionId}`);

    // 1. RETRIEVE ORIGINAL TRANSACTION
    const { data: originalTx } = await sb
      .from('card_transactions')
      .select('*')
      .eq('id', cardTransactionId)
      .eq('user_id', userId)
      .single();

    if (!originalTx) throw new Error('Original transaction not found');
    if (!['SETTLED', 'AUTHORIZED'].includes(originalTx.status)) {
      throw new Error('Only settled or authorized transactions can be refunded');
    }

    // 2. CREATE REFUND RECORD
    const refundId = `refund_${UUID.generate()}`;
    const { data: refund, error } = await sb
      .from('card_transactions')
      .insert({
        id: refundId,
        card_token_id: originalTx.card_token_id,
        user_id: userId,
        merchant_id: originalTx.merchant_id,
        amount: -originalTx.amount, // Negative amount
        currency: originalTx.currency,
        status: 'SETTLED',
        response_code: 'REFUND',
        response_message: reason || 'Customer refund',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        settled_at: new Date().toISOString(),
      })
      .select()
      .single();

    if (error) throw new Error(`Refund failed: ${error.message}`);

    await Audit.log('FINANCIAL', userId, 'CARD_REFUND_PROCESSED', { originalTxId: cardTransactionId, refundId });

    return { success: true, refundId, originalAmount: originalTx.amount };
  }

  /**
   * LIST USER CARD TOKENS
   */
  async listCardTokens(userId: string): Promise<CardToken[]> {
    const sb = getSupabase();
    if (!sb) return [];

    const { data: tokens } = await sb
      .from('card_tokens')
      .select('*')
      .eq('user_id', userId)
      .eq('status', 'ACTIVE')
      .order('created_at', { ascending: false });

    return tokens?.map(t => this.formatCardToken(t)) || [];
  }

  /**
   * DELETE CARD TOKEN
   */
  async deleteCardToken(tokenId: string, userId: string): Promise<void> {
    const sb = getSupabase();
    if (!sb) throw new Error('Database connection required');

    const { error } = await sb
      .from('card_tokens')
      .update({ status: 'INACTIVE' })
      .eq('id', tokenId)
      .eq('user_id', userId);

    if (error) throw new Error(`Failed to delete card token: ${error.message}`);

    await Audit.log('SECURITY', userId, 'CARD_TOKEN_DELETED', { tokenId });
  }

  /**
   * HELPER: Validate card number using Luhn algorithm
   */
  private validateCardNumber(cardNumber: string): boolean {
    const sanitized = cardNumber.replace(/\D/g, '');
    if (sanitized.length < 13 || sanitized.length > 19) return false;

    let sum = 0;
    let isEven = false;
    for (let i = sanitized.length - 1; i >= 0; i--) {
      let digit = parseInt(sanitized[i], 10);
      if (isEven) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      isEven = !isEven;
    }

    return sum % 10 === 0;
  }

  /**
   * HELPER: Detect card brand from BIN
   */
  private detectCardBrand(cardNumber: string): 'VISA' | 'MASTERCARD' | 'AMEX' | 'DISCOVERY' {
    const sanitized = cardNumber.replace(/\D/g, '');
    if (this.BIN_PATTERNS.VISA.test(sanitized)) return 'VISA';
    if (this.BIN_PATTERNS.MASTERCARD.test(sanitized)) return 'MASTERCARD';
    if (this.BIN_PATTERNS.AMEX.test(sanitized)) return 'AMEX';
    if (this.BIN_PATTERNS.DISCOVERY.test(sanitized)) return 'DISCOVERY';
    return 'VISA'; // Default fallback
  }

  /**
   * HELPER: Generate card fingerprint for fraud detection
   */
  private generateFingerprint(cardNumber: string): string {
    return crypto.createHash('sha256').update(cardNumber + 'card_fingerprint').digest('hex');
  }

  /**
   * HELPER: Check if card is expired
   */
  private isCardExpired(month: number, year: number): boolean {
    const expiry = new Date(year, month - 1, 0);
    return expiry < new Date();
  }

  /**
   * HELPER: Generate STAN (System Trace Audit Number)
   */
  private generateSTAN(): string {
    return Math.random().toString().slice(2, 8).padStart(6, '0');
  }

  /**
   * HELPER: Generate RRN (Retrieval Reference Number)
   */
  private generateRRN(): string {
    return crypto.randomBytes(12).toString('hex').toUpperCase();
  }

  /**
   * HELPER: Simulate card authorization
   */
  private async performAuthorization(
    token: any,
    request: CardPaymentRequest,
    riskAssessment: any
  ): Promise<{ success: boolean; authCode?: string; responseCode: string; responseMessage: string }> {
    // Simulate authorization delay
    await new Promise(resolve => setTimeout(resolve, 500));

    // In production, call Stripe, Square, or Adyen API here
    const isDeclined = Math.random() < 0.02; // 2% decline rate for simulation

    return {
      success: !isDeclined,
      authCode: isDeclined ? undefined : `AUTH${UUID.generate().slice(0, 12)}`,
      responseCode: isDeclined ? '05' : '00',
      responseMessage: isDeclined ? 'Card Declined' : 'Approved',
    };
  }

  /**
   * HELPER: Create failed transaction record
   */
  private async createFailedTransaction(
    request: CardPaymentRequest,
    responseCode: string,
    riskAssessment: any
  ): Promise<CardTransaction> {
    const transactionId = `ctxn_${UUID.generate()}`;
    return {
      id: transactionId,
      cardTokenId: request.cardTokenId,
      userId: '',
      amount: request.amount,
      currency: request.currency,
      status: 'DECLINED',
      responseCode,
      responseMessage: 'Transaction blocked by fraud detection',
      riskScore: riskAssessment.score || 0,
      fraudFlags: riskAssessment.signals?.map((s: any) => s.type) || [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * HELPER: Format card token for response
   */
  private formatCardToken(token: any): CardToken {
    return {
      id: token.id,
      userId: token.user_id,
      maskedCardNumber: token.masked_card_number,
      tokenizedCardNumber: token.tokenized_card_number,
      expiryMonth: token.expiry_month,
      expiryYear: token.expiry_year,
      cardholderName: token.cardholder_name,
      cardBrand: token.card_brand,
      cardType: token.card_type || 'CREDIT',
      last4Digits: token.last_four_digits,
      fingerprint: token.fingerprint,
      isDefault: token.is_default,
      status: token.status,
      createdAt: token.created_at,
      expiresAt: token.expires_at,
      metadata: token.metadata || {},
    };
  }

  /**
   * HELPER: Format card transaction for response
   */
  private formatCardTransaction(tx: any): CardTransaction {
    return {
      id: tx.id,
      cardTokenId: tx.card_token_id,
      userId: tx.user_id,
      merchantId: tx.merchant_id,
      amount: tx.amount,
      currency: tx.currency,
      status: tx.status,
      authorizationCode: tx.authorization_code,
      rrn: tx.rrn,
      stanNumber: tx.stan_number,
      responseCode: tx.response_code,
      responseMessage: tx.response_message,
      riskScore: tx.risk_score,
      fraudFlags: tx.fraud_flags,
      createdAt: tx.created_at,
      updatedAt: tx.updated_at,
      settledAt: tx.settled_at,
      metadata: tx.metadata || {},
    };
  }
}

export const cardProcessor = new CardProcessor();
