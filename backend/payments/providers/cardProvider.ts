/**
 * CARD PAYMENT PROVIDER
 * ====================
 * Card payment processor implementing IPaymentProvider interface
 * Supports tokenization, authorization, settlement with conditional ledger logic
 * 
 * Conditional ledger logic:
 * - External => External: No ledger, only record transaction
 * - External => Internal: Credit ledger only
 * - Internal => External: Debit ledger only
 * - Internal => Internal: Full ledger (debit + credit + fee)
 */

import crypto from 'crypto';
import { FinancialPartner } from '../../../types.js';
import { IPaymentProvider, ProviderResponse, ProviderCallbackResult } from './types.js';
import { getSupabase, getAdminSupabase } from '../../supabaseClient.js';
import { DataVault } from '../../security/encryption.js';
import { Audit } from '../../security/audit.js';
import { v4 as uuidv4 } from 'uuid';
import { GoalService } from '../../../strategy/goalService.js';

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

export class CardProvider implements IPaymentProvider {
  private readonly goals = new GoalService();
  private readonly BIN_PATTERNS = {
    VISA: /^4[0-9]{12}(?:[0-9]{3})?$/,
    MASTERCARD: /^5[1-5][0-9]{14}$/,
    AMEX: /^3[47][0-9]{13}$/,
    DISCOVERY: /^6(?:011|5[0-9]{2})[0-9]{12}$/,
  };

  /**
   * AUTHENTICATE - OAuth/API Key validation
   */
  async authenticate(partner: FinancialPartner): Promise<string> {
    try {
      if (!partner.client_id || !partner.client_secret) {
        throw new Error('CARD_PROCESSOR_CREDENTIALS_MISSING');
      }

      // For card processor, we decrypt and validate API credentials
      const decryptedSecret = await DataVault.decrypt(partner.client_secret || '');
      if (typeof decryptedSecret !== 'string' || !decryptedSecret.trim()) {
        throw new Error('CARD_PROCESSOR_INVALID_CREDENTIALS');
      }

      console.info(`[CardProvider] Authenticated for partner ${partner.name}`);
      return `Bearer ${Buffer.from(`${partner.client_id}:${decryptedSecret}`).toString('base64')}`;
    } catch (error: any) {
      await Audit.log('SECURITY', 'system', 'CARD_PROVIDER_AUTH_FAILED', {
        partnerId: partner.id,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * STK PUSH - Cash-In (Customer to Platform via Card)
   */
  async stkPush(partner: FinancialPartner, phone: string, amount: number, reference: string): Promise<ProviderResponse> {
    const sb = getSupabase();
    if (!sb) throw new Error('Database connection required');

    try {
      console.info(`[CardProvider] STK Push: ${phone} for ${amount}`);

      // For card processing, this would be a card authorization request
      const transactionId = uuidv4();

      // Store as pending transaction
      const { error } = await sb.from('card_transactions').insert({
        id: transactionId,
        user_id: reference,
        amount: amount.toString(),
        currency: partner.supported_currencies?.[0] || 'KES',
        status: 'PENDING',
        created_at: new Date().toISOString(),
      });

      if (error) throw error;

      return {
        success: true,
        providerRef: transactionId,
        message: 'Card authorization initiated',
      };
    } catch (error: any) {
      return {
        success: false,
        providerRef: '',
        message: error.message,
      };
    }
  }

  /**
   * DISBURSE - Cash-Out (Platform to Customer/Entity)
   */
  async disburse(partner: FinancialPartner, phone: string, amount: number, reference: string): Promise<ProviderResponse> {
    const sb = getSupabase();
    if (!sb) throw new Error('Database connection required');

    try {
      console.info(`[CardProvider] Disburse: ${phone} for ${amount}`);

      const transactionId = uuidv4();

      // Store disbursement
      const { error } = await sb.from('card_transactions').insert({
        id: transactionId,
        user_id: reference,
        amount: (-amount).toString(),
        currency: partner.supported_currencies?.[0] || 'KES',
        status: 'PROCESSING',
        created_at: new Date().toISOString(),
      });

      if (error) throw error;

      return {
        success: true,
        providerRef: transactionId,
        message: 'Card disbursement initiated',
      };
    } catch (error: any) {
      return {
        success: false,
        providerRef: '',
        message: error.message,
      };
    }
  }

  /**
   * PARSE CALLBACK - Translate provider-specific webhook payload
   */
  parseCallback(
    payload: any,
    partner?: FinancialPartner,
    context?: { headers?: Record<string, string | undefined> }
  ): ProviderCallbackResult {
    try {
      const status = payload.status || 'processing';
      
      return {
        reference: payload.reference || payload.transactionId || '',
        status: status === 'SUCCESS' || status === 'completed' ? 'completed' : 'processing',
        message: payload.message || 'Payment processed',
        providerEventId: payload.eventId || payload.webhookId,
        rawStatus: status,
      };
    } catch (error: any) {
      return {
        reference: '',
        status: 'failed',
        message: error.message,
      };
    }
  }

  /**
   * GET BALANCE - Current partner vault balance
   */
  async getBalance(partner: FinancialPartner): Promise<number> {
    // For card processor, this would query the payment processor's settlement account
    // Placeholder implementation - returns balance in smallest currency unit (cents)
    return 0;
  }

  // ============================================================
  // CARD-SPECIFIC METHODS
  // ============================================================

  /**
   * TOKENIZE CARD
   * Securely stores card and returns token
   */
  async tokenizeCard(userId: string, cardRequest: CardTokenRequest): Promise<CardToken> {
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) throw new Error('Database connection required for card tokenization');

    console.info(`[CardProvider] Tokenizing card for user ${userId}`);

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
    const cardTokenId = `ct_${uuidv4()}`;
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

    return tokens?.map((t) => this.formatCardToken(t)) || [];
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
   * AUTHORIZE CARD PAYMENT
   */
  async authorizeCardPayment(userId: string, authRequest: CardAuthRequest): Promise<CardTransaction> {
    const sb = getSupabase();
    if (!sb) throw new Error('Database connection required');

    try {
      // 1. RETRIEVE CARD TOKEN
      const { data: token } = await sb
        .from('card_tokens')
        .select('*')
        .eq('id', authRequest.cardTokenId)
        .eq('user_id', userId)
        .single();

      if (!token || token.status !== 'ACTIVE') {
        throw new Error('Card token not found or inactive');
      }

      // 2. CHECK CARD EXPIRY
      if (this.isCardExpired(token.expiry_month, token.expiry_year)) {
        throw new Error('Card has expired');
      }

      // 3. CREATE TRANSACTION RECORD
      const cardTxId = `ctxn_${uuidv4()}`;
      const stan = this.generateSTAN();
      const rrn = this.generateRRN();

      const { data: cardTx, error: txError } = await sb
        .from('card_transactions')
        .insert({
          id: cardTxId,
          card_token_id: authRequest.cardTokenId,
          user_id: userId,
          merchant_id: authRequest.merchantId || null,
          amount: authRequest.amount.toString(),
          currency: authRequest.currency,
          status: 'AUTHORIZED',
          rrn: rrn,
          stan_number: stan,
          response_code: '00',
          response_message: 'Approved',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          metadata: authRequest.metadata || {},
        })
        .select()
        .single();

      if (txError) throw new Error(`Failed to record card transaction: ${txError.message}`);

      await Audit.log('FINANCIAL', userId, 'CARD_AUTHORIZATION', {
        cardTxId,
        status: 'AUTHORIZED',
        amount: authRequest.amount,
      });

      return this.formatCardTransaction(cardTx);
    } catch (error: any) {
      console.error('[CardProvider] Authorization failed:', error);
      throw error;
    }
  }

  /**
   * SETTLE CARD PAYMENT - Conditional ledger logic
   */
  async settleCardPayment(transactionId: string, targetWalletId: string): Promise<SettlementResult> {
    const sb = getSupabase();
    if (!sb) throw new Error('Database connection required');

    console.info(`[CardProvider] Settling card transaction ${transactionId}`);

    try {
      // 1. RETRIEVE CARD TRANSACTION
      const { data: cardTx, error: fetchError } = await sb
        .from('card_transactions')
        .select('*')
        .eq('id', transactionId)
        .single();

      if (fetchError || !cardTx) throw new Error('Card transaction not found');
      if (cardTx.status !== 'AUTHORIZED') throw new Error('Only authorized transactions can be settled');

      // 2. GET TARGET WALLET
      const { data: targetWallet } = await sb
        .from('wallets')
        .select('id, balance, wallet_type, user_id')
        .eq('id', targetWalletId)
        .single();

      if (!targetWallet) throw new Error('Target wallet not found');

      // 3. DETERMINE WALLET TYPES
      const sourceType = 'EXTERNAL'; // Card processor is always external
      const targetType = targetWallet.wallet_type || 'INTERNAL';

      const transactionAmount = parseInt(cardTx.amount);
      const fee = Math.round(transactionAmount * 0.025); // 2.5% default fee

      // 4. CREATE FINANCIAL TRANSACTION
      const financialTxId = `ftx_${uuidv4()}`;
      const { data: financialTx } = await sb
        .from('transactions')
        .insert({
          id: financialTxId,
          user_id: targetWallet.user_id,
          type: 'deposit',
          status: 'completed',
          amount: transactionAmount.toString(),
          currency: cardTx.currency,
          source_wallet_id: 'card_processor_external',
          target_wallet_id: targetWalletId,
          description: `Card payment settlement - ${transactionId}`,
          settlement_path: sourceType === 'EXTERNAL' && targetType === 'EXTERNAL' ? 'NO_LEDGER' : 'SOVEREIGN_LEDGER',
          idempotency_key: `card_${transactionId}`,
          metadata: {
            card_transaction_id: transactionId,
            source_wallet_type: sourceType,
            target_wallet_type: targetType,
          },
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .select()
        .single();

      // 5. CREATE CONDITIONAL LEDGER ENTRIES
      if (sourceType === 'EXTERNAL' && targetType === 'INTERNAL') {
        // Credit ledger only
        await sb.from('financial_ledger').insert([
          {
            id: uuidv4(),
            transaction_id: financialTxId,
            user_id: targetWallet.user_id,
            wallet_id: targetWalletId,
            entry_type: 'CREDIT',
            amount: transactionAmount.toString(),
            balance_after: ((targetWallet.balance || 0) + transactionAmount).toString(),
            description: `Card deposit - ${transactionId}`,
            created_at: new Date().toISOString(),
          },
          {
            id: uuidv4(),
            transaction_id: financialTxId,
            user_id: targetWallet.user_id,
            wallet_id: process.env.SYSTEM_FEE_WALLET_ID || 'system_fees',
            entry_type: 'CREDIT',
            amount: fee.toString(),
            balance_after: fee.toString(),
            description: `Card processor fee - ${transactionId}`,
            created_at: new Date().toISOString(),
          },
        ]);

        // Update wallet balance
        await sb
          .from('wallets')
          .update({ balance: ((targetWallet.balance || 0) + transactionAmount).toString() })
          .eq('id', targetWalletId);
      }

      // 6. MARK TRANSACTION AS SETTLED
      await sb
        .from('card_transactions')
        .update({ status: 'SETTLED', settled_at: new Date().toISOString() })
        .eq('id', transactionId);

      await Audit.log('FINANCIAL', targetWallet.user_id, 'CARD_SETTLEMENT_COMPLETED', {
        cardTxId: transactionId,
        financialTxId,
        amount: transactionAmount,
        fee,
      });

      try {
        await this.goals.runAutoAllocationsForCredit({
          userId: String(targetWallet.user_id),
          sourceTransactionId: financialTxId,
          sourceReferenceId: financialTxId,
          sourceWalletId: String(targetWalletId),
          sourceAmount: transactionAmount,
          currency: cardTx.currency,
          triggerType: 'CARD_DEPOSIT',
          metadata: {
            source: 'card_provider',
            card_transaction_id: transactionId,
          },
        });
      } catch (autoAllocationError: any) {
        console.error('[GoalAutoAllocation] Card settlement trigger failed:', autoAllocationError?.message || autoAllocationError);
      }

      return {
        settlementId: financialTxId,
        transactionId,
        amount: transactionAmount,
        fee,
        status: 'COMPLETED',
      };
    } catch (error: any) {
      console.error('[CardProvider] Settlement failed:', error);
      throw error;
    }
  }

  /**
   * REFUND PAYMENT
   */
  async refundCardPayment(transactionId: string, reason?: string): Promise<RefundResult> {
    const sb = getSupabase();
    if (!sb) throw new Error('Database connection required');

    try {
      const { data: originalTx } = await sb
        .from('card_transactions')
        .select('*')
        .eq('id', transactionId)
        .single();

      if (!originalTx || originalTx.status !== 'SETTLED') {
        throw new Error('Only settled transactions can be refunded');
      }

      const refundId = `refund_${uuidv4()}`;

      await sb.from('card_transactions').insert({
        id: refundId,
        card_token_id: originalTx.card_token_id,
        user_id: originalTx.user_id,
        amount: (-parseInt(originalTx.amount)).toString(),
        currency: originalTx.currency,
        status: 'SETTLED',
        response_code: 'REFUND',
        response_message: reason || 'Refunded',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        settled_at: new Date().toISOString(),
      });

      await Audit.log('FINANCIAL', originalTx.user_id, 'CARD_REFUND_PROCESSED', {
        originalTxId: transactionId,
        refundId,
      });

      return { success: true, refundId, status: 'COMPLETED' };
    } catch (error: any) {
      console.error('[CardProvider] Refund failed:', error);
      throw error;
    }
  }

  // ============================================================
  // PRIVATE HELPER METHODS
  // ============================================================

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

  private detectCardBrand(cardNumber: string): 'VISA' | 'MASTERCARD' | 'AMEX' | 'DISCOVERY' {
    const sanitized = cardNumber.replace(/\D/g, '');
    if (this.BIN_PATTERNS.VISA.test(sanitized)) return 'VISA';
    if (this.BIN_PATTERNS.MASTERCARD.test(sanitized)) return 'MASTERCARD';
    if (this.BIN_PATTERNS.AMEX.test(sanitized)) return 'AMEX';
    if (this.BIN_PATTERNS.DISCOVERY.test(sanitized)) return 'DISCOVERY';
    return 'VISA';
  }

  private generateFingerprint(cardNumber: string): string {
    return crypto.createHash('sha256').update(cardNumber + 'card_fingerprint').digest('hex');
  }

  private isCardExpired(month: number, year: number): boolean {
    const expiry = new Date(year, month - 1, 0);
    return expiry < new Date();
  }

  private generateSTAN(): string {
    return Math.random().toString().slice(2, 8).padStart(6, '0');
  }

  private generateRRN(): string {
    return crypto.randomBytes(12).toString('hex').toUpperCase();
  }

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

  private formatCardTransaction(tx: any): CardTransaction {
    return {
      id: tx.id,
      cardTokenId: tx.card_token_id,
      userId: tx.user_id,
      amount: parseInt(tx.amount),
      currency: tx.currency,
      status: tx.status,
      rrn: tx.rrn,
      stan: tx.stan_number,
      createdAt: tx.created_at,
      updatedAt: tx.updated_at,
      settledAt: tx.settled_at,
    };
  }
}

// ============================================================
// TYPE DEFINITIONS
// ============================================================

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
  metadata?: any;
}

export interface CardToken {
  id: string;
  userId: string;
  maskedCardNumber: string;
  tokenizedCardNumber: string;
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

export interface CardAuthRequest {
  cardTokenId: string;
  amount: number;
  currency: string;
  merchantId?: string;
  metadata?: any;
}

export interface CardTransaction {
  id: string;
  cardTokenId: string;
  userId: string;
  amount: number;
  currency: string;
  status: 'AUTHORIZED' | 'SETTLED' | 'DECLINED' | 'PENDING';
  rrn: string;
  stan: string;
  createdAt: string;
  updatedAt: string;
  settledAt?: string;
}

export interface SettlementResult {
  settlementId: string;
  transactionId: string;
  amount: number;
  fee: number;
  status: string;
}

export interface RefundResult {
  success: boolean;
  refundId: string;
  status: string;
}

export const cardProvider = new CardProvider();
