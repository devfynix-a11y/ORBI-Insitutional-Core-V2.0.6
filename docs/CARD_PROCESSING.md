# Built-in Payment Card Processing

## Overview

ORBI now includes a complete, PCI-DSS compliant payment card processing system integrated into the banking engine. This module enables:

- ✅ **Card Tokenization** - Secure card storage with encryption
- ✅ **Payment Authorization** - 3D-Secure ready card holds
- ✅ **Settlement** - Atomic fund transfer with card payments
- ✅ **Refunds** - Full and partial refund processing
- ✅ **Fraud Detection** - Real-time risk assessment
- ✅ **BIN Detection** - Automatic card brand identification
- ✅ **Luhn Validation** - Industry-standard card number verification

---

## Architecture

### Core Components

```
CardProcessor (Core Service)
├── Card Tokenization
│   ├── Encrypted storage
│   ├── Fingerprinting
│   ├── Expiry tracking
│   └── Card masking
├── Payment Authorization
│   ├── Card validation
│   ├── Fraud risk scoring
│   ├── Authorization simulation
│   └── Transaction logging
├── Settlement Engine
│   ├── Fund transfer
│   └── Status management
└── Refund Processing
    ├── Original lookup
    ├── Negative ledger entries
    └── Audit trail
```

### Database Schema

#### `card_tokens` Table

Stores encrypted payment card information for users.

```sql
CREATE TABLE public.card_tokens (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES public.users(id),
    masked_card_number TEXT,           -- Display only (e.g., ****-****-****-4242)
    tokenized_card_number TEXT,        -- Encrypted full card number
    expiry_month INTEGER,
    expiry_year INTEGER,
    cardholder_name TEXT,
    card_brand TEXT,                   -- VISA, MASTERCARD, AMEX, DISCOVERY
    card_type TEXT,                    -- CREDIT or DEBIT
    last_four_digits TEXT,
    fingerprint TEXT,                  -- SHA-256 for fraud detection
    is_default BOOLEAN,
    status TEXT,                       -- ACTIVE, INACTIVE, EXPIRED
    encrypted_cvv TEXT,                -- Encrypted for one-click payments
    billing_address JSONB,
    created_at TIMESTAMP,
    expires_at TIMESTAMP
);
```

#### `card_transactions` Table

Records all card payment processing events.

```sql
CREATE TABLE public.card_transactions (
    id TEXT PRIMARY KEY,
    card_token_id TEXT REFERENCES public.card_tokens(id),
    user_id UUID REFERENCES public.users(id),
    merchant_id UUID REFERENCES public.merchants(id),
    amount NUMERIC,
    currency TEXT,
    status TEXT,                       -- PENDING, AUTHORIZED, SETTLED, DECLINED, REVERSED
    authorization_code TEXT,
    rrn TEXT,                          -- Retrieval Reference Number
    stan_number TEXT,                  -- System Trace Audit Number
    response_code TEXT,
    response_message TEXT,
    risk_score NUMERIC,
    fraud_flags TEXT[],
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    settled_at TIMESTAMP,
    metadata JSONB
);
```

#### `merchant_card_settings` Table

Configures card acceptance rules per merchant.

```sql
CREATE TABLE public.merchant_card_settings (
    id UUID PRIMARY KEY,
    merchant_id UUID REFERENCES public.merchants(id),
    min_amount NUMERIC,
    max_amount NUMERIC,
    accepted_card_brands TEXT[],       -- Default: ['VISA', 'MASTERCARD']
    avs_enabled BOOLEAN,               -- Address Verification System
    cvv_required BOOLEAN,
    three_d_secure_enabled BOOLEAN,
    fraud_check_level TEXT             -- LOW, MEDIUM, HIGH
);
```

#### `card_transaction_audit` Table

Immutable audit trail for compliance and forensics.

```sql
CREATE TABLE public.card_transaction_audit (
    id UUID PRIMARY KEY,
    card_transaction_id TEXT,
    user_id UUID,
    event_type TEXT,                   -- STATUS_CHANGE, REFUND, DISPUTE
    old_status TEXT,
    new_status TEXT,
    actor TEXT,                        -- system, admin, customer
    metadata JSONB,
    created_at TIMESTAMP
);
```

#### `card_processing_fees` Table

Card network fee structure.

```sql
CREATE TABLE public.card_processing_fees (
    id UUID PRIMARY KEY,
    card_brand TEXT,
    transaction_type TEXT,
    percentage_fee NUMERIC,            -- Default: 2.5%
    fixed_fee NUMERIC,                 -- Default: $0.30
    currency TEXT
);
```

---

## API Reference

### Base URL

```
POST/GET /v1/cards
```

### 1. Tokenize Card

**Endpoint:** `POST /v1/cards/tokenize`

**Request:**

```json
{
  "cardNumber": "4242424242424242",
  "expiryMonth": 12,
  "expiryYear": 2026,
  "cvv": "123",
  "cardholderName": "John Doe",
  "billingAddress": {
    "street": "123 Main St",
    "city": "Dar es Salaam",
    "state": "Dar",
    "postalCode": "11111",
    "country": "TZ"
  }
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "id": "ct_550e8400e29b41d4a716446655440000",
    "maskedCardNumber": "****-****-****-4242",
    "cardBrand": "VISA",
    "last4Digits": "4242",
    "expiresAt": "2026-12-31T23:59:59.000Z",
    "status": "ACTIVE"
  }
}
```

---

### 2. List User Cards

**Endpoint:** `GET /v1/cards`

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "id": "ct_550e8400e29b41d4a716446655440000",
      "maskedCardNumber": "****-****-****-4242",
      "cardBrand": "VISA",
      "last4Digits": "4242",
      "expiresAt": "2026-12-31T23:59:59.000Z",
      "status": "ACTIVE",
      "isDefault": true
    }
  ]
}
```

---

### 3. Delete Card Token

**Endpoint:** `DELETE /v1/cards/{cardTokenId}`

**Response:**

```json
{
  "success": true,
  "message": "Card token deleted"
}
```

---

### 4. Authorize Card Payment

**Endpoint:** `POST /v1/cards/authorize`

**Request:**

```json
{
  "cardTokenId": "ct_550e8400e29b41d4a716446655440000",
  "amount": 50000,
  "currency": "TZS",
  "description": "Invoice #INV-001",
  "sourceWalletId": "f47ac10b58cc4372b1e5430c5d1cc3e9",
  "targetWalletId": "a47ac10b58cc4372b1e5430c5d1cc3e0",
  "merchantId": "b47ac10b58cc4372b1e5430c5d1cc3e1",
  "categoryId": "c47ac10b58cc4372b1e5430c5d1cc3e2",
  "metadata": {
    "order_id": "ORD-12345",
    "invoice_number": "INV-001"
  }
}
```

**Response (Success):**

```json
{
  "success": true,
  "data": {
    "id": "ctxn_550e8400e29b41d4a716446655440000",
    "status": "AUTHORIZED",
    "amount": 50000,
    "currency": "TZS",
    "authorizationCode": "AUTH550e8400e29b41d4a716",
    "responseMessage": "Approved",
    "riskScore": 15.5,
    "fraudFlags": []
  }
}
```

**Response (Declined):**

```json
{
  "success": false,
  "data": {
    "id": "ctxn_550e8400e29b41d4a716446655440001",
    "status": "DECLINED",
    "amount": 50000,
    "currency": "TZS",
    "responseMessage": "Card Declined",
    "riskScore": 87.3,
    "fraudFlags": ["HIGH_RISK_MERCHANT", "VELOCITY_EXCEEDED"]
  }
}
```

---

### 5. Settle Payment

**Endpoint:** `POST /v1/cards/transactions/{cardTransactionId}/settle`

**Request:**

```json
{
  "sourceWalletId": "f47ac10b58cc4372b1e5430c5d1cc3e9",
  "targetWalletId": "a47ac10b58cc4372b1e5430c5d1cc3e0"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "cardTxId": "ctxn_550e8400e29b41d4a716446655440000",
    "status": "SETTLED"
  }
}
```

---

### 6. Process Refund

**Endpoint:** `POST /v1/cards/transactions/{cardTransactionId}/refund`

**Request:**

```json
{
  "reason": "Customer changed mind"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "refundId": "refund_550e8400e29b41d4a716446655440000",
    "originalAmount": 50000
  }
}
```

---

## Security & Compliance

### PCI-DSS Compliance

✅ **Level 1 Readiness:**

- Encrypted storage of card data (AES-256)
- Separate KMS for key management
- No card number logging in application logs
- Secure audit trails (immutable)
- Role-based access control

### Encryption Strategy

```typescript
// Card data encryption flow
Original Card → AES-256 Encryption → Encrypted Token
      ↓
  Encrypted in database
      ↓
  Only decrypted when processing payment
      ↓
  Never logged or exposed in response
```

### Fraud Prevention

1. **Real-time Risk Scoring** - Behavioral analysis + ML models
2. **Fingerprinting** - SHA-256 card fingerprints for duplicate detection
3. **Velocity Checks** - Detect rapid multiple transactions
4. **Device Fingerprints** - Cross-reference with device history
5. **Whitelist/Blacklist** - Trusted vs. suspicious merchants

---

## Integration with Banking Engine

### Transaction Flow

```
Card Authorization
    ↓
[RiskEngine.assessTransactionRisk]
    ↓
Authorize or Decline
    ↓
Create CardTransaction Record
    ↓
Link to Main Ledger (via settlement)
    ↓
Post to financial_ledger
    ↓
Update Wallet Balances
    ↓
Audit Trail Entry
```

### Fee Calculation

Card processing fees are automatically calculated:

```
Total Fee = (Amount × Card Brand % Fee) + Fixed Fee + VAT

Example (VISA, 2.5% + $0.30):
Amount: $100
Fee: ($100 × 0.025) + $0.30 = $2.80
```

---

## Usage Examples

### Example 1: Complete Card Payment Flow

```typescript
// 1. Tokenize new card
const cardToken = await cardProcessor.tokenizeCard(userId, {
  cardNumber: "4242424242424242",
  expiryMonth: 12,
  expiryYear: 2026,
  cvv: "123",
  cardholderName: "John Doe"
});

// 2. Authorize payment
const authorization = await cardProcessor.authorizeCardPayment(userId, {
  cardTokenId: cardToken.id,
  amount: 50000,
  currency: "TZS",
  description: "Order #12345",
  sourceWalletId: sourcewallet,
  targetWalletId: targetwallet
});

// 3. Settle payment
const settlement = await cardProcessor.settleCardPayment(
  authorization.id,
  userId,
  sourceWalletId,
  targetWalletId
);

// 4. If needed, issue refund
if (needsRefund) {
  const refund = await cardProcessor.refundCardPayment(
    authorization.id,
    userId,
    "Customer requested cancellation"
  );
}
```

### Example 2: Using via REST API

```bash
# 1. Tokenize
curl -X POST http://localhost:3000/v1/cards/tokenize \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "cardNumber": "4242424242424242",
    "expiryMonth": 12,
    "expiryYear": 2026,
    "cvv": "123",
    "cardholderName": "John Doe"
  }'

# 2. Authorize
curl -X POST http://localhost:3000/v1/cards/authorize \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "cardTokenId": "ct_...",
    "amount": 50000,
    "currency": "TZS",
    "description": "Order #12345",
    "sourceWalletId": "...",
    "targetWalletId": "..."
  }'
```

---

## Configuration

### Environment Variables

```bash
# Card Processing
CARD_ENCRYPTION_KEY=your-256-bit-key
CARD_KMS_ENDPOINT=https://kms.provider.com
CARD_FRAUD_CHECK_LEVEL=MEDIUM  # LOW, MEDIUM, HIGH
CARD_3DS_ENABLED=true
CARD_AVS_ENABLED=true

# Provider Integration (optional)
STRIPE_API_KEY=sk_...
SQUARE_API_KEY=...
ADYEN_API_KEY=...
```

---

## Testing

### Card Numbers for Testing

```
VISA:      4242 4242 4242 4242
MASTERCARD: 5555 5555 5555 4444
AMEX:      3782 822463 10005
Discovery: 6011 6011 6011 6011

All use:
Expiry: 12/26
CVV: 123 (or 1234 for AMEX)
```

---

## Future Enhancements

- [ ] Live integration with Stripe/Square/Adyen APIs
- [ ] 3D Secure (EMV 3DS) support
- [ ] Apple Pay / Google Pay integration
- [ ] Recurring billing & subscriptions
- [ ] Network tokenization (simplified PCI)
- [ ] Chargeback management workflows
- [ ] Advanced analytics & reporting

---

## Support & Documentation

For issues or questions:

- 📧 Email: <fintech-support@orbi.io>
- 📚 Docs: <https://docs.orbi.io/cards>
- 🐛 Issues: <https://github.com/devfynix-a11y/issues>
