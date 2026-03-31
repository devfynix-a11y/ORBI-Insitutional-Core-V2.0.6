# Frontend Integration Guide

## Real-Time Notifications (Nexus Stream)

To receive real-time notifications, connect to the WebSocket endpoint `/nexus-stream`.

### Endpoint
`wss://<YOUR_APP_URL>/nexus-stream`

### Authentication
Send an `AUTH` event immediately after connection with your JWT:
```json
{
    "event": "AUTH",
    "token": "<JWT_ACCESS_TOKEN>"
}
```

### React Hook Example (`useNexusStream.ts`)

```typescript
import { useEffect, useRef, useState } from 'react';
import { toast } from 'sonner'; // Or your preferred toast library

type NexusEvent = 
    | { type: 'NOTIFICATION'; payload: { id: string; category: string; subject: string; body: string; timestamp: string } }
    | { type: 'ACTIVITY_LOG'; payload: { activity_type: string; status: string; device_info: string } }
    | { type: 'AUTH_SUCCESS'; ts: number }
    | { type: 'KYC_UPDATE'; payload: { status: string; level: number } };

export const useNexusStream = (token: string | undefined) => {
    const socketRef = useRef<WebSocket | null>(null);
    const [isConnected, setIsConnected] = useState(false);

    useEffect(() => {
        if (!token) return;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        const wsUrl = `${protocol}//${host}/nexus-stream`;
        
        const ws = new WebSocket(wsUrl);
        socketRef.current = ws;

        ws.onopen = () => {
            console.log('[Nexus] Connected');
            setIsConnected(true);
            ws.send(JSON.stringify({ event: 'AUTH', token }));
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data) as NexusEvent;
                if (data.type === 'NOTIFICATION') {
                    toast(data.payload.subject, { description: data.payload.body });
                }
            } catch (e) {
                console.error('[Nexus] Parse Error', e);
            }
        };

        ws.onclose = () => setIsConnected(false);

        return () => ws.close();
    }, [token]);

    return { isConnected };
};
```

## Notification Management API

### Get Notifications
`GET /api/v1/notifications?limit=50&offset=0`

### Mark as Read
`PATCH /api/v1/notifications/:id/read`

### Mark All as Read
`PATCH /api/v1/notifications/read-all`

### Delete Notification
`DELETE /api/v1/notifications/:id`

## Device-Bound PIN Authentication

The mobile lock/login experience now supports a biometric-backed PIN flow.

### Core Rules
- biometric / passkey verification is the parent trust
- PIN is device-bound and tied to the same fingerprint used for biometric trust
- PIN enrollment and PIN update require a recent biometric parent verification
- successful PIN login returns a normal session payload

### Endpoints
- `POST /v1/auth/pin/enroll`
- `POST /v1/auth/pin/update`
- `POST /v1/auth/pin-login`

### Recommended Mobile Error Handling
- `PIN_NOT_ENROLLED`: prompt user to finish PIN setup after biometric
- `PIN_LOCKED_USE_BIOMETRIC`: send user to biometric re-verification
- `DEVICE_NOT_TRUSTED` / `DEVICE_BINDING_REQUIRED`: re-establish trust on the same device through biometric
- `IDENTITY_MISMATCH`: require the same phone/email linked to the biometric-backed identity

### Enrollment Example
```json
{
  "pin": "1234",
  "device": {
    "platform": "android",
    "model": "Pixel 8",
    "deviceName": "Daniel Phone"
  },
  "metadata": {
    "app_origin": "ORBI_MOBILE_V2026"
  }
}
```

### Login Example
```json
{
  "identifier": "+255712345678",
  "pin": "1234",
  "device": {
    "platform": "android",
    "model": "Pixel 8",
    "deviceName": "Daniel Phone"
  }
}
```

## Transaction Status Visibility
Clients should monitor the `status` field of transactions to provide real-time feedback to users.

### Status Values
*   `pending`: Transaction is in queue or awaiting external settlement.
*   `completed`: Funds have been successfully moved and ledger legs are balanced.
*   `failed`: Transaction was rejected (e.g., Insufficient Funds, Sentinel Block).
*   `reversed`: Transaction was rolled back due to a dispute or error.

## Handling Transaction Errors

## Multi-Currency & FX Engine

The system supports real-time currency conversion for cross-currency transfers. The backend `FXEngine` normalizes all amounts to USD for AML checks and applies a standard 0.5% conversion fee for actual transactions.

### Get FX Quote (Before Transfer)

Before a user confirms a transfer involving two different currencies, you should fetch a live quote to display the exchange rate, the fee, and the final amount they will receive.

**Endpoint:** `GET /api/v1/fx/quote?from=USD&to=TZS&amount=100`

**Response:**
```json
{
  "success": true,
  "data": {
    "originalAmount": 100,
    "fromCurrency": "USD",
    "toCurrency": "TZS",
    "exchangeRate": 2550,
    "fee": 1275,
    "finalAmount": 253725
  }
}
```

**Frontend Implementation Example:**
```tsx
const fetchQuote = async (amount: number, from: string, to: string) => {
    if (from === to) return null;
    const res = await fetch(`/api/v1/fx/quote?from=${from}&to=${to}&amount=${amount}`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const { data } = await res.json();
    return data; // { exchangeRate, fee, finalAmount, ... }
};

// In your UI:
// <p>Exchange Rate: 1 {from} = {data.exchangeRate} {to}</p>
// <p>Conversion Fee (0.5%): {data.fee} {to}</p>
// <p>Recipient Gets: {data.finalAmount} {to}</p>
```

### Autonomous Transfer Payloads

The system is designed to be autonomous. You can initiate transfers without knowing internal UUIDs.

#### Standard Transfer (Operating to Operating)
```json
{
  "type": "INTERNAL_TRANSFER",
  "category": "Transfer",
  "amount": 10000,
  "currency": "TZS",
  "recipient_customer_id": "OBI-839204",
  "description": "Payment for services",
  "walletType": "internal_vault"
}
```

#### Sub-Wallet Transfer (Goal/Budget to Recipient)
```json
{
  "type": "INTERNAL_TRANSFER",
  "category": "Transfer",
  "walletType": "GOAL", 
  "sourceWalletId": "UUID_OF_THE_GOAL", 
  "amount": 5000,
  "currency": "TZS",
  "recipient_customer_id": "OBI-839204",
  "description": "Savings used for payment"
}
```

### Complete Frontend Example (`api.ts`)

Here is a robust `fetch` function you can drop into your frontend code. It handles the token, idempotency key, and error parsing.

```typescript
// frontend/src/services/api.ts

interface PaymentRequest {
  amount: number;
  currency: string;
  recipient_customer_id: string; // The Customer ID (e.g., OB25-XXXX)
  description: string;
  type?: 'INTERNAL_TRANSFER' | 'EXTERNAL_PAYMENT';
}

export const sendTransaction = async (data: PaymentRequest, token: string) => {
  // 1. Generate a unique key to prevent double-charging on network retries
  const idempotencyKey = crypto.randomUUID(); 

  try {
    const response = await fetch('https://<YOUR_BACKEND_URL>/v1/transactions/settle', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        'x-idempotency-key': idempotencyKey
      },
      body: JSON.stringify({
        ...data,
        type: data.type || 'INTERNAL_TRANSFER', // Default to internal
        walletType: 'internal_vault' // Explicitly target the operating vault
      })
    });

    const result = await response.json();

    if (!response.ok) {
      // Handle Backend Errors (e.g., "VALIDATION_ERROR", "INSUFFICIENT_FUNDS")
      throw new Error(result.error || result.message || 'Transaction failed');
    }

    return result.data; // Success!

  } catch (error) {
    console.error('Payment Error:', error);
    throw error;
  }
};
```

### Insufficient Funds (400 Bad Request)
When calling `POST /v1/transactions/settle`, the server may return a `400` error with the code `INSUFFICIENT_FUNDS`.

## Consumer Payment Extensions

The consumer app now uses dedicated payment flows beyond generic `transactions/preview` and `transactions/settle`.

### ORBI Pay (Merchant Payments)

Endpoints:
- `POST /v1/payments/orbi-pay/preview`
- `POST /v1/payments/orbi-pay/settle`

Expected payload fields may include:
- `merchantPayNumber`
- `merchantId`
- `merchantName`
- `channel`
- `reference`
- `amount`
- `currency`
- `sourceWalletId`

These endpoints are designed for the normal consumer/mobile app. They do not require merchant-actor routes.

### Bill Payments

Endpoints:
- `GET /v1/payments/bills/providers`
- `POST /v1/payments/bills/preview`
- `POST /v1/payments/bills/settle`

Expected payload fields may include:
- `provider`
- `billCategory`
- `reference`
- `amount`
- `currency`
- `sourceWalletId`

Use the provider catalog to build the bill picker UI and pass the selected category/provider/reference into preview first.

## Shared Pot Invitation Flow

Shared pots now support invitation lifecycle management instead of only direct member insertion.

Endpoints:
- `GET /v1/wealth/shared-pot-invitations`
- `GET /v1/wealth/shared-pots/:id/invitations`
- `POST /v1/wealth/shared-pots/:id/invitations`
- `POST /v1/wealth/shared-pot-invitations/:id/respond`

Invitation states:
- `PENDING`
- `ACCEPTED`
- `REJECTED`
- `CANCELLED`
- `EXPIRED`

## Shared Budgets

Shared budgets are a separate collaborative spending product.

### Endpoints
- `GET /v1/wealth/shared-budgets`
- `POST /v1/wealth/shared-budgets`
- `PATCH /v1/wealth/shared-budgets/:id`
- `GET /v1/wealth/shared-budgets/:id/members`
- `GET /v1/wealth/shared-budgets/:id/transactions`
- `GET /v1/wealth/shared-budgets/:id/invitations`
- `GET /v1/wealth/shared-budget-invitations`
- `POST /v1/wealth/shared-budgets/:id/invitations`
- `POST /v1/wealth/shared-budget-invitations/:id/respond`
- `POST /v1/wealth/shared-budgets/:id/spend/preview`
- `POST /v1/wealth/shared-budgets/:id/spend/settle`

### UI Guidance
- show per-member spend totals from the members endpoint
- show recent activity from the transactions endpoint
- when approval mode is enabled, a settle attempt may return a review/pending result rather than immediate completion

## External Transfer / Withdraw Typing

When sending external transfer, withdraw, or agent-cash metadata, the client can now send richer context fields and the backend will preserve them:
- `transactionType` / `transaction_type`
- `providerInput` / `provider_input`
- `counterpartyType` / `counterparty_type`

Use these fields to distinguish:
- bank transfer
- mobile money movement
- external agent cash withdrawal

## Goal Auto-Allocation Replay

Goal auto-allocation is now backend-driven and replayable.

Endpoint:
- `POST /v1/goals/auto-allocate/replay`

Recommended use:
- admin/support recovery for missed credit events
- operational replay after delayed settlement reconciliation

**Recommended UI Behavior**:
1.  **Preventive**: Use the `available_balance` returned from `POST /v1/transactions/preview` to disable the "Confirm" button if `total > available_balance`.
2.  **Reactive**: If the API returns `INSUFFICIENT_FUNDS`, display a specific error message: "Your balance is insufficient to cover the transaction amount plus fees."

### Sentinel Block (403 Forbidden)
If the AI security engine blocks a request, the API returns `SENTINEL_BLOCK`.

**Recommended UI Behavior**:
Display a security alert: "This transaction was flagged by our security system. Please contact support."

## Admin Portal: Forensic Ledger Integration
The Admin Portal should utilize the forensic endpoints to provide staff with a "Deep Dive" view of any transaction.

### Implementation Pattern
1.  **List View**: Fetch all transactions using `GET /v1/admin/transactions`.
2.  **Detail View**: When a staff member clicks a transaction, fetch its ledger legs using `GET /v1/admin/transactions/:id/ledger`.
3.  **Visualization**: Display the ledger legs in a table showing the flow between vaults (e.g., `OPERATING` -> `INTERNAL_TRANSFER` -> `OPERATING`).

### Ledger Leg Object
```json
{
  "id": "uuid",
  "wallet_id": "uuid",
  "entry_type": "DEBIT | CREDIT",
  "amount": 5000.00,
  "balance_after": 15000.00,
  "description": "P2P Escrow Lock",
  "created_at": "2026-03-01T..."
}
```
