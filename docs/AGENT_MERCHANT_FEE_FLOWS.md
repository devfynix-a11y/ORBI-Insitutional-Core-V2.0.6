# Agent, Merchant, and System Fee Flows

This document describes how agent cash operations, merchant payments, and system/service commissions use the unified platform fee registry (`platform_fee_configs`).

## Summary
- All fees are resolved from `platform_fee_configs` via `PlatformFeeService`.
- Fees are selected by `flow_code` plus optional context (currency, provider, rail, channel, direction).
- Agent commissions now use the same platform fee rules, not hardcoded rates.

## Fee Flow Codes
Use these `flow_code` values in `platform_fee_configs`:
- `MERCHANT_PAYMENT`
- `AGENT_CASH_DEPOSIT`
- `AGENT_CASH_WITHDRAWAL`
- `AGENT_REFERRAL_COMMISSION`
- `AGENT_CASH_COMMISSION`
- `SYSTEM_OPERATION`

## Merchant Payments
1. The transaction is created with `service_context: 'MERCHANT'` in metadata.
2. The ledger fee calculation maps to `flow_code = MERCHANT_PAYMENT`.
3. Fees are posted through the normal ledger paths.

Key paths:
- `backend/ledger/regulatoryService.ts`
- `backend/ledger/transactionEngine.ts`
- `backend/features/ServiceActorOps.ts` (merchant transaction sync)

## Agent Cash Deposits and Withdrawals
1. The transaction is created with `service_context: 'AGENT_CASH'` and `cash_direction` in metadata.
2. The ledger fee calculation maps to:
   - `AGENT_CASH_DEPOSIT` for deposits
   - `AGENT_CASH_WITHDRAWAL` for withdrawals
3. Fees post to the fee collector vault in the transaction currency.

Key paths:
- `backend/ledger/regulatoryService.ts`
- `backend/ledger/transactionEngine.ts`
- `backend/features/ServiceActorOps.ts` (agent transaction sync)

## Agent Commissions (Referral and Cash)
Commission amounts are calculated using platform fee rules:
- Referral commission: `AGENT_REFERRAL_COMMISSION`
- Agent cash commission: `AGENT_CASH_COMMISSION`

The commission is staged in `service_commissions` and paid after the source transaction settles.

Key paths:
- `backend/features/ServiceActorOps.ts`
- `backend/payments/PlatformFeeService.ts`

## System and Service Operations
System-level and service commission payouts map to `SYSTEM_OPERATION` so that Admin UI can keep them in the same fee catalog.

Key paths:
- `backend/ledger/regulatoryService.ts`
- `backend/features/ServiceActorOps.ts`

## Admin UI Integration
Admin API routes:
- `GET /api/admin/platform-fees`
- `POST /api/admin/platform-fees`
- `PATCH /api/admin/platform-fees/:id`

Each row in `platform_fee_configs` can be scoped by:
- `flow_code`
- `currency`
- `provider_id`
- `rail`
- `channel`
- `direction`

## Recommended Defaults
Set initial fee rows in `platform_fee_configs` for:
- `MERCHANT_PAYMENT`
- `AGENT_CASH_DEPOSIT`
- `AGENT_CASH_WITHDRAWAL`
- `AGENT_REFERRAL_COMMISSION`
- `AGENT_CASH_COMMISSION`
- `SYSTEM_OPERATION`

