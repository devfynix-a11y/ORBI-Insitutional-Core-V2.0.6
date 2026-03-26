# Universal Provider And Offline Gateway Status

This document summarizes the current backend implementation status for the
universal provider registry, institutional external settlements, automatic
deposit intent flow, and offline gateway adapter bridge.

## What Is Implemented

### 1. Dynamic provider registry execution

Provider integrations are now designed to execute from the database registry
instead of hardcoded provider branches.

Current execution model:

- provider records live in `financial_partners`
- execution config lives in `mapping_config`
- UI and product metadata live in `provider_metadata`
- provider routing can be resolved by `rail + operation + country + currency`

Current code paths:

- `backend/payments/providers/ProviderFactory.ts`
- `backend/payments/providers/GenericRestProvider.ts`
- `backend/payments/providers/ProviderRegistryValidator.ts`
- `backend/payments/ProviderRoutingService.ts`

### 2. Universal service roots and operation-aware registry config

The registry now supports:

- `mapping_config.service_root`
- `mapping_config.service_roots`
- `mapping_config.operations`

This allows Admin UI to define:

- one universal provider base root
- optional per-service roots such as `auth`, `stk_push`, `disbursement`, and
  `balance`
- operation-specific endpoint definitions such as
  `COLLECTION_REQUEST` or `DISBURSEMENT_REQUEST`

### 3. Institutional external settlements

Real external fund movement support now exists through:

- `institutional_payment_accounts`
- `external_fund_movements`

Institutional account roles:

- `MAIN_COLLECTION`
- `FEE_COLLECTION`
- `TAX_COLLECTION`
- `TRANSFER_SAVINGS`

Supported movement directions:

- `INTERNAL_TO_EXTERNAL`
- `EXTERNAL_TO_INTERNAL`
- `EXTERNAL_TO_EXTERNAL`

Behavior:

- `INTERNAL_TO_EXTERNAL`: double-entry posted
- `EXTERNAL_TO_INTERNAL`: double-entry posted
- `EXTERNAL_TO_EXTERNAL`: record only, no double-entry

Current code path:

- `backend/payments/InstitutionalFundsService.ts`

### 4. Automatic external deposit intent flow

The backend now supports webhook-driven external cash-in settlement.

Flow:

1. client creates an incoming deposit intent
2. ORBI stores the pending `external_fund_movements` record
3. ORBI returns a universal payment reference
4. provider callback arrives through universal webhook route
5. ORBI matches the reference to the deposit intent
6. ORBI posts the real internal settlement automatically

Current routes:

- `POST /v1/external-funds/deposit-intents`
- `POST /v1/webhooks/gateway/:providerId`
- `POST /v1/webhooks/:partnerId`

### 5. Provider routing rules table

Routing rules now have a dedicated table:

- `provider_routing_rules`

This supports:

- rail-specific routing
- operation-specific routing
- country and currency scoping
- priority ordering
- future failover and tenant-specific conditions

Admin API routes:

- `GET /api/admin/provider-routing-rules`
- `POST /api/admin/provider-routing-rules`
- `PATCH /api/admin/provider-routing-rules/:id`

### 6. Offline gateway adapter persistence and bridge

The backend now includes the first real offline adapter skeleton.

Tables:

- `inbound_sms_messages`
- `offline_transaction_sessions`
- `outbound_sms_messages`

Current service path:

- `backend/offline/OfflineGatewayService.ts`
- `backend/offline/OfflineOrbiBridge.ts`

Internal routes:

- `POST /api/internal/offline/requests`
- `POST /api/internal/offline/confirmations`

Behavior:

- inbound offline request is parsed and stored
- offline session is created
- challenge response is generated and queued
- confirmation updates session state
- confirmed session is forwarded into the same ORBI transaction engine

## Current Offline Bridge Scope

The offline bridge currently supports the first safe path:

- confirmed offline `SEND` requests
- forwarded into the normal ORBI payment engine as `INTERNAL_TRANSFER`

This means the offline bridge does not create its own ledger path.
It uses the same ORBI financial core already used by online flows.

## Current Gaps

The architecture is moving in the right direction, but the backend is not yet
at the full target state described in the larger architecture note.

Still pending:

- explicit `providers`, `provider_operations`, and `provider_credentials` tables
  separate from `financial_partners`
- richer routing conditions and failover behavior
- polling orchestration tied to operation definitions
- offline bridge support for `PAY`, `WITHDRAW`, `BALANCE`, and statement flows
- stronger gateway-to-adapter authentication and timestamp freshness checks
- Redis-backed replay protection for offline request ids
- outbound SMS delivery worker integration

## Recommended Next Steps

1. apply the latest schema changes in the live database
2. seed `provider_routing_rules` for the active mobile money and bank rails
3. configure `mapping_config.operations` on each active provider
4. extend the offline bridge for merchant pay and withdrawal
5. split provider registry further into dedicated operation and credential tables

## Main Files

- `server.ts`
- `backend/server.ts`
- `types.ts`
- `database/schema.sql`
- `database/schema_reset.sql`
- `backend/payments/InstitutionalFundsService.ts`
- `backend/payments/ProviderRoutingService.ts`
- `backend/payments/providers/GenericRestProvider.ts`
- `backend/payments/webhookHandler.ts`
- `backend/offline/OfflineGatewayService.ts`
- `backend/offline/OfflineOrbiBridge.ts`
