# ORBI Institutional Core

ORBI Institutional Core is a Node.js/TypeScript sovereign banking backend for
consumer, merchant, and institutional financial operations.

This repository is not an AI Studio app. The previous root README was stale and
did not describe the actual runtime.

## What This Repository Contains

- `server.ts`: primary API gateway and websocket runtime
- `backend/`: core banking, security, treasury, reconciliation, infrastructure
- `iam/`: identity, auth, and app-origin enforcement
- `ledger/`, `wealth/`, `strategy/`: financial domain services
- `docs/`: integration and operational documentation

## Primary Runtime Model

- REST API is served from `/v1`
- `/api/v1` is an alias for compatibility
- `/` also mounts the versioned router as a fallback
- Websocket stream is served at `/nexus-stream`

## Current Consumer App Identity

- `x-orbi-app-id`: `mobile-android` or `mobile-ios`
- `x-orbi-app-origin`: `ORBI_MOBILE_V2026`
- `x-orbi-registry-type`: optional on authenticated mobile requests and should
  reflect the authoritative public identity classification returned by the
  backend (`CONSUMER`, `MERCHANT`, or `AGENT`)
- `x-orbi-apk-hash`: Android only

## Institutional Desktop Identity

- `x-orbi-app-id`: `ORBI_INSTITUTIONAL_CORE_V2026`
- `x-orbi-app-origin`: `ORBI_INSTITUTIONAL_CORE_V2026`
- `x-orbi-user-role`: required on authenticated institutional requests and must
  match the authenticated session role

## Public Role Model

The current public-side role model is:

- `USER`: default public signup identity and compatibility fallback
- `CONSUMER`: standard retail user classification
- `MERCHANT`: business/payment acceptance user
- `AGENT`: cash-in / cash-out operator

Current lifecycle:

- mobile signups start as `role=USER` with `registry_type=CONSUMER`
- merchant and agent access are not self-assigned on signup
- public users request service elevation through `service_access_requests`
- ORBI institutional staff approve or reject those requests
- approval promotes the authoritative backend identity to `MERCHANT` or `AGENT`
  and updates the user metadata used by mobile and desktop clients

Service actor operations now persist through dedicated operational tables while still using the same canonical `transactions` and `financial_ledger` engine:
- `merchant_wallets`
- `merchant_transactions`
- `agents`
- `agent_wallets`
- `agent_transactions`
- `service_actor_customer_links`
- `service_commissions`

In practice:
- consumer transfers are normal retail wallet activity
- merchant payments are business/payment-acceptance activity with merchant projections
- agent payments are cash-service activity with agent projections and commission handling
- all three still share the same secure preview, settlement, double-entry ledger, audit, and reconciliation core

## Service Access Approval Model

Public users can request upgraded service access after signup:

- `POST /v1/service-access/requests`
- `GET /v1/service-access/requests/my`

Institutional staff review those requests through:

- `GET /v1/admin/service-access/requests`
- `POST /v1/admin/service-access/requests/:id/review`

Review outcomes:

- `APPROVED`: backend updates `role`, `registry_type`, and service-actor records
- `REJECTED`: request is retained for audit with reviewer attribution and notes
- agent approvals also provision the `agents` operational record

This keeps the consumer mobile app open to normal users while preventing direct
self-promotion into merchant or agent operations.

Institutional/staff-side roles remain:

- `SUPER_ADMIN`
- `ADMIN`
- `IT`
- `AUDIT`
- `ACCOUNTANT`
- `CUSTOMER_CARE`
- `HUMAN_RESOURCE`

Legacy `OBI_MOBILE_V1` remains accepted in older auth paths for backward
compatibility, but new consumer clients should not use it.

## Operational Notes

- Root gateway background jobs can be disabled with
  `ORBI_ENABLE_GATEWAY_BACKGROUND_JOBS=false`
- Internal modular server background jobs are disabled by default and only run
  when `ORBI_ENABLE_INTERNAL_BACKGROUND_JOBS=true`
- Process-local idempotency fallback is disabled by default because it is not
  safe in multi-instance deployments. Enable only for local/single-instance
  debugging with `ORBI_ALLOW_PROCESS_LOCAL_IDEMPOTENCY=true`
- Legacy `/api` operation gateway is disabled by default. Enable only for
  controlled migrations with `ORBI_ENABLE_LEGACY_API_GATEWAY=true`
- Legacy `/auth/biometric/*` aliases are disabled by default. Use
  `ORBI_ENABLE_LEGACY_BIOMETRIC_ROUTES=true` only while retiring older clients
- Server-side local session fallback is disabled by default and should only be
  used in non-production troubleshooting with
  `ORBI_ALLOW_LOCAL_SESSION_FALLBACK=true`
- Android app trust should be configured with `ORBI_ANDROID_PACKAGE_NAME` and
  `ORBI_ANDROID_APP_HASH`
- iOS trust should be configured with `ORBI_IOS_BUNDLE_IDS` as a comma-separated
  allowlist of trusted bundle IDs
- Redis TLS verification is enabled by default when `REDIS_TLS_ENABLED=true`.
  Only use `REDIS_ALLOW_INSECURE_TLS=true` for non-production troubleshooting
- Sandbox/demo routes are disabled by default and require
  `ORBI_ENABLE_SANDBOX_ROUTES=true`
- Messaging test routes are disabled by default and require
  `ORBI_ENABLE_MESSAGING_TEST_ROUTES=true`
- Provider webhooks should have secrets configured for every partner.
  `ORBI_REQUIRE_WEBHOOK_SIGNATURES=true` keeps unsigned callbacks rejected
- Generic REST processor calls enforce HTTPS by default and use
  `ORBI_PROVIDER_TIMEOUT_MS` for outbound timeouts
- Webhook replay protection is enabled through a Redis-backed event cache when
  available, with `ORBI_WEBHOOK_REPLAY_WINDOW_SECONDS` controlling the replay
  window
- Process-local webhook replay storage is disabled by default and should only be
  enabled for non-production troubleshooting with
  `ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE=true`

## Provider Registry Model

Provider integrations are now intended to be registry-driven rather than
selected by hardcoded provider classes.

Store provider behavior in `financial_partners.mapping_config` as JSON:

```json
{
  "auth": {
    "type": "oauth2_client_credentials",
    "url": "/oauth/token",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json"
    },
    "payload_template": {
      "client_id": "{{partner.client_id}}",
      "client_secret": "{{partner.client_secret}}"
    },
    "response_mapping": {
      "token_field": "access_token",
      "expires_in_field": "expires_in"
    }
  },
  "stk_push": {
    "url": "/payments/stkpush",
    "method": "POST",
    "headers": {
      "Authorization": "Bearer {{partner.access_token}}"
    },
    "payload_template": {
      "msisdn": "{{phone}}",
      "amount": "{{amount}}",
      "reference": "{{reference}}"
    },
    "response_mapping": {
      "id_field": "data.id",
      "status_field": "data.status",
      "message_field": "data.message"
    }
  },
  "callback": {
    "reference_field": "transaction.id",
    "status_field": "transaction.status",
    "message_field": "transaction.message",
    "event_id_field": "event.id",
    "success_values": ["SUCCESS", "200"],
    "pending_values": ["PENDING", "PROCESSING"],
    "failed_values": ["FAILED", "ERROR"]
  }
}
```

Secret values can be stored in top-level partner fields or inside registry JSON.
Sensitive fields written through the admin registry are encrypted before
persistence.

Registry-backed partner records should use these database fields:

- `type`: `mobile_money`, `bank`, `card`, or `crypto`
- `logic_type`: `REGISTRY` for new integrations
- `api_base_url`: provider base URL
- `client_id`, `client_secret`, `connection_secret`, `webhook_secret`: optional
  secret-bearing fields encrypted at rest
- `provider_metadata`: free-form metadata for routing, capabilities, or labels
- `mapping_config`: executable provider registry JSON

The Admin UI should create and update provider records through the partner
registry. New processor support should be added by registry JSON configuration,
not by introducing new hardcoded provider classes for each partner.

## Universal Routing, External Settlements, And Offline Gateway

The backend now includes the first production-oriented foundation for the
universal provider and offline gateway architecture.

Current implemented layers:

- registry-driven provider execution from `financial_partners`
- operation-aware routing through `provider_routing_rules`
- institutional external settlement accounts through
  `institutional_payment_accounts`
- persistent external movement records through `external_fund_movements`
- webhook-driven incoming deposit intent settlement
- offline gateway persistence through
  `inbound_sms_messages`, `offline_transaction_sessions`, and
  `outbound_sms_messages`
- offline confirmation bridge into the same ORBI transaction engine used by
  online flows

Important current routes:

- `GET /v1/gateway/providers`
- `POST /v1/external-funds/deposit-intents`
- `POST /v1/external-funds/preview`
- `POST /v1/external-funds/settle`
- `GET /v1/external-funds/movements`
- `POST /v1/webhooks/gateway/:providerId`
- `POST /api/internal/offline/requests`
- `POST /api/internal/offline/confirmations`
- `GET /api/admin/provider-routing-rules`
- `POST /api/admin/provider-routing-rules`
- `GET /api/admin/institutional-payment-accounts`
- `POST /api/admin/institutional-payment-accounts`

Current offline bridge scope:

- confirmed offline `SEND` requests are forwarded into the normal ORBI payment
  engine as `INTERNAL_TRANSFER`
- the offline layer does not post ledger entries directly
- ORBI core remains the financial truth

See:

- `docs/PROVIDER_REGISTRY_CONTRACT.md`
- `docs/UNIVERSAL_PROVIDER_AND_OFFLINE_GATEWAY_STATUS.md`

## Read Next

- `docs/INTEGRATION_MANUAL.md`
- `docs/MOBILE_SDK_GUIDE.md`
- `docs/CORE_BANKING_ARCHITECTURE.md`
- `docs/ORBI_OPERATION.md`
- `docs/PROVIDER_REGISTRY_CONTRACT.md`
- `docs/UNIVERSAL_PROVIDER_AND_OFFLINE_GATEWAY_STATUS.md`
