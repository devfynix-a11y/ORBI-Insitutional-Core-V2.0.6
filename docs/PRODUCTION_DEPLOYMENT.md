# ORBI Production Deployment Guide

## Required Services
- Primary database: Supabase Postgres (service role access required for server-side operations)
- Auth: Supabase Auth (server-side admin access)
- Cache/queues: Redis (cluster or single-node)
- Object storage: Supabase Storage or equivalent S3-compatible backend (for receipts, artifacts)
- Background jobs: Node worker runtime (same build as API)
- Observability: centralized log ingestion (JSON structured logs)

## Secrets
- `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_ANON_KEY`
- `JWT_SECRET`
- `KMS_MASTER_KEY`
- `WORKER_SECRET`
- `WORKER_SIGNING_SECRET`
- Provider secrets (stored in `financial_partners.provider_metadata.secrets` or encrypted vault fields)

## Environment Variables
### Required (Production)
- `NODE_ENV=production`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_ANON_KEY`
- `JWT_SECRET`
- `KMS_MASTER_KEY`
- `WORKER_SECRET`
- `WORKER_SIGNING_SECRET`
- `ORBI_INTERNAL_MTLS_MODE=required`
- `ORBI_INTERNAL_MTLS_SOURCE`
- `ORBI_ENFORCE_HTTPS=true`
- `RP_ID`
- `ORBI_WEB_ORIGIN`
- `ORBI_MOBILE_ORIGIN`
- `ORBI_CORE_PORTAL_APP_ORIGIN`
- `ORBI_ANDROID_APP_HASH`

### Strongly Recommended
- `REDIS_URL` or `REDIS_CLUSTER_NODES`
- `REDIS_TLS_ENABLED=true`
- `REDIS_ALLOW_INSECURE_TLS=false`
- `ORBI_TLS_ENABLED=true` with valid `ORBI_TLS_CERT_PATH` and `ORBI_TLS_KEY_PATH` when terminating TLS directly on the Node server
- `ORBI_GATEWAY_API_KEY` and `ORBI_GATEWAY_URL`
- `ORBI_WEBHOOK_MAX_AGE_SECONDS`
- `ORBI_WEBHOOK_REPLAY_WINDOW_SECONDS`
- `ORBI_PROVIDER_TIMEOUT_MS`
- `ORBI_PROVIDER_MAX_ATTEMPTS`
- `ORBI_PROVIDER_RETRY_DELAY_MS`

### Optional / Feature Flags
- `ORBI_ENABLE_GATEWAY_BACKGROUND_JOBS`
- `ORBI_ENABLE_INTERNAL_BACKGROUND_JOBS`
- `ORBI_ENABLE_LEGACY_API_GATEWAY`
- `ORBI_ENABLE_SANDBOX_ROUTES`
- `ORBI_ENABLE_MESSAGING_TEST_ROUTES`

## Pre-Flight Checklist
1. Confirm required production env vars are present (see above).
2. Confirm `ORBI_INTERNAL_MTLS_MODE=required` and worker signing secrets are set.
3. Confirm internal mTLS source is explicitly configured:
   - proxy mode: `ORBI_INTERNAL_MTLS_SOURCE=proxy` and `ORBI_INTERNAL_MTLS_PROXY_SHARED_SECRET`
   - direct mode: `ORBI_INTERNAL_MTLS_SOURCE=direct` and `ORBI_INTERNAL_MTLS_CA_PATH`
4. Confirm desktop portal identity is configured if desktop clients are enabled:
   - `ORBI_CORE_PORTAL_APP_ID`
   - `ORBI_CORE_PORTAL_APP_ORIGIN`
5. Ensure Supabase connectivity using service-role credentials.
6. Verify critical RPCs exist:
   - `post_transaction_v2`
   - `append_ledger_entries_v1`
   - `claim_internal_transfer_settlement`
   - `complete_internal_transfer_settlement`
   - `repair_wallet_balance_emergency`
7. Validate Redis connectivity (or accept degraded mode if intentionally disabled).
8. Verify provider registry readiness for active partners (mapping config, webhook callback config).
9. Run `/health` and `/api/admin/monitor/operational-health` before opening traffic.

## TLS / SSL
- If you are behind a managed edge such as Render, keep:
  - `ORBI_ENFORCE_HTTPS=true`
  - `ORBI_TLS_ENABLED=false`
  This relies on the platform TLS terminator plus strict HTTPS enforcement and HSTS inside the app.
- If you terminate TLS directly in Node, set:
  - `ORBI_TLS_ENABLED=true`
  - `ORBI_TLS_CERT_PATH=/path/to/fullchain.pem`
  - `ORBI_TLS_KEY_PATH=/path/to/privkey.pem`
  - optional `ORBI_TLS_CA_PATH=/path/to/ca.pem`
- In production, startup now fails if HTTPS enforcement is disabled or TLS file paths are missing while `ORBI_TLS_ENABLED=true`.
- Database/API transport is also locked down:
  - `SUPABASE_URL` must use `https://` in production
  - Redis should use `rediss://` with `REDIS_TLS_ENABLED=true`
  - direct insecure database transport is not allowed by startup validation

## Internal mTLS
- Preferred on Render:
  - `ORBI_INTERNAL_MTLS_SOURCE=proxy`
  - trusted proxy/service mesh verifies client certs
  - proxy injects `ORBI_INTERNAL_MTLS_PROXY_HEADER` with secret `ORBI_INTERNAL_MTLS_PROXY_SHARED_SECRET`
  - backend rejects spoofed mTLS headers without that attestation
- Direct end-to-end Node termination:
  - `ORBI_INTERNAL_MTLS_SOURCE=direct`
  - `ORBI_TLS_ENABLED=true`
  - `ORBI_INTERNAL_MTLS_CA_PATH=/path/to/internal-ca.pem`
  - workers must connect directly to Node and present valid client certs
  - use this only where infrastructure allows direct TLS connectivity to the service

## Database Migration Order
1. Apply core schema: `database/reset_schema.sql`
2. Apply main schema updates: `database/main.sql`
3. Validate critical RPCs exist:
   - `post_transaction_v2`
   - `append_ledger_entries_v1`
   - `claim_internal_transfer_settlement`
   - `complete_internal_transfer_settlement`
   - `repair_wallet_balance_emergency`
4. Run post-migration health checks (see below).

## Background Worker Requirements
- At least one worker process for internal settlement flows and ledger reapers.
- Worker must present:
  - `x-worker-id`
  - signed request headers
  - mTLS client cert (production)
- Worker auth is required; legacy worker auth is blocked in prod.

## Webhook Endpoints
- Provider callbacks route through:
  - `POST /api/v1/webhooks/:providerId`
- Required provider callback configuration in `financial_partners.mapping_config.callback`:
  - `reference_field`
  - `status_field`
  - `event_id_field`
  - `timestamp_header` (if freshness validation enforced)

## Rollback Guidance
- Always rollback API and worker together (they share schema assumptions).
- If rolling back schema:
  - Restore prior `main.sql` and `reset_schema.sql` snapshot
  - Verify RPC compatibility before re-enabling traffic
- For emergency rollback of a release:
  1. Disable traffic to new pods
  2. Roll back deployment image
  3. Run `/health` and `/api/admin/monitor/operational-health`
  4. Resume traffic only after DB/RPC checks pass

## Incident Recovery Basics
- Use `audit_trail` and `provider_webhook_events` for forensic reconstruction.
- For ledger drift:
  - Run reconciliation read-only checks
  - Use `repair_wallet_balance_emergency` only with incident approval
- For settlement stalls:
  - Inspect `settlement_lifecycle` stage/status
  - Re-queue via worker with proper claim and idempotency keys
- For provider webhook failures:
  - Check `provider_webhook_events` for `failed` status
  - Use replay and re-claim only via controlled worker paths

## Reconciliation Operations
- Read-only checks:
  - `reconciliation_reports` for `WALLET_DRIFT` and other mismatches
- Automated reconciliation:
  - `TransactionService.verifyWalletBalance(walletId)` for drift detection
- Privileged repair:
  - `repair_wallet_balance_emergency` only during incident windows
  - Ensure audit entry exists for every repair

## Production Readiness Checks
On startup, the app now validates:
- Required env vars for production
- Provider secret dependency consistency
- Supabase connectivity
- Critical RPC availability

If any check fails, startup exits with a fatal log.
