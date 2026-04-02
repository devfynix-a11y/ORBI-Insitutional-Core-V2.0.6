# ORBI Security Attack Simulation Plan

## Goal
This plan validates that ORBI rejects, contains, or auditable-detects common defensive security failure modes without using offensive exploit payloads.

The review was performed on April 2, 2026 against the local ORBI repository after inspecting the current code and test suite.

## Prioritized Findings
1. High - User session theft and refresh-token replay defenses exist in `iam/authService.ts`, but coverage is mostly source-level and still needs live environment validation against Supabase token rotation behavior.
2. High - Privileged admin misuse controls exist in route authorization, SQL/RLS, and repair tooling, but there is still limited end-to-end automated proof that every privileged route is consistently denied for non-admin sessions.
3. Medium - Brute-force protection existed in code but had limited direct test coverage before this pass; automated lock/escalation coverage has now been added.
4. Medium - Malformed payload rejection existed broadly via Zod middleware, but direct middleware regression coverage was thin before this pass; automated validation tests have now been added.
5. Medium - Silent wallet-balance tampering has strong reconciliation and repair instrumentation, but it still requires manual DB-backed validation because the most meaningful evidence comes from reconciliation tables and privileged repair paths.
6. Medium - Dependency and supply-chain checks rely on operational process (`npm audit`, lockfile review, secret scanning, CI discipline) more than application code, so this remains partly manual by design.

## Existing Coverage Map

### 1. Stolen or Replayed Auth Token
- Existing controls:
  - `iam/authService.ts`
  - Refresh token rotation via `replaced_by`
  - Reuse detection with `revokeSessionChain(...)`
  - Device-fingerprint mismatch revokes session chains
  - Logout revokes persisted sessions
- Existing tests:
  - `tests/authorizationHelpers.test.ts`
    - internal signed request replay protection
- Added in this pass:
  - `tests/authDefensiveControls.test.ts`
    - source-level regression coverage for refresh token rotation, replay detection, and revocation markers
- Remaining manual validation:
  - real refresh-token reuse attempt across devices/sessions against a live Supabase-backed environment
  - access-token revocation timing after `logout`

### 2. Brute-Force Login or PIN Attempts
- Existing controls:
  - `backend/src/services/bruteForce.service.ts`
  - `backend/src/modules/auth/auth.controller.ts`
  - `backend/security/waf.ts`
- Existing tests:
  - none specific before this pass
- Added in this pass:
  - `tests/authDefensiveControls.test.ts`
    - brute-force lock and 24h escalation
    - PIN failed-attempt lockout markers
  - `tests/securityMiddlewareDefense.test.ts`
    - WAF login-rate-limit enforcement
- Remaining manual validation:
  - end-to-end login route lockout UX and unlock timing
  - distributed Redis behavior under multi-instance load

### 3. Malformed API Payloads
- Existing controls:
  - `src/middleware/validation/validate.ts`
  - `backend/middleware/validation.ts`
  - Zod schemas in `backend/security/schemas.ts`
- Existing tests:
  - indirect schema usage across route tests
- Added in this pass:
  - `tests/securityMiddlewareDefense.test.ts`
    - malformed login payload rejection
    - valid payment payload acceptance
- Remaining manual validation:
  - route-level contract checks for multipart/form-data and file upload endpoints

### 4. Privilege Bypass Attempts
- Existing controls:
  - `src/middleware/auth/authorization.ts`
  - `src/middleware/auth/sessionAuth.ts`
  - `database/main.sql` RLS policies
  - admin route `requireSessionPermission(...)`
- Existing tests:
  - `tests/authorizationHelpers.test.ts`
    - scope, role, org-role, internal worker authorization, replay block
- Remaining manual validation:
  - non-admin calls to every `/admin/*` route in a live environment
  - service-role and RLS interaction review for sensitive SQL tables

### 5. Duplicate Transaction Replay
- Existing controls:
  - `database/main.sql`
    - `post_transaction_v2`
    - `IDEMPOTENCY_VIOLATION`
  - `backend/enterprise/infrastructure/IdempotencyLayer.ts`
- Existing tests:
  - `tests/financialCoreCoverage.test.ts`
  - `tests/financialAuthority.test.ts`
  - `tests/sqlFinancialAuthority.test.ts`
- Remaining manual validation:
  - client retry behavior with repeated `x-idempotency-key`
  - provider retry path on network timeout

### 6. Concurrent Double Debit
- Existing controls:
  - `database/main.sql`
    - row locks
    - SQL-authoritative balance updates
    - insufficient-funds checks
  - `backend/ledger/financialInvariants.ts`
- Existing tests:
  - `tests/financialAuthority.test.ts`
  - `tests/sqlFinancialAuthority.test.ts`
  - `tests/internalSettlementFlow.test.ts`
  - `tests/financialCoreCoverage.test.ts`
- Remaining manual validation:
  - parallel settlement/transfer requests against a writable DB
  - serialization-failure retry behavior under real concurrency

### 7. Duplicate Settlement Append
- Existing controls:
  - `database/main.sql`
    - `append_ledger_entries_v1`
    - `ledger_append_markers`
    - `claim_internal_transfer_settlement`
    - `complete_internal_transfer_settlement`
  - `backend/ledger/transactionEngine.ts`
- Existing tests:
  - `tests/internalSettlementFlow.test.ts`
  - `tests/financialCoreCoverage.test.ts`
  - `tests/sqlFinancialAuthority.test.ts`
- Remaining manual validation:
  - repeated worker retries across separate worker processes

### 8. Invalid or Replayed Provider Webhook
- Existing controls:
  - `backend/payments/WebhookVerificationService.ts`
  - `backend/payments/ProviderWebhookEventLedger.ts`
  - `backend/payments/webhookHandler.ts`
  - `database/main.sql`
    - `provider_webhook_events`
    - partner/provider dedupe index
- Existing tests:
  - `tests/webhookVerification.test.ts`
  - `tests/providerWebhookEventLedger.test.ts`
  - `tests/financialCoreCoverage.test.ts`
  - `tests/providerActivationGuard.test.ts`
- Remaining manual validation:
  - provider-specific signature canonicalization in staging
  - exact replay windows with real provider timestamp headers

### 9. Silent Wallet Balance Tampering
- Existing controls:
  - `ledger/transactionService.ts`
    - wallet drift verification
    - explicit privileged repair RPC path
  - `database/main.sql`
    - `repair_wallet_balance_emergency`
    - reconciliation reporting tables
- Existing tests:
  - `tests/financialCoreCoverage.test.ts`
    - drift reporting and privileged repair markers
- Remaining manual validation:
  - write-path tamper simulation in a DB clone
  - reconciliation alerting and audit review after manual drift introduction

### 10. Privileged Admin Misuse
- Existing controls:
  - `src/routes/public/adminOps.ts`
  - `src/middleware/auth/sessionAuth.ts`
  - `database/main.sql`
    - RLS policies
    - explicit privileged repair restrictions
- Existing tests:
  - `tests/authorizationHelpers.test.ts`
  - `tests/financialCoreCoverage.test.ts`
- Added in this pass:
  - `tests/authDefensiveControls.test.ts`
    - repair and session-revocation control presence remains guarded by regression checks
- Remaining manual validation:
  - privileged route inventory review
  - approval/audit/reversal separation-of-duties verification
  - emergency repair workflow sign-off and evidence collection

### 11. Dependency / Supply-Chain Risk Checks
- Existing controls:
  - `package.json`
    - `overrides`
  - lockfile-managed dependency pinning
- Existing tests:
  - none meaningful in code
- Remaining manual validation:
  - `npm audit --omit=dev`
  - lockfile diff review before release
  - secret scanning
  - verify GitHub branch protections / CI required checks
  - provenance review for newly added packages

## Tests Added
- `tests/authDefensiveControls.test.ts`
  - refresh-token replay/rotation regression markers
  - PIN lockout regression markers
  - brute-force lock and escalation behavior
- `tests/securityMiddlewareDefense.test.ts`
  - malformed login payload rejection
  - valid payment payload acceptance
  - WAF oversized-payload rejection
  - WAF login rate-limit enforcement and audit logging

## Manual Validation Steps

### Token Replay / Theft
1. Login normally and capture a valid refresh token in a controlled staging environment.
2. Refresh once successfully.
3. Reuse the old refresh token again from the same device.
4. Confirm refresh is rejected and existing sessions are revoked.
5. Retry with a mismatched device fingerprint and confirm session-chain revocation.

### Brute Force
1. Repeatedly submit invalid password attempts for the same user until lockout.
2. Confirm the response becomes a lock signal rather than a normal invalid-credential signal.
3. Repeat after the first lock cycle and verify escalation behavior.
4. Repeat the same flow for PIN login on a trusted device.

### Malformed Payloads
1. Send structurally invalid payloads to login, payment preview, payment settle, and wallet routes.
2. Confirm responses are `400` with `VALIDATION_FAILED`.
3. Confirm no transaction, ledger, or audit side effects are created for rejected payloads.

### Privilege Bypass
1. Call representative `/admin/*` routes with:
   - no token
   - consumer token
   - staff token without required permission
2. Confirm `401` or `403` responses.
3. Verify no protected records are mutated.

### Duplicate Replay / Double Debit
1. Submit the same payment request twice with the same idempotency key.
2. Confirm the second request is rejected or returns the previously registered result.
3. In a writable staging DB, launch two concurrent debit requests against the same wallet with insufficient balance for both.
4. Confirm only one can succeed and the wallet does not go negative.

### Duplicate Settlement Append
1. Re-run the same internal settlement worker action twice for the same transaction.
2. Confirm append markers prevent duplicate ledger mutation.
3. Confirm completion remains idempotent and auditable.

### Webhook Replay / Invalid Webhook
1. Resend a previously processed webhook event with the same provider event id / dedupe key.
2. Confirm it is ignored or replay-gated safely.
3. Send a webhook with missing or invalid signature metadata.
4. Confirm it is rejected and recorded in `provider_webhook_events`.

### Silent Balance Tampering
1. In a non-production DB clone, manually change a wallet balance without matching ledger entries.
2. Run reconciliation.
3. Confirm drift is detected, recorded, and not silently normalized.
4. Verify privileged repair requires explicit actor and reason evidence.

### Privileged Admin Misuse
1. Attempt privileged repair, reversal, and staff-management actions with accounts that are:
   - consumer
   - low-privilege staff
   - approved admin
2. Confirm least-privilege boundaries hold.
3. Confirm successful admin actions create audit evidence.

### Dependency / Supply Chain
1. Run `npm audit --omit=dev`.
2. Review `package-lock.json` diff for any unexpected transitive changes.
3. Scan for leaked secrets in repo history and current tree.
4. Verify CI, branch protection, and release-signoff checks are enabled.

## Gaps Requiring Manual Review
- Live Supabase refresh-token replay behavior and logout propagation timing
- End-to-end admin misuse and separation-of-duties validation
- Writable DB concurrency testing for double-debit and settlement-worker races
- Real provider webhook signature canonicalization in staging
- Silent balance tampering detection against a DB clone
- Dependency provenance, CI enforcement, and secret-scanning process checks
