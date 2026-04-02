# Financial Core Testing Plan

## Current Test Stack
The backend already uses:
- `node:test`
- `node:assert/strict`
- `tsx --test`

That is a workable lightweight stack, so this plan keeps the current style instead of introducing a new framework.

## Testing Strategy
Use a layered approach:
1. `Contract / source assertions`
   - Verify that critical financial flows still call the SQL-authoritative functions and preserve guardrails.
   - Best for settlement locking, idempotency wiring, and append-only behavior.
2. `Focused unit tests`
   - Verify domain error normalization and orchestration behavior without needing a live database.
   - Best for insufficient funds, wallet lock behavior, and state eligibility.
3. `Stubbed integration tests`
   - Use narrow in-memory stubs for services like operational health or provider helpers where realistic behavior can be isolated safely.
4. `DB-backed integration scaffold`
   - Added as env-gated, read-only by default.
   - Verifies service-role access to financial tables and live exception counters without mutating production-like data.
5. `Write-enabled DB integration tests`
   - Added as env-gated and fixture-gated.
   - Only for isolated, disposable, non-production financial test environments.

## Current Foundation
Implemented now:
- `tests/financialAuthority.test.ts`
- `tests/financialInvariants.test.ts`
- `tests/sqlFinancialAuthority.test.ts`
- `tests/internalSettlementFlow.test.ts`
- `tests/financialCoreCoverage.test.ts`
- `tests/financialCoreDbIntegration.test.ts`
- `tests/financialCoreDbMutation.test.ts`
- `tests/providerWebhookEventLedger.test.ts`
- `tests/helpers/dbIntegration.ts`

Optional DB-backed runners:
- `npm run test:db:financial`
- `npm run test:db:financial:write`

Helper assets:
- `.env.test.example`
- `tests/helpers/validateDbIntegrationEnv.ts`

## Read-Only DB Integration Mode
Enable with:
- `ORBI_RUN_DB_INTEGRATION=true`
- `SUPABASE_URL=...`
- `SUPABASE_SERVICE_ROLE_KEY=...`

The `npm run test:db:financial` script now fails fast if these env vars are missing or invalid.

This mode safely verifies:
- core financial table reachability
- live `held_for_review` counts
- live reconciliation mismatch / wallet drift counts
- live failed webhook counts
- live settlement backlog-by-phase counts

## Write-Enabled DB Integration Mode
Enable only in an isolated environment with:
- `ORBI_RUN_DB_INTEGRATION=true`
- `ORBI_DB_INTEGRATION_ALLOW_WRITES=true`
- `SUPABASE_URL=...`
- `SUPABASE_SERVICE_ROLE_KEY=...`
- `ORBI_DB_TEST_USER_ID=...`
- `ORBI_DB_TEST_SOURCE_WALLET_ID=...`
- `ORBI_DB_TEST_TARGET_WALLET_ID=...`
- `ORBI_DB_TEST_INTERNAL_TRANSFER_VAULT_ID=...`
- `ORBI_DB_TEST_LOW_BALANCE_WALLET_ID=...`
- `ORBI_DB_TEST_LOCKED_WALLET_ID=...`
- `ORBI_DB_TEST_REVIEW_ACTOR_ID=...`
- `ORBI_DB_TEST_DRIFT_WALLET_ID=...`
- `ORBI_DB_TEST_WEBHOOK_PARTNER_ID=...`
- `ORBI_DB_TEST_OPERATING_VAULT_ID=...`
- `ORBI_DB_TEST_ESCROW_VAULT_ID=...`
- `ORBI_DB_TEST_BUDGET_CATEGORY_ID=...`
- `ORBI_DB_TEST_BUDGET_TRIGGER_AMOUNT=...`
- `ORBI_DB_TEST_WITHDRAWAL_PROVIDER_ID=...`
- optional: `ORBI_DB_TEST_AMOUNT=0.01`
- optional: `ORBI_DB_TEST_INSUFFICIENT_AMOUNT=999999`

The `npm run test:db:financial:write` script now validates these env vars up front and fails fast instead of silently starting with an invalid fixture set.

This mode now covers:
- transaction posting through `post_transaction_v2`
- insufficient-funds rejection against disposable low-balance fixtures
- locked-wallet rejection against dedicated locked fixtures
- append idempotency through `append_ledger_entries_v1`
- internal transfer settlement claim/finalize flow
- duplicate settlement prevention after completion
- signed provider webhook callback application against a disposable provider fixture
- deposit into operating wallet
- external withdrawal initiation
- reversal execution on disposable posted transactions
- `held_for_review` approval lifecycle
- `held_for_review` rejection + reversal lifecycle
- privileged repair on a disposable drift wallet
- provider webhook receipt dedupe + single application claim behavior
- zero-sum invalid settlement completion forced into `held_for_review`
- auto-reversal after a forced overdue review window
- reconciliation incident drill coverage for drift evidence + repair audits
- shared budget spend enforcement
- bill reserve allocation via escrow vault

## Priority Coverage

### 1. Transaction Posting
Goal:
- Ensure posting still routes through SQL-authoritative `post_transaction_v2`.
- Ensure service layer normalizes DB failures instead of trusting app-computed balances.

Current coverage:
- `tests/sqlFinancialAuthority.test.ts`
- `tests/financialCoreCoverage.test.ts`
- `tests/financialCoreDbMutation.test.ts`

### 2. Insufficient Funds
Goal:
- Ensure SQL insufficient-funds failures map to stable domain errors.

Current coverage:
- `tests/financialAuthority.test.ts`
- `tests/sqlFinancialAuthority.test.ts`
- `tests/financialCoreDbMutation.test.ts`

### 3. Idempotency
Goal:
- Ensure posting and append flows preserve SQL idempotency enforcement.
- Ensure duplicate appends / duplicate webhook applications are blocked.

Current coverage:
- `tests/sqlFinancialAuthority.test.ts`
- `tests/financialCoreCoverage.test.ts`
- `tests/financialCoreDbMutation.test.ts`

### 4. Duplicate Settlement Prevention
Goal:
- Ensure settlement uses durable append markers and locked lifecycle claims.

Current coverage:
- `tests/internalSettlementFlow.test.ts`
- `tests/financialCoreCoverage.test.ts`
- `tests/financialCoreDbMutation.test.ts`

### 5. Reversal Flows
Goal:
- Ensure reversals remain eligibility-gated, append compensating legs, and persist reversal metadata.

Current coverage:
- `tests/financialInvariants.test.ts`
- `tests/financialCoreCoverage.test.ts`
- `tests/financialCoreDbMutation.test.ts`

### 6. Wallet Lock Behavior
Goal:
- Ensure locked wallets become stable domain errors and remain enforced by SQL / service boundaries.

Current coverage:
- `tests/financialAuthority.test.ts`
- `tests/sqlFinancialAuthority.test.ts`
- `tests/financialCoreCoverage.test.ts`
- `tests/financialCoreDbMutation.test.ts`

### 7. Held For Review Flows
Goal:
- Ensure review locks, audit pass requirements, approval, and timed auto-reversal remain explicit and testable.

Current coverage:
- `tests/internalSettlementFlow.test.ts`
- `tests/financialCoreCoverage.test.ts`
- `tests/financialCoreDbIntegration.test.ts` (live read-only counters)
- `tests/financialCoreDbMutation.test.ts`

### 8. Provider Webhook Deduplication
Goal:
- Ensure webhook receipts are deduplicated before application and only one application claim proceeds.

Current coverage:
- `tests/financialCoreCoverage.test.ts`
- `tests/financialCoreDbIntegration.test.ts` (live failed/rejected webhook counter reads)
- `tests/financialCoreDbMutation.test.ts`
- `tests/providerWebhookEventLedger.test.ts`

### 9. Balance Reconciliation
Goal:
- Ensure wallet drift detection records reconciliation evidence and privileged repair remains explicit.

Current coverage:
- `tests/operationalHealthService.test.ts`
- `tests/financialCoreCoverage.test.ts`
- `tests/financialCoreDbIntegration.test.ts` (live mismatch/drift counter reads)
- `tests/financialCoreDbMutation.test.ts`

## Next Recommended Phase
For even stronger enterprise confidence, the next step should be dedicated disposable-fixture integration coverage for:
- provider-failure replay flows after an initial failed application through the full webhook handler
- cross-wallet settlement rollback drills after downstream append failure
- external movement webhook application against deposit-intent and movement routing branches
- database-seeded alerting assertions for reconciliation mismatch escalation

Those tests should remain isolated to disposable infrastructure and never run against shared production-connected environments.
