# Internal Transfer Settlement Lifecycle

This document describes the enterprise-standard settlement path for internal transfers that stage funds in the PaySafe/internal transfer vault before final release.

## Design goals

- ledger remains the financial source of truth
- settlement is idempotent
- settlement does not depend on ledger description text matching
- settlement verifies transaction state under lock before append
- settlement is safe under concurrent workers
- zero-sum verification remains mandatory after append
- PaySafe/internal vault design remains unchanged

## Settlement model

Internal transfers settle in two phases:

1. `post_transaction_v2` records the initial staged transfer and leaves the transaction in `processing`
2. settlement appends the release legs from the internal transfer vault to the target operating wallet

The settlement path uses two durable markers:

- lifecycle key: `INTERNAL_TRANSFER:<txId>:PAYSAFE_SETTLEMENT`
- append key: `settlement:<txId>:paysafe_release:v2`

These markers are authoritative. Workers must not infer settlement completion from ledger descriptions.

## Claim phase

Workers call:

- `public.claim_internal_transfer_settlement(tx_id, worker_id, worker_claim_id)`

The SQL function:

- locks the `transactions` row with `FOR UPDATE`
- creates or reuses the settlement lifecycle row
- verifies the transaction is still `processing`
- checks whether the append marker already exists
- records the active worker claim id in lifecycle metadata
- rejects stale concurrent workers with `CONCURRENCY_CONFLICT`

## Append phase

After claim succeeds, the backend appends the PaySafe release legs using:

- append phase: `PAYSAFE_SETTLEMENT`
- append key: `settlement:<txId>:paysafe_release:v2`

If the append marker already exists, the backend treats the append as already applied instead of replaying the financial mutation.

## Verification phase

After append, the backend runs zero-sum verification.

- valid zero-sum: finalize settlement to `completed`
- invalid zero-sum: move the transaction to `held_for_review`

## Finalize phase

Workers finalize through:

- `public.complete_internal_transfer_settlement(tx_id, worker_claim_id, result, note, zero_sum_valid)`

The SQL function:

- re-locks transaction and lifecycle rows
- verifies the worker still owns the active claim
- finalizes the transaction status under lock
- updates lifecycle stage/status
- records durable completion metadata

## Allowed status transitions

- `processing -> completed`
- `processing -> held_for_review`

Settlement workers must not force other transitions. Any invalid or stale state is treated as `INVALID_SETTLEMENT_STATE`.

## Worker contract

Internal worker callers should provide:

- `x-worker-id`

The backend passes that identity into the claim step so lifecycle metadata shows which worker owned the settlement attempt.

Conflict outcomes are expected:

- `CONCURRENCY_CONFLICT` means another worker already owns the active settlement claim
- `INVALID_SETTLEMENT_STATE` means the transaction or lifecycle is no longer eligible

Both should be handled as controlled worker outcomes, not silent retries with new semantics.
