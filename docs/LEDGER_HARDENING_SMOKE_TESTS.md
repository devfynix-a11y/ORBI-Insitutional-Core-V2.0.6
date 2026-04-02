# Ledger Hardening Smoke Tests

This checklist validates the deterministic SQL ledger rewrite now in place for:
- `post_transaction_v2`
- `append_ledger_entries_v1`
- goal-backed ledger legs
- shared atomic financial mutation paths already added earlier

## Preconditions
- Latest schema applied from `database/main.sql` or `database/reset_schema.sql`
- Test environment has valid internal wallets/vaults/goals
- `transactions.reference_id` uniqueness is active
- Service-role DB execution path is working

## Core Transaction Posting
1. Post a normal wallet-to-wallet transfer.
- Expect one `transactions` row.
- Expect balanced `financial_ledger` legs.
- Expect cached balances on both internal entities to match SQL-computed ledger result.

2. Post a wallet-to-vault transfer.
- Expect vault balance update from SQL-computed values only.
- Expect no trust in incoming `balance_after`.

3. Post a wallet-to-goal allocation.
- Expect `goals.current` to update inside SQL.
- Expect no separate app-side goal current mutation.

4. Post a goal-to-wallet withdrawal.
- Expect `goals.current` decrement inside SQL.
- Expect destination wallet increment inside SQL.

## Negative / Integrity Checks
5. Attempt an internal debit that exceeds available funds.
- Expect full rollback.
- Expect no `transactions` row left behind.
- Expect no ledger legs inserted.

6. Attempt a transaction with unbalanced legs.
- Expect `LEDGER_OUT_OF_BALANCE`.
- Expect full rollback.

7. Attempt a transaction with duplicate `reference_id`.
- Expect DB rejection / idempotency violation.
- Expect original transaction preserved.

8. Attempt a transaction against a locked wallet or locked vault.
- Expect `WALLET_LOCKED` style failure.
- Expect no partial writes.

9. Attempt a leg with encrypted `amount` but missing `amount_plain`.
- Expect `LEG_AMOUNT_REQUIRED`.

## Append Ledger Legs
10. Append balanced fee legs to an existing transaction.
- Expect appended ledger entries.
- Expect balances recomputed in SQL.

11. Attempt unbalanced append legs.
- Expect rejection.
- Expect no appended ledger rows.

12. Attempt append against a locked internal entity.
- Expect rejection.
- Expect no appended ledger rows.

## Concurrency
13. Run two simultaneous debits against the same wallet with total amount greater than balance.
- Expect only one to succeed.
- Expect the other to fail cleanly.
- Expect no negative cached balance.

14. Run concurrent goal allocate + goal withdraw on the same goal.
- Expect serialization via row locking.
- Expect final `goals.current` to match ledger-derived result.

15. Run concurrent append operations touching the same wallet.
- Expect serialized row locking.
- Expect no cached/ledger drift.

## Reconciliation Checks
16. After the above tests, verify drift using reconciliation or balance verification helpers.
- `wallets.balance` must match ledger sum.
- `platform_vaults.balance` must match ledger sum.
- `goals.current` must match ledger sum for goal-backed flows.

## Legacy Helper Safety
17. Exercise `update_wallet_balance(...)` only in controlled admin/test flow.
- Confirm locked entities are rejected.
- Confirm goal updates route through the function safely.
- Do not use it as a normal financial mutation primitive.

## Observability
18. Watch backend logs for:
- `LEDGER_OUT_OF_BALANCE`
- `INSUFFICIENT_FUNDS`
- `IDEMPOTENCY_VIOLATION`
- `LEG_AMOUNT_REQUIRED`
- `WALLET_LOCKED`
- any atomic-RPC fallback warnings from earlier wealth/card hardening work

## Sign-off Criteria
- No partial writes under failure cases
- No negative internal balances unless business rules explicitly allow them
- No ledger/cache drift after concurrent tests
- Goal balances are updated exactly once per committed ledger flow
- Duplicate references do not create duplicate transactions
