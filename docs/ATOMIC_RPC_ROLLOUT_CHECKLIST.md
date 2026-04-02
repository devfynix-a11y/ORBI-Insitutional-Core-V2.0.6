# Atomic RPC Rollout Checklist

This checklist covers the new DB-owned atomic mutation paths introduced to reduce direct multi-write financial mutations from route/provider code.

## Included RPCs

- `shared_pot_contribute_v1`
- `shared_pot_withdraw_v1`
- `card_settle_v1`
- `bill_reserve_adjust_v1`

## Rollout Order

1. Apply SQL to test/staging database
2. Restart backend with the updated code
3. Run smoke tests against each affected flow
4. Verify ledger, transaction, and balance side effects
5. Repeat in production during a controlled window

## Preconditions

- `SYSTEM_FEE_WALLET_ID` points to a real internal wallet or platform vault UUID
- service-role / admin Supabase credentials are present
- DB schema is applied from both:
  - `database/reset_schema.sql`
  - `database/main.sql`

## Shared Pot Checks

### Contribute

1. Create or select an active shared pot
2. Contribute from a funded wallet
3. Verify:
   - transaction row created
   - shared pot balance increased
   - source wallet/vault balance decreased
   - ledger rows written
   - response succeeds

### Withdraw

1. Withdraw from a funded shared pot to a valid wallet
2. Verify:
   - transaction row created
   - shared pot balance decreased
   - target wallet/vault balance increased
   - ledger rows written
   - member contribution metadata updated

### Failure Cases

1. insufficient source funds
2. insufficient pot funds
3. invalid wallet id
4. invalid pot id
5. repeat request / retry behavior

## Card Settlement Checks

1. Authorize a card transaction
2. Settle into a valid target wallet
3. Verify:
   - `card_transactions.status = SETTLED`
   - transaction row created
   - target wallet credited
   - fee wallet/vault credited
   - ledger rows written
4. Re-run the same settlement and confirm it is rejected

### Failure Cases

1. missing `SYSTEM_FEE_WALLET_ID`
2. nonexistent fee wallet/vault id
3. settle non-authorized card transaction
4. settle nonexistent card transaction

## Bill Reserve Checks

### Create With Locked Funds

1. Create reserve with fixed amount and valid source wallet
2. Verify:
   - transaction row created
   - source balance reduced
   - reserve `locked_balance` updated
   - two ledger rows written

### Update / Top-up / Release

1. Increase reserve amount
2. Decrease reserve amount
3. Pause/archive if applicable
4. Verify:
   - reserve `locked_balance` matches desired amount
   - source balance moves correctly
   - transaction row created
   - ledger rows written

### Delete With Locked Funds

1. Delete reserve with non-zero locked balance
2. Verify:
   - source funds are released first
   - transaction row created
   - ledger rows written
   - reserve deleted

## Fallback Verification

Before DB migration is applied, confirm backend still works through the legacy fallback path for:

- shared pot contribute
- shared pot withdraw
- card settlement
- bill reserve adjustment

After DB migration is applied, repeat and confirm behavior remains correct.

## Observability

For each tested flow, inspect:

- `transactions`
- `financial_ledger`
- `wallets`
- `platform_vaults`
- `shared_pots`
- `shared_pot_members`
- `bill_reserves`
- `card_transactions`

## Sign-off

Do not consider rollout complete until:

1. functional checks pass
2. ledger side effects match balances
3. duplicate/retry behavior is understood
4. no unexpected fallback-only errors appear in backend logs
