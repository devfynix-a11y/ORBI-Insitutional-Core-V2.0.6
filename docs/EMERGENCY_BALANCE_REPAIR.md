# Emergency Balance Repair

`public.repair_wallet_balance_emergency(...)` is now a privileged reconciliation tool, not a normal wallet operation API.

## Allowed Use

- emergency incident repair after independent ledger truth has been verified
- auditor-approved reconciliation of a corrupted cached balance
- controlled back-office repair during postmortem recovery or regulated operations support

## Not Allowed

- normal payment flows
- transfer posting
- settlement processing
- wealth/goals allocation flows
- UI-driven balance edits
- convenience balance fixes when the ledger entry path is available

## Required Inputs

- `target_wallet_id`
- `new_balance`
- `new_encrypted`
- `repair_actor_id`
- `repair_reason`

The function now rejects calls without a repair actor and human-readable reason.

## Safety Guarantees

- restricted to privileged callers only
- writes an `EMERGENCY_BALANCE_REPAIR` record to `public.audit_trail`
- returns the entity type plus before/after balances so the mutation is not silent
- raises on missing or locked entities instead of failing quietly

## Operational Rule

Call this only when ledger-derived correction is temporarily impossible and the repair has been approved by finance, audit, or incident command. Every invocation must map to an incident ticket, reconciliation case, or auditor directive referenced in `repair_reason`.

## App Review

A repository search found one backend maintenance helper using the repair RPC, plus schema/docs references. The app should not expose this directly to normal financial flow or customer-facing paths. If balance repair is needed operationally, keep it behind a dedicated privileged admin/reconciliation path with explicit incident approval controls.
