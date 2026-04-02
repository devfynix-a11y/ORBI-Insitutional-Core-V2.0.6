# Audit Trail Model

## Authoritative audit surfaces

For production-critical investigations, the backend should rely on these tables together:

- `audit_trail`: immutable signed forensic audit ledger for privileged, financial, security, admin, and webhook application events
- `transaction_events`: transaction state transition history
- `financial_events`: domain event trail for financial mutations and purpose lifecycle changes
- `settlement_lifecycle`: current settlement state plus structured failure metadata
- `provider_webhook_events`: inbound webhook receipt, verification, dedupe, and application ledger
- `item_reconciliation_audit`: reconciliation-specific findings

## Sufficiency review

The current model is sufficient for enterprise auditability **if these tables are used consistently**.

What was insufficient before this pass:

- settlement lifecycle transitions were not consistently mirrored into `audit_trail`
- settlement failure recording was not consistently mirrored into `audit_trail`
- webhook application failures were not explicitly written to `audit_trail`
- privileged repair service-layer intent lacked a strong explicit audit action name and reason linkage
- transaction status changes relied mainly on `transaction_events` without a corresponding immutable audit entry

## Legacy table

`audit_logs` is legacy and should not be treated as authoritative for production-critical flows.

## Practical investigation path

### Financial events

Use:
- `transactions`
- `financial_ledger`
- `transaction_events`
- `financial_events`
- `audit_trail`

### Privileged repairs

Use:
- `audit_trail` with action `PRIVILEGED_WALLET_BALANCE_REPAIR_EXECUTED`
- SQL-side `repair_wallet_balance_emergency` audit records in `audit_trail`

### Settlement investigations

Use:
- `settlement_lifecycle`
- `audit_trail` actions starting with `SETTLEMENT_`
- `transaction_events`
- `financial_events`

### Provider webhook investigations

Use:
- `provider_webhook_events`
- `audit_trail` actions `WEBHOOK_*`
- `external_fund_movements`
- `transactions`

## Design note

The goal is not one giant audit table. The goal is a layered model where:
- `audit_trail` is immutable forensic evidence
- `transaction_events` and `financial_events` are domain history
- `provider_webhook_events` is inbound provider evidence
- `settlement_lifecycle` is operational settlement truth
