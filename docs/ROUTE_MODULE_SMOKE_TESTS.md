# Route Module Smoke Tests

This checklist verifies the modular route registration refactor without changing API behavior.

## Goal

Confirm that:
- all existing public paths still respond on the same URLs
- auth and admin protections still work
- upload flows still accept current client payloads
- finance and wealth routes still resolve through the extracted modules

## Top-Level And Monitoring

- `GET /`
- `GET /health`
- `GET /heath`
- `POST /api/broker/heartbeat` with valid `x-worker-secret`
- `GET /api/broker/health`
- `GET /api/admin/monitor/ledger-health` with API key
- `GET /api/admin/monitor/wallet-forensics/:walletId` with API key

## Auth And User

- `POST /v1/auth/login`
- `POST /v1/auth/refresh`
- `POST /v1/auth/logout`
- `GET /v1/auth/session`
- `GET /v1/auth/bootstrap-state` with trusted headers
- `GET /v1/auth/bootstrap-state` with untrusted headers
- `GET /v1/user/profile`
- `PATCH /v1/user/profile`
- `POST /v1/user/avatar`
- `POST /v1/user/kyc/scan`
- `POST /v1/user/kyc/upload`
- `GET /v1/user/kyc/status`
- `POST /v1/service-access/requests`
- `GET /v1/service-access/requests/my`

## Support And Admin Ops

- `GET /v1/admin/kyc/requests`
- `POST /v1/admin/kyc/review`
- `POST /v1/user/devices`
- `GET /v1/user/devices`
- `DELETE /v1/user/devices/:id`
- `POST /v1/user/documents`
- `GET /v1/user/documents`
- `DELETE /v1/user/documents/:id`
- `GET /v1/admin/documents`
- `GET /v1/admin/transactions`
- `POST /v1/admin/transactions/:id/lock`
- `POST /v1/admin/transactions/:id/audit`
- `PATCH /v1/admin/users/:id/status`

## Commerce

- `POST /v1/webhooks/:partnerId`
- `GET /v1/merchant/accounts`
- `GET /v1/merchant/wallets`
- `POST /v1/merchant/payments/preview`
- `POST /v1/merchant/payments/settle`
- `GET /v1/agent/wallets`
- `POST /v1/agent/cash/deposit/preview`
- `POST /v1/agent/cash/deposit/settle`
- `POST /v1/agent/cash/withdraw/preview`
- `POST /v1/agent/cash/withdraw/settle`
- `GET /v1/payments/bills/providers`
- `POST /v1/payments/bills/preview`
- `POST /v1/payments/bills/settle`

## Core Finance

- `GET /v1/dashboard`
- `GET /v1/wallets`
- `POST /v1/wallets`
- `POST /v1/wallets/:id/lock`
- `POST /v1/wallets/:id/unlock`
- `POST /v1/transactions/preview`
- `POST /v1/transactions/settle`
- `GET /v1/transactions`
- `GET /v1/transactions/:id/receipt`
- `GET /v1/fx/quote`
- `GET /v1/core/tenants/my`

## Engagement

- `POST /v1/chat`
- `POST /v1/chat` with attachment
- `GET /v1/insights`
- `POST /v1/receipt/scan`
- `GET /v1/notifications`
- `PATCH /v1/notifications/:id/read`
- `PATCH /v1/notifications/read-all`
- `DELETE /v1/notifications/:id`

## Strategy

- `GET /v1/goals`
- `POST /v1/goals`
- `PATCH /v1/goals/:id`
- `DELETE /v1/goals/:id`
- `GET /v1/categories`
- `POST /v1/categories`
- `GET /v1/tasks`
- `POST /v1/tasks`
- `POST /v1/goals/:id/allocate`
- `POST /v1/goals/:id/withdraw`
- `POST /v1/goals/auto-allocate/replay`

## Operations

- `GET /v1/enterprise/organizations`
- `POST /v1/enterprise/organizations`
- `GET /v1/escrow`
- `POST /v1/escrow/create`
- `POST /v1/admin/reconciliation/run`
- `GET /v1/admin/reconciliation/reports`
- `GET /v1/admin/config/ledger`
- `POST /v1/admin/config/fx-rates`
- `GET /v1/admin/kms/health`
- `POST /v1/admin/kms/diagnose`
- `GET /v1/sys/bootstrap`
- `GET /v1/sys/metrics`
- `POST /v1/transactions/secure-sign`

## Wealth

- `GET /v1/wealth/summary`
- `GET /v1/wealth/bill-reserves`
- `POST /v1/wealth/bill-reserves`
- `PATCH /v1/wealth/bill-reserves/:id`
- `GET /v1/wealth/shared-pots`
- `POST /v1/wealth/shared-pots`
- `POST /v1/wealth/shared-pots/:id/invitations`
- `POST /v1/wealth/shared-pot-invitations/:id/respond`
- `POST /v1/wealth/shared-pots/:id/contribute`
- `POST /v1/wealth/shared-pots/:id/withdraw`
- `GET /v1/wealth/shared-budgets`
- `POST /v1/wealth/shared-budgets`
- `POST /v1/wealth/shared-budgets/:id/invitations`
- `POST /v1/wealth/shared-budget-invitations/:id/respond`
- `GET /v1/wealth/shared-budgets/:id/approvals`
- `POST /v1/wealth/shared-budget-approvals/:id/respond`
- `POST /v1/wealth/shared-budgets/:id/spend/preview`
- `POST /v1/wealth/shared-budgets/:id/spend/settle`
- `GET /v1/wealth/allocation-rules`
- `POST /v1/wealth/allocation-rules`

## Final Verification

- confirm `/v1`, `/api/v1`, and legacy root mounting still resolve correctly where expected
- confirm auth-protected routes still reject missing tokens
- confirm admin routes still reject non-admin users
- confirm uploads work with current multipart field names
- confirm no route path changed during extraction
