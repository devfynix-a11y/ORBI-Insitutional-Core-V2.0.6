# KMS And Encryption Model

## Purpose

This document describes the backend crypto boundary model after the KMS/encryption hardening refactor.

The goal is to keep financial behavior unchanged while making cryptographic intent explicit:

- data encryption is not token signing
- audit signing is not JWT signing
- provider secret wrapping is not the same thing as general field encryption
- financial amount and description protection are explicit hot-path use cases

## Current Boundary Model

### 1. Data encryption

Primary modules:

- `backend/security/CryptoEnvelope.ts`
- `backend/security/DataProtection.ts`
- compatibility wrapper: `backend/security/encryption.ts`

Use this boundary for:

- financial amounts at rest
- financial descriptions at rest
- general sensitive persisted values
- message content encryption

Important notes:

- AES-GCM remains the at-rest encryption primitive
- KMS key type remains `ENCRYPTION`
- envelope context now includes a crypto domain such as:
  - `DATA_AT_REST`
  - `FINANCIAL_AMOUNT`
  - `FINANCIAL_DESCRIPTION`
  - `PROVIDER_SECRET`
  - `PROVIDER_TOKEN`
  - `MESSAGE_CONTENT`

### 2. Signing

Primary module:

- `backend/security/SignatureService.ts`

Use this boundary for:

- audit log signing
- other integrity signatures that are not auth tokens

Important notes:

- this uses KMS `SIGNING`
- audit signing is no longer implemented directly inside the audit service

### 3. Auth tokens

Primary module:

- `backend/security/AuthTokenCrypto.ts`

Use this boundary for:

- JWT/session token signing and verification

Important notes:

- this uses KMS `AUTH`
- auth token signing is intentionally separated from audit signing

### 4. Provider secret wrapping

Primary module:

- `backend/payments/providers/ProviderSecretVault.ts`

Use this boundary for:

- `client_secret`
- `connection_secret`
- `webhook_secret`
- `token_cache`
- provider API keys/access tokens

Important notes:

- provider credentials should not be decrypted through broad recursive translation paths when a specific secret lookup is enough
- provider token cache is now explicitly treated as provider token material, not generic app data

## Hot Path Guidance

### Financial hot paths

For ledger and balance-sensitive flows, prefer:

- `DataProtection.encryptAmount(...)`
- `DataProtection.decryptAmount(...)`
- `DataProtection.encryptDescription(...)`
- `DataProtection.decryptDescription(...)`

Why:

- it makes amount/description handling explicit
- it avoids silent string/number drift in sensitive financial code
- it makes future optimizations and telemetry easier

### Compatibility path

`DataVault` still exists for backward compatibility and legacy code. New code should prefer narrower boundaries over generic `DataVault.encrypt/decrypt` where practical.

## Failure Handling

### Encryption/decryption failures

Current behavior:

- low-level crypto failures throw `CryptoBoundaryError`
- compatibility `DataVault.decrypt(...)` still preserves legacy sentinel behavior:
  - `INTEGRITY_FAIL`
  - `HEALING_REQUIRED`

Why both exist:

- newer code can fail with typed crypto errors
- legacy flows can keep current operational behavior until migrated

### Provider secret failures

Provider secret resolution now:

- unwraps only the specific secret being requested
- returns empty string if no usable secret exists
- avoids broad unsafe mutation from recursively translated partner payloads

## Key Usage Boundaries

Logical KMS boundaries now are:

- `AUTH` -> JWT/auth token signing and verification
- `SIGNING` -> audit/integrity signing
- `ENCRYPTION` -> encrypted at-rest envelopes including financial data and wrapped provider secrets

Current key-family model:

- `ENCRYPTION` -> general data encryption and financial data envelopes
- `SECRET_WRAPPING` -> provider secret and provider token envelopes

This gives provider credential material a stricter physical KMS boundary than before while preserving the existing encrypted envelope format.

## Backup And Recovery Assumptions

Current assumptions in KMS:

- encrypted data can only be recovered if the wrapped KMS keys can be unwrapped
- wrapped KMS keys depend on:
  - `KMS_MASTER_KEY` or equivalent platform master secret
  - database availability for `kms_keys`
- `reWrapAllKeys(...)` is the supported master-secret rotation path
- `createRecoveryKit()` is not a full disaster recovery workflow; it is only a placeholder mechanism

Operational implications:

- database backups alone are not sufficient
- master-secret custody is mandatory for restore
- restoring `kms_keys` without the corresponding master secret will leave encrypted data inaccessible
- rotating the master secret without re-wrapping keys is a data-loss event

## Recommended Follow-Up

1. Migrate additional amount/description call sites from `DataVault` to `DataProtection`
2. Add telemetry around decrypt failures by crypto domain
3. Replace the placeholder recovery-kit flow with a documented operational recovery procedure
