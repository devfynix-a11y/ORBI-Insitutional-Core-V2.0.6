# Internal Worker And Service Route Authentication

## Why this exists

Internal routes are operationally sensitive. They can settle transactions, reverse funds, move queued work, and process offline confirmations. Shared-secret-only authentication was too weak as the long-term model because it did not provide freshness, replay resistance, or strong request identity metadata for audit analysis.

## Current route coverage

The hardened worker middleware currently protects:

- `/api/internal/*`
- `/api/broker/heartbeat`

## Supported authentication patterns

### 1. Signed internal requests (preferred)

Signed requests use HMAC-SHA256 with these headers:

- `x-worker-id`
- `x-worker-scopes`
- `x-worker-request-id`
- `x-worker-timestamp`
- `x-worker-nonce`
- `x-worker-signature`
- optional `x-worker-key-id`

Canonical signing payload:

1. HTTP method
2. original URL/path
3. worker id
4. comma-separated worker scopes
5. timestamp
6. nonce
7. request id
8. SHA-256 of the normalized request body

Behavior:

- verifies signature with `WORKER_SIGNING_SECRET` or fallback `WORKER_SECRET`
- enforces timestamp freshness using `ORBI_INTERNAL_REQUEST_MAX_AGE_SECONDS`
- applies replay protection using Redis when available
- falls back to process-local replay storage only when Redis is unavailable and local fallback is allowed
- records request identity metadata on the request for downstream audit logs

### 2. Legacy shared-secret mode (explicit compatibility only)

Legacy mode still accepts:

- `x-worker-secret` or `x-orbi-worker-secret`
- `x-worker-id`
- worker scopes

This mode is preserved for compatibility, but it does **not** provide strong replay resistance. It should be considered transitional.

Signed internal requests are now the default expectation. Legacy fallback should only be enabled deliberately with `ORBI_ALLOW_LEGACY_INTERNAL_WORKER_AUTH=true` outside production.

## Audit metadata added to internal requests

When a request is authenticated, the middleware attaches structured metadata that can be included in audit events:

- worker id
- worker scopes
- auth mode
- request id
- nonce
- timestamp
- key id
- request body hash
- source IP
- user agent
- signature verification status
- replay protection status

## Failure handling

Authentication failures generate `INTERNAL_REQUEST_AUTH_FAILED` security audit events with:

- failure code
- request path and method
- source IP
- worker id when present
- requested scopes
- request body hash

## mTLS support

The middleware is now mTLS-aware when a trusted edge, reverse proxy, or service mesh forwards verified client certificate metadata headers. Supported verification headers include values like:

- `x-ssl-client-verify`
- `x-client-cert-verified`
- `x-forwarded-client-cert-verified`

Supported identity headers include subject, issuer, serial, and forwarded certificate fields.

Mode is controlled by `ORBI_INTERNAL_MTLS_MODE`:

- `required`: reject internal requests unless mTLS verification headers indicate success
- `optional`: accept requests without mTLS headers, but reject requests that present failed verification headers
- `off`: disable mTLS header checks

Production required behavior is `required`, and startup validation now fails if `ORBI_INTERNAL_MTLS_MODE` is not set to `required`.

## Current limitations

This is materially stronger than the old worker-secret-only model, but there are still important limitations:

- HMAC-signed requests still rely on symmetric shared secrets
- mTLS verification is only as strong as the trusted edge/service mesh forwarding the certificate verification result
- full end-to-end mutual TLS still depends on infrastructure configuration outside this Node service
- legacy shared-secret mode remains intentionally weaker and should stay disabled in production
- process-local replay protection is only a fallback; Redis-backed replay protection is preferred for multi-node deployments

## Recommended production posture

- keep signed internal requests enabled
- keep legacy shared-secret fallback disabled
- run internal traffic behind a trusted proxy or mesh that forwards verified client-certificate metadata
- keep `ORBI_INTERNAL_MTLS_MODE=required` in production
