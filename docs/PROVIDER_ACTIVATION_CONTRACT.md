# Provider Activation Contract

## Purpose

`financial_partners.status = 'ACTIVE'` is now treated as a production-readiness state, not just a display flag.
An active provider must be executable through the registry-driven provider runtime without relying on fallback assumptions.

## Source Of Truth

Provider execution is registry-only:

- `financial_partners`
- `provider_metadata`
- `mapping_config`

Runtime resolution flows through:

- `ProviderFactory`
- `GenericRestProvider`
- `ProviderRegistryAdapter`

Specialized named provider classes are no longer part of the runtime path.

## Activation Requirements

A provider cannot be activated unless it has:

- `mapping_config`
- `mapping_config.service_root` or `mapping_config.service_roots`
- operation coverage through `mapping_config.operations` or supported legacy endpoint keys
- `provider_metadata.provider_code`
- `provider_metadata.rail`
- `provider_metadata.operations`

If webhook behavior is implied, it must also have:

- `mapping_config.callback`
- `mapping_config.callback.reference_field`
- `mapping_config.callback.status_field`

Webhook support is considered implied when any of the following are true:

- `provider_metadata.supports_webhooks = true`
- `mapping_config.callback` exists
- `provider_metadata.operations` contains `WEBHOOK_VERIFY`

## Enforcement Layers

The contract is enforced in three places:

1. Application validation
   `backend/payments/providers/ProviderRegistryValidator.ts`

2. Service-layer onboarding paths
   `backend/admin/partnerRegistry.ts`
   `backend/payments/providers/MerchantFabric.ts`

3. Database backstop
   `database/main.sql`
   `database/reset_schema.sql`

The SQL trigger blocks invalid `ACTIVE` rows even if a future code path bypasses backend validation.

## Operational Guidance

Use `INACTIVE` while drafting or partially configuring a provider.

Promote to `ACTIVE` only after:

- secrets are stored securely
- routing metadata is complete
- callback mapping is defined where required
- registry endpoints are validated
- test traffic succeeds through the registry runtime

## Migration Note

If an environment already contains active providers created before these guardrails, they must be reviewed before applying the SQL trigger migration.
Any non-compliant active row will fail future inserts or updates until its registry data is completed or its status is set to `INACTIVE`.
