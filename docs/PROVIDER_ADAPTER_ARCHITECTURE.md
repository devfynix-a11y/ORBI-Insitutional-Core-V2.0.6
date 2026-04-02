# Provider Adapter Architecture

## Purpose

Provider execution is now formalized around a registry-driven adapter architecture.
The goal is to keep `financial_partners` and `provider_routing_rules` intact while removing hardcoded provider behavior and normalizing execution across mobile money, bank, card, and crypto rails.

## Core Model

Runtime provider execution now flows through these layers:

1. `ProviderSelectionService`
2. `ProviderRoutingService`
3. `ProviderFactory`
4. `IProviderAdapter`
5. `GenericRestProvider`

This keeps provider selection separate from provider execution.

## Source Of Configuration

Execution remains registry-driven from existing models:

- `financial_partners`
- `provider_routing_rules`
- `financial_partners.provider_metadata`
- `financial_partners.mapping_config`

No runtime path should depend on hardcoded Airtel-style assumptions.

## Normalized Contracts

Formal request/response contracts live in:

- `backend/payments/providers/types.ts`

Key contracts:

- `ProviderExecutionRequest`
- `ProviderExecutionResponse`
- `ProviderCapabilityDescriptor`
- `NormalizedProviderError`

This means provider adapters execute by normalized operation codes such as:

- `COLLECTION_REQUEST`
- `DISBURSEMENT_REQUEST`
- `BALANCE_INQUIRY`

Legacy names like `stkPush` and `disburse` remain compatibility shims only.

## Capability Descriptors

Provider capabilities are derived through:

- `backend/payments/ProviderCapabilityService.ts`

Capabilities describe:

- provider category
- rail
- supported operations
- webhook/polling support
- supported currencies and countries
- routing priority hints

`mobile_money` is treated as a generic provider category, not a named-provider implementation.

## Routing Selection

Routing selection is formalized through:

- `backend/payments/ProviderSelectionService.ts`
- `backend/payments/ProviderRoutingService.ts`

The selection service wraps the existing routing model and produces a normalized provider selection result without changing the storage model.

## Error Normalization

Provider errors are normalized through:

- `backend/payments/providers/ProviderErrorNormalizer.ts`

The normalization layer converts raw transport/provider faults into stable categories such as:

- `AUTH`
- `CONFIG`
- `NETWORK`
- `TIMEOUT`
- `RATE_LIMIT`
- `UNAVAILABLE`
- `REJECTED`
- `INVALID_RESPONSE`

## Retry And Failover Hooks

Retry handling is centralized in:

- `backend/payments/providers/ProviderRetryPolicy.ts`

The retry policy now supports hooks for:

- retry observation
- exhaustion handling
- failover candidate resolution

This creates a safe extension point for future provider failover without changing the adapter contract.

## Migration Guidance

When touching provider execution code:

- prefer `execute(partner, request)` over provider-specific methods
- treat capability descriptors as the runtime description of what a provider can do
- route first, then execute
- normalize errors before surfacing them to upstream services
- keep raw provider payloads as diagnostics, not business authority

## Current Compatibility Boundary

The architecture is formalized, but some compatibility shims still exist to preserve current behavior during migration.
Those shims should be treated as transitional and should not be used by new code.
