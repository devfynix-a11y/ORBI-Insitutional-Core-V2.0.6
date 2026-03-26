# Provider Registry Contract

The ORBI backend uses a dynamic provider registry stored in `financial_partners`.
Providers must be configured from Admin UI and executed through `logic_type` plus
`mapping_config`, not through hardcoded provider ids or provider classes.

## Core Fields

- `name`: operator or provider display label
- `type`: `mobile_money` | `bank` | `card` | `crypto`
- `logic_type`: `REGISTRY` | `GENERIC_REST` | `SPECIALIZED`
- `status`: `ACTIVE` | `INACTIVE` | `MAINTENANCE`
- `api_base_url`: provider base URL
- `mapping_config`: auth, request, response, webhook, and balance registry config
- `provider_metadata`: UI and product metadata

## Current Routing Model

The backend now supports registry resolution by:

- `rail`
- `operation`
- `country`
- `currency`
- `priority`

Primary routing source:

- `provider_routing_rules`

Fallback routing source:

- `financial_partners.provider_metadata`
- `financial_partners.mapping_config`

## provider_metadata

Supported UI/product fields:

- `group`: `Mobile` | `Bank` | `Gateways` | `Crypto`
- `rail`: `MOBILE_MONEY` | `BANK` | `CARD_GATEWAY` | `CRYPTO` | `WALLET`
- `brand_name`: provider-facing brand label
- `display_name`: optional frontend label override
- `display_icon`: icon URL or asset reference
- `color`: brand accent color
- `checkout_mode`: `redirect` | `embedded` | `tokenized` | `server_to_server` | `ussd` | `stk_push` | `manual`
- `channels`: array of
  - `bank_transfer`
  - `bank_account`
  - `mobile_money`
  - `card`
  - `paypal`
  - `crypto`
  - `ussd`
  - `qr`
  - `checkout_link`
- `sort_order`: numeric ordering value
- `region`: primary region label
- `currency`: primary currency
- `countries`: supported country codes
- `capabilities`: free-form capability labels
- `operations`: supported ORBI money operations
- `routing_priority`: default provider selection priority
- `provider_code`: stable registry-facing provider code
- `supports_webhooks`: callback capability flag
- `supports_polling`: polling capability flag

## Grouping Rules

Gateway provider listing resolves group in this order:

1. `provider_metadata.group`
2. normalized provider `type`
3. fallback to `Gateways`

This means Stripe, PayPal, and similar processors can be stored with:

- `type = "card"` or another supported execution type
- `provider_metadata.group = "Gateways"`

## mapping_config

The backend currently supports these registry execution fields:

- `service_root`
- `service_roots`
- `auth`
- `operations`
- `stk_push`
- `disbursement`
- `check_status`
- `balance`
- `callback`

Recommended direction:

- new integrations should prefer `operations`
- legacy compatibility can still use `stk_push`, `disbursement`, and `balance`

Example operation-aware registry layout:

```json
{
  "service_root": "https://provider.example.com",
  "service_roots": {
    "auth": "https://auth.provider.example.com",
    "stk_push": "https://collections.provider.example.com"
  },
  "operations": {
    "COLLECTION_REQUEST": {
      "url": "/collections",
      "method": "POST"
    },
    "DISBURSEMENT_REQUEST": {
      "url": "/disbursements",
      "method": "POST"
    },
    "BALANCE_INQUIRY": {
      "url": "/balances",
      "method": "GET"
    }
  },
  "callback": {
    "reference_field": "transaction.id",
    "status_field": "transaction.status"
  }
}
```

## API Output

`GET /v1/gateway/providers` returns normalized fields:

- `id`
- `name`
- `brandName`
- `type`
- `group`
- `logicType`
- `status`
- `supportedCurrencies`
- `icon`
- `color`
- `checkoutMode`
- `channels`
- `sortOrder`
- `metadata`
