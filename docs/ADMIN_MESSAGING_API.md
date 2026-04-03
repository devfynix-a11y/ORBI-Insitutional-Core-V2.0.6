# Admin Messaging API

This note documents the new staff/admin messaging flow for ORBI Backend.

## Principles

- Official ORBI notifications are template-driven from ORBI Gateway.
- ORBI Backend does not define a second custom template system.
- Staff search and select available gateway templates by name.
- Backend resolves the audience and dispatches the selected gateway template.
- Only system custom SMS may bypass templates.

## Auth

All routes below require an authenticated staff session.

Allowed roles depend on the route:
- `ADMIN`
- `SUPER_ADMIN`
- `CUSTOMER_CARE`
- `MARKETING`
- `IT`

## Template Catalog

### `GET /api/v1/admin/messaging/templates`

Query params:
- `search`
- `channel`: `sms | email | push | whatsapp`
- `language`: `en | sw`
- `messageType`: `transactional | promotional`
- `limit`

Example:

```http
GET /api/v1/admin/messaging/templates?search=Transfer&channel=sms&language=en
```

Example response:

```json
{
  "success": true,
  "data": [
    {
      "name": "Transfer_Sent",
      "channel": "sms",
      "language": "en",
      "messageType": "transactional",
      "subject": "",
      "body": "Dear {{senderName}} ... Ref {{refId}}",
      "variables": ["senderName", "recipientName", "amount", "currency", "timestamp", "refId"]
    }
  ]
}
```

## Template Preview

### `POST /api/v1/admin/messaging/templates/preview`

Example body:

```json
{
  "templateName": "Promo_Message",
  "channel": "sms",
  "language": "en",
  "messageType": "promotional",
  "variables": {
    "body": "Enjoy zero transfer fees this weekend."
  }
}
```

Example response:

```json
{
  "success": true,
  "data": {
    "template": {
      "name": "Promo_Message",
      "channel": "sms",
      "language": "en",
      "messageType": "promotional",
      "body": "{{body}}",
      "variables": ["body"]
    },
    "rendered": {
      "subject": "",
      "body": "Enjoy zero transfer fees this weekend."
    }
  }
}
```

## Audience Preview

### `POST /api/v1/admin/messaging/audience/preview`

Supported filters:
- `search`
- `country`
- `registryType`
- `kycStatus`
- `accountStatus`
- `appOrigin`
- `hasPhone`
- `hasEmail`
- `createdAfter`
- `createdBefore`
- `newCustomersWithinDays`
- `minTransactionCount`
- `minTransactionAmount`
- `maxTransactionAmount`
- `minTotalTransactionAmount`
- `limit`

Example body:

```json
{
  "country": "Tanzania",
  "newCustomersWithinDays": 30,
  "hasPhone": true,
  "limit": 100
}
```

Example response:

```json
{
  "success": true,
  "data": {
    "count": 42,
    "sample": [
      {
        "id": "user-uuid",
        "full_name": "Jane Doe",
        "email": "jane@example.com",
        "phone": "+2557...",
        "nationality": "Tanzania",
        "transaction_count": 4,
        "total_transaction_amount": 120000
      }
    ]
  }
}
```

## Send Templated Staff Message

### `POST /api/v1/admin/messaging/send-template`

Use this for official ORBI staff/admin outreach.

You may target:
- explicit users with `userIds`
- filtered users with `filters`

Example body:

```json
{
  "templateName": "Promo_Message",
  "channel": "sms",
  "language": "en",
  "messageType": "promotional",
  "category": "promo",
  "filters": {
    "country": "Tanzania",
    "minTransactionCount": 5,
    "minTotalTransactionAmount": 500000,
    "hasPhone": true,
    "limit": 200
  },
  "variables": {
    "body": "ORBI Gold customers now enjoy reduced transfer charges this month."
  }
}
```

Example body for exact users:

```json
{
  "templateName": "Security_Alert_Message",
  "channel": "email",
  "language": "en",
  "messageType": "transactional",
  "category": "security",
  "userIds": ["uuid-1", "uuid-2"],
  "variables": {
    "subject": "Important ORBI account advisory",
    "body": "Please review your recent security activity.",
    "refId": "ADMIN-SEC-01"
  }
}
```

Example response:

```json
{
  "success": true,
  "data": {
    "delivered": 200,
    "audienceCount": 200,
    "template": {
      "name": "Promo_Message",
      "channel": "sms",
      "language": "en",
      "messageType": "promotional"
    }
  }
}
```

## Send System Custom SMS

### `POST /api/v1/admin/messaging/send-system-sms`

This is the only intentional template bypass.

Use it for urgent system-generated SMS where a gateway template is not appropriate.

Example body:

```json
{
  "category": "info",
  "filters": {
    "country": "Tanzania",
    "hasPhone": true,
    "newCustomersWithinDays": 7,
    "limit": 50
  },
  "body": "ORBI system notice: onboarding support is available on +255 764 258 114 if you need account activation help."
}
```

Example response:

```json
{
  "success": true,
  "data": {
    "delivered": 50,
    "audienceCount": 50
  }
}
```

## Notes

- Official notifications continue to prefer gateway templates.
- Older backend dispatch calls now fall back to gateway-safe defaults:
  - `Security_Alert_Message`
  - `Transactional_Message`
  - `Promo_Message`
- Mobile push to client apps is handled directly by ORBI Backend via Firebase Admin.
- Gateway remains the source of truth for message templates.
