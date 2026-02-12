# Commune Python SDK API Reference

Package on PyPI: `commune-mail`  
Import path: `commune`

This reference describes typed request/response contracts for the public SDK.

## Contract Policy

- Stable core fields are strongly typed in `commune/types.py`.
- Forward-compatible API expansion is allowed through extensible metadata (`extra` fields).
- Backward compatibility target: non-breaking additions for response fields.

## Client

```python
from commune import CommuneClient

client = CommuneClient(api_key="comm_...")

# Or use COMMUNE_API_KEY env var:
client = CommuneClient()
```

| Parameter | Type | Required | Default |
|---|---|---|---|
| `api_key` | `str \| None` | No | `COMMUNE_API_KEY` env var |
| `base_url` | `str \| None` | No | `https://api.commune.sh` |
| `timeout` | `float` | No | `30.0` |

## Async Client

```python
from commune import AsyncCommuneClient

async with AsyncCommuneClient(api_key="comm_...") as client:
    ...
```

Same parameters as `CommuneClient`. All methods are `async`.

## Domains

### `client.domains.list()`
Permission: `domains:read`

Request params: none  
Response type: `list[Domain]`

### `client.domains.create(name, region=None)`
Permission: `domains:write`

| Parameter | Type | Required |
|---|---|---|
| `name` | `str` | Yes |
| `region` | `str | None` | No |

Response type: `Domain`

### `client.domains.get(domain_id)`
Permission: `domains:read`

| Parameter | Type | Required |
|---|---|---|
| `domain_id` | `str` | Yes |

Response type: `Domain`

### `client.domains.verify(domain_id)`
Permission: `domains:write`

| Parameter | Type | Required |
|---|---|---|
| `domain_id` | `str` | Yes |

Response type: `DomainVerificationResult`

### `client.domains.records(domain_id)`
Permission: `domains:read`

| Parameter | Type | Required |
|---|---|---|
| `domain_id` | `str` | Yes |

Response type: `list[DomainDnsRecord]`

## Inboxes

### `client.inboxes.list(domain_id=None)`
Permission: `inboxes:read`

| Parameter | Type | Required |
|---|---|---|
| `domain_id` | `str | None` | No |

Response type: `list[Inbox]`

### `client.inboxes.create(local_part, *, domain_id=None, name=None, webhook=None)`
Permission: `inboxes:write`

| Parameter | Type | Required |
|---|---|---|
| `local_part` | `str` | Yes |
| `domain_id` | `str | None` | No |
| `name` | `str | None` | No |
| `webhook` | `dict[str, Any] | None` | No |

Response type: `Inbox`

### `client.inboxes.get(domain_id, inbox_id)`
Permission: `inboxes:read`

| Parameter | Type | Required |
|---|---|---|
| `domain_id` | `str` | Yes |
| `inbox_id` | `str` | Yes |

Response type: `Inbox`

### `client.inboxes.update(domain_id, inbox_id, *, local_part=None, webhook=None, status=None)`
Permission: `inboxes:write`

| Parameter | Type | Required |
|---|---|---|
| `domain_id` | `str` | Yes |
| `inbox_id` | `str` | Yes |
| `local_part` | `str | None` | No |
| `webhook` | `dict[str, Any] | None` | No |
| `status` | `str | None` | No |

Response type: `Inbox`

### `client.inboxes.set_webhook(domain_id, inbox_id, *, endpoint, events=None)`
Permission: `inboxes:write`

| Parameter | Type | Required |
|---|---|---|
| `domain_id` | `str` | Yes |
| `inbox_id` | `str` | Yes |
| `endpoint` | `str` | Yes |
| `events` | `list[str] | None` | No |

Response type: `Inbox`

### `client.inboxes.remove(domain_id, inbox_id)`
Permission: `inboxes:write`

| Parameter | Type | Required |
|---|---|---|
| `domain_id` | `str` | Yes |
| `inbox_id` | `str` | Yes |

Response type: `bool`

## Threads

### `client.threads.list(*, inbox_id=None, domain_id=None, limit=20, cursor=None, order="desc")`
Permission: `threads:read`

| Parameter | Type | Required |
|---|---|---|
| `inbox_id` | `str | None` | One of `inbox_id` or `domain_id` |
| `domain_id` | `str | None` | One of `inbox_id` or `domain_id` |
| `limit` | `int` | No |
| `cursor` | `str | None` | No |
| `order` | `str` | No |

Response type: `ThreadList` (`data`, `next_cursor`, `has_more`)

### `client.threads.messages(thread_id, *, limit=50, order="asc")`
Permission: `threads:read`

| Parameter | Type | Required |
|---|---|---|
| `thread_id` | `str` | Yes |
| `limit` | `int` | No |
| `order` | `str` | No |

Response type: `list[Message]`

## Messages

### `client.messages.send(...)`
Permission: `messages:write`

| Parameter | Type | Required |
|---|---|---|
| `to` | `str | list[str]` | Yes |
| `subject` | `str` | Yes |
| `html` | `str | None` | No |
| `text` | `str | None` | No |
| `from_address` | `str | None` | No |
| `cc` | `list[str] | None` | No |
| `bcc` | `list[str] | None` | No |
| `reply_to` | `str | None` | No |
| `thread_id` | `str | None` | No |
| `domain_id` | `str | None` | No |
| `inbox_id` | `str | None` | No |
| `attachments` | `list[str] | None` | No |
| `headers` | `dict[str, str] | None` | No |

Response type: `SendMessageResult`

### `client.messages.list(*, inbox_id=None, domain_id=None, sender=None, limit=50, order="desc", before=None, after=None)`
Permission: `messages:read`

| Parameter | Type | Required |
|---|---|---|
| `inbox_id` | `str | None` | One of `inbox_id`, `domain_id`, `sender` |
| `domain_id` | `str | None` | One of `inbox_id`, `domain_id`, `sender` |
| `sender` | `str | None` | One of `inbox_id`, `domain_id`, `sender` |
| `limit` | `int` | No |
| `order` | `str` | No |
| `before` | `str | None` | No |
| `after` | `str | None` | No |

Response type: `list[Message]`

## Attachments

### `client.attachments.upload(content, filename, mime_type)`
Permission: `attachments:write`

| Parameter | Type | Required |
|---|---|---|
| `content` | `str` (base64) | Yes |
| `filename` | `str` | Yes |
| `mime_type` | `str` | Yes |

Response type: `AttachmentUpload`

### `client.attachments.get(attachment_id)`
Permission: `attachments:read`

| Parameter | Type | Required |
|---|---|---|
| `attachment_id` | `str` | Yes |

Response type: `Attachment`

### `client.attachments.url(attachment_id, *, expires_in=3600)`
Permission: `attachments:read`

| Parameter | Type | Required |
|---|---|---|
| `attachment_id` | `str` | Yes |
| `expires_in` | `int` | No |

Response type: `AttachmentUrl`

## Webhook Verification

```python
from commune import verify_signature, WebhookVerificationError

verify_signature(payload, signature, secret, timestamp=None, tolerance_seconds=300)
```

| Parameter | Type | Required | Default |
|---|---|---|---|
| `payload` | `bytes \| str` | Yes | - |
| `signature` | `str` | Yes | - |
| `secret` | `str` | Yes | - |
| `timestamp` | `str \| None` | No | `None` |
| `tolerance_seconds` | `int` | No | `300` |

Returns `True` on success. Raises `WebhookVerificationError` on failure.

## Exception Types

- `AuthenticationError` (401)
- `PermissionDeniedError` (403) — recommended name
- `PermissionError` (403) — backward-compatible alias (shadows builtin)
- `ValidationError` (400)
- `NotFoundError` (404)
- `RateLimitError` (429)
- `WebhookVerificationError` — webhook signature verification failure
- `CommuneError` — base class / fallback for other HTTP errors
