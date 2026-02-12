# Changelog

All notable changes to the Commune Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-02-12

### Added
- **`AsyncCommuneClient`** — Full async/await support via `httpx.AsyncClient`. Identical API surface to the sync client.
- **`verify_signature()`** — Webhook signature verification helper with HMAC-SHA256 and timestamp freshness checks.
- **`WebhookVerificationError`** exception for webhook verification failures.
- **`PermissionDeniedError`** — Renamed from `PermissionError` to avoid shadowing the Python builtin. The old name is kept as a backward-compatible alias.
- **`COMMUNE_API_KEY` env var** — `CommuneClient()` and `AsyncCommuneClient()` now auto-read the API key from the environment if not passed explicitly.
- **`CONTRIBUTING.md`** — Contributor guide.
- **`LICENSE`** file (MIT).
- This **`CHANGELOG.md`**.

### Changed
- `api_key` parameter is now optional (falls back to `COMMUNE_API_KEY` env var).
- `CommuneError` now has a `__repr__` for better debugging.

### Fixed
- `PermissionError` no longer shadows `builtins.PermissionError`.

## [0.1.1] — 2026-02-06

### Added
- Inbox `display_name` field support.
- `MessageMetadata` fields: `spam_score`, `spam_action`, `spam_flagged`, `delivery_status`, prompt injection fields.
- Comprehensive security documentation in README.

### Changed
- Package renamed from `commune-ai` to `commune-mail` on PyPI.
- `Message.conversation_id` renamed to `Message.thread_id`.
- Updated all examples from `conv_` prefixes to `thread_` prefixes.

## [0.1.0] — 2026-01-28

### Added
- Initial release.
- Sync client with domains, inboxes, threads, messages, and attachments.
- Pydantic v2 typed models with `extra="allow"` for forward compatibility.
- Exception hierarchy mapping HTTP status codes.
- `py.typed` marker for PEP 561 type checking support.
- 9 unit tests covering contracts, error mapping, and pagination.
