"""Async Commune Python SDK client — mirrors the sync client API surface."""

from __future__ import annotations

import os
from typing import Any, Optional
from urllib.parse import quote

from commune._async_http import AsyncHttpClient
from commune.types import (
    Attachment,
    DeleteResult,
    DomainDnsRecord,
    DomainVerificationResult,
    CreateDomainPayload,
    CreateInboxPayload,
    UpdateInboxPayload,
    SetInboxWebhookPayload,
    SendMessagePayload,
    SendMessageResult,
    UploadAttachmentPayload,
    AttachmentUpload,
    AttachmentUrl,
    Domain,
    Inbox,
    Message,
    Thread,
    ThreadList,
)


class _AsyncDomains:
    """Async domain management."""

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def list(self) -> list[Domain]:
        """List all domains in your organization."""
        data = await self._http.get("/v1/domains")
        if isinstance(data, list):
            return [Domain.model_validate(d) for d in data]
        return [Domain.model_validate(d) for d in (data or [])]

    async def create(self, name: str, region: str | None = None) -> Domain:
        """Create a new custom domain."""
        payload = CreateDomainPayload(name=name, region=region)
        data = await self._http.post(
            "/v1/domains",
            json=payload.model_dump(exclude_none=True),
        )
        return Domain.model_validate(data)

    async def get(self, domain_id: str) -> Domain:
        """Get details for a single domain."""
        data = await self._http.get(f"/v1/domains/{quote(domain_id)}")
        return Domain.model_validate(data)

    async def verify(self, domain_id: str) -> DomainVerificationResult:
        """Trigger DNS verification for a domain."""
        data = await self._http.post(f"/v1/domains/{quote(domain_id)}/verify")
        return DomainVerificationResult.model_validate(data)

    async def records(self, domain_id: str) -> list[DomainDnsRecord]:
        """Get DNS records required for domain verification."""
        data = await self._http.get(f"/v1/domains/{quote(domain_id)}/records")
        records = data if isinstance(data, list) else []
        return [DomainDnsRecord.model_validate(record) for record in records]


class _AsyncInboxes:
    """Async inbox management."""

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def list(self, domain_id: Optional[str] = None) -> list[Inbox]:
        """List inboxes."""
        if domain_id:
            data = await self._http.get(f"/v1/domains/{quote(domain_id)}/inboxes")
        else:
            data = await self._http.get("/v1/inboxes")
        if isinstance(data, list):
            return [Inbox.model_validate(d) for d in data]
        return [Inbox.model_validate(d) for d in (data or [])]

    async def create(
        self,
        local_part: str,
        *,
        domain_id: Optional[str] = None,
        name: Optional[str] = None,
        webhook: Optional[dict[str, Any]] = None,
    ) -> Inbox:
        """Create a new inbox."""
        payload = CreateInboxPayload(
            local_part=local_part,
            domain_id=domain_id,
            name=name,
            webhook=webhook,
        )
        data = await self._http.post(
            "/v1/inboxes",
            json=payload.model_dump(exclude_none=True),
        )
        return Inbox.model_validate(data)

    async def get(self, domain_id: str, inbox_id: str) -> Inbox:
        """Get a single inbox."""
        data = await self._http.get(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}"
        )
        return Inbox.model_validate(data)

    async def update(
        self,
        domain_id: str,
        inbox_id: str,
        *,
        local_part: Optional[str] = None,
        webhook: Optional[dict[str, Any]] = None,
        status: Optional[str] = None,
    ) -> Inbox:
        """Update an inbox."""
        payload = UpdateInboxPayload(
            local_part=local_part,
            webhook=webhook,
            status=status,
        )
        data = await self._http.put(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}",
            json=payload.model_dump(exclude_none=True),
        )
        return Inbox.model_validate(data)

    async def remove(self, domain_id: str, inbox_id: str) -> bool:
        """Delete an inbox."""
        data = await self._http.delete(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}"
        )
        if isinstance(data, dict):
            return DeleteResult.model_validate(data).ok
        return True

    async def set_webhook(
        self,
        domain_id: str,
        inbox_id: str,
        *,
        endpoint: str,
        events: Optional[list[str]] = None,
    ) -> Inbox:
        """Set a webhook on an inbox."""
        payload = SetInboxWebhookPayload(endpoint=endpoint, events=events)
        data = await self._http.put(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}",
            json={"webhook": payload.model_dump(exclude_none=True)},
        )
        return Inbox.model_validate(data)


class _AsyncThreads:
    """Async thread management."""

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def list(
        self,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        limit: int = 20,
        cursor: str | None = None,
        order: str = "desc",
    ) -> ThreadList:
        """List email threads with cursor-based pagination."""
        params: dict[str, Any] = {"limit": limit, "order": order}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        if cursor:
            params["cursor"] = cursor

        raw = await self._http.get("/v1/threads", params=params, unwrap_data=False)
        if isinstance(raw, dict):
            return ThreadList.model_validate(raw)
        if isinstance(raw, list):
            return ThreadList(data=[Thread.model_validate(t) for t in raw])
        return ThreadList()

    async def messages(
        self,
        thread_id: str,
        *,
        limit: int = 50,
        order: str = "asc",
    ) -> list[Message]:
        """Get all messages in a thread."""
        data = await self._http.get(
            f"/v1/threads/{quote(thread_id)}/messages",
            params={"limit": limit, "order": order},
        )
        if isinstance(data, list):
            return [Message.model_validate(m) for m in data]
        return [Message.model_validate(m) for m in (data or [])]


class _AsyncMessages:
    """Async email sending and listing."""

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def send(
        self,
        *,
        to: str | list[str],
        subject: str,
        html: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        reply_to: str | None = None,
        thread_id: str | None = None,
        domain_id: str | None = None,
        inbox_id: str | None = None,
        attachments: list[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> SendMessageResult:
        """Send an email."""
        payload = SendMessagePayload(
            to=to,
            subject=subject,
            html=html,
            text=text,
            from_address=from_address,
            cc=cc,
            bcc=bcc,
            reply_to=reply_to,
            thread_id=thread_id,
            domain_id=domain_id,
            inbox_id=inbox_id,
            attachments=attachments,
            headers=headers,
        )
        data = await self._http.post(
            "/v1/messages/send",
            json=payload.model_dump(by_alias=True, exclude_none=True),
        )
        return SendMessageResult.model_validate(data)

    async def list(
        self,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        sender: str | None = None,
        limit: int = 50,
        order: str = "desc",
        before: str | None = None,
        after: str | None = None,
    ) -> list[Message]:
        """List messages with filters."""
        params: dict[str, Any] = {"limit": limit, "order": order}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        if sender:
            params["sender"] = sender
        if before:
            params["before"] = before
        if after:
            params["after"] = after

        data = await self._http.get("/v1/messages", params=params)
        if isinstance(data, list):
            return [Message.model_validate(m) for m in data]
        return [Message.model_validate(m) for m in (data or [])]


class _AsyncAttachments:
    """Async attachment upload and retrieval."""

    def __init__(self, http: AsyncHttpClient):
        self._http = http

    async def upload(
        self,
        content: str,
        filename: str,
        mime_type: str,
    ) -> AttachmentUpload:
        """Upload an attachment for later use in emails."""
        payload = UploadAttachmentPayload(
            content=content,
            filename=filename,
            mime_type=mime_type,
        )
        data = await self._http.post(
            "/v1/attachments/upload",
            json=payload.model_dump(exclude_none=True),
        )
        return AttachmentUpload.model_validate(data)

    async def get(self, attachment_id: str) -> Attachment:
        """Get attachment metadata."""
        data = await self._http.get(f"/v1/attachments/{quote(attachment_id)}")
        return Attachment.model_validate(data)

    async def url(self, attachment_id: str, *, expires_in: int = 3600) -> AttachmentUrl:
        """Get a temporary download URL for an attachment."""
        data = await self._http.get(
            f"/v1/attachments/{quote(attachment_id)}/url",
            params={"expires_in": expires_in},
        )
        return AttachmentUrl.model_validate(data)


class AsyncCommuneClient:
    """Async Commune SDK client.

    Identical API to ``CommuneClient`` but all methods are ``async``.

    Example::

        import asyncio
        from commune import AsyncCommuneClient

        async def main():
            async with AsyncCommuneClient(api_key="comm_...") as client:
                inbox = await client.inboxes.create(local_part="support")
                await client.messages.send(
                    to="user@example.com",
                    subject="Hello",
                    html="<p>Hi!</p>",
                    inbox_id=inbox.id,
                )

        asyncio.run(main())

    Args:
        api_key: Your Commune API key (starts with ``comm_``).
            Falls back to the ``COMMUNE_API_KEY`` environment variable.
        base_url: Override the API base URL (default: Commune cloud).
        timeout: Request timeout in seconds (default 30).
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        timeout: float = 30.0,
    ):
        resolved_key = api_key or os.environ.get("COMMUNE_API_KEY") or ""
        if not resolved_key:
            raise ValueError(
                "No API key provided. Pass api_key= or set the COMMUNE_API_KEY "
                "environment variable."
            )
        self._http = AsyncHttpClient(api_key=resolved_key, base_url=base_url, timeout=timeout)
        self.domains = _AsyncDomains(self._http)
        self.inboxes = _AsyncInboxes(self._http)
        self.threads = _AsyncThreads(self._http)
        self.messages = _AsyncMessages(self._http)
        self.attachments = _AsyncAttachments(self._http)

    async def close(self) -> None:
        """Close the underlying HTTP connection."""
        await self._http.close()

    async def __aenter__(self) -> AsyncCommuneClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
