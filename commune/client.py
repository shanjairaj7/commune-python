"""Commune Python SDK client — mirrors the Node.js SDK API surface."""

from __future__ import annotations

import os
from typing import Any, Optional
from urllib.parse import quote

from commune._http import HttpClient
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


class _Domains:
    """Domain management.

    Example::

        # List all domains
        domains = client.domains.list()

        # Create a domain
        domain = client.domains.create(name="example.com")

        # Verify DNS
        result = client.domains.verify(domain_id)

        # Get DNS records to configure
        records = client.domains.records(domain_id)
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def list(self) -> list[Domain]:
        """List all domains in your organization."""
        data = self._http.get("/v1/domains")
        if isinstance(data, list):
            return [Domain.model_validate(d) for d in data]
        return [Domain.model_validate(d) for d in (data or [])]

    def create(self, name: str, region: str | None = None) -> Domain:
        """Create a new custom domain.

        Args:
            name: The domain name (e.g. "example.com").
            region: Optional region (e.g. "us-east-1").
        """
        payload = CreateDomainPayload(name=name, region=region)
        data = self._http.post(
            "/v1/domains",
            json=payload.model_dump(exclude_none=True),
        )
        return Domain.model_validate(data)

    def get(self, domain_id: str) -> Domain:
        """Get details for a single domain.

        Args:
            domain_id: The domain ID.
        """
        data = self._http.get(f"/v1/domains/{quote(domain_id)}")
        return Domain.model_validate(data)

    def verify(self, domain_id: str) -> DomainVerificationResult:
        """Trigger DNS verification for a domain.

        Args:
            domain_id: The domain ID to verify.
        """
        data = self._http.post(f"/v1/domains/{quote(domain_id)}/verify")
        return DomainVerificationResult.model_validate(data)

    def records(self, domain_id: str) -> list[DomainDnsRecord]:
        """Get DNS records required for domain verification.

        Args:
            domain_id: The domain ID.

        Returns:
            List of DNS record objects to configure at your registrar.
        """
        data = self._http.get(f"/v1/domains/{quote(domain_id)}/records")
        records = data if isinstance(data, list) else []
        return [DomainDnsRecord.model_validate(record) for record in records]


class _Inboxes:
    """Inbox management.

    Create inboxes with or without specifying a domain. When no domain is
    provided, Commune automatically assigns your inbox to an available domain.

    Example::

        # Simplest — domain is auto-resolved
        inbox = client.inboxes.create(local_part="support")

        # Explicit domain
        inbox = client.inboxes.create(local_part="support", domain_id="d_abc")

        # List all inboxes across all domains
        inboxes = client.inboxes.list()
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def list(self, domain_id: Optional[str] = None) -> list[Inbox]:
        """List inboxes.

        Args:
            domain_id: Optional — list inboxes for a specific domain.
                       If omitted, lists all inboxes across all domains.
        """
        if domain_id:
            data = self._http.get(f"/v1/domains/{quote(domain_id)}/inboxes")
        else:
            data = self._http.get("/v1/inboxes")
        if isinstance(data, list):
            return [Inbox.model_validate(d) for d in data]
        return [Inbox.model_validate(d) for d in (data or [])]

    def create(
        self,
        local_part: str,
        *,
        domain_id: Optional[str] = None,
        name: Optional[str] = None,
        webhook: Optional[dict[str, Any]] = None,
    ) -> Inbox:
        """Create a new inbox.

        The email address will be ``{local_part}@{domain}``. If no
        ``domain_id`` is provided, Commune auto-assigns your inbox to
        an available domain — no DNS setup required.

        Args:
            local_part: The part before the @ (e.g. ``"support"`` → support@domain.com).
            domain_id: Optional domain to create under. Auto-resolved if omitted.
            name: Optional display name for the inbox.
            webhook: Optional webhook config: ``{"endpoint": "https://...", "events": ["inbound"]}``.
        """
        payload = CreateInboxPayload(
            local_part=local_part,
            domain_id=domain_id,
            name=name,
            webhook=webhook,
        )

        # Use top-level POST /v1/inboxes (auto-resolves domain)
        data = self._http.post(
            "/v1/inboxes",
            json=payload.model_dump(exclude_none=True),
        )
        return Inbox.model_validate(data)

    def get(self, domain_id: str, inbox_id: str) -> Inbox:
        """Get a single inbox.

        Args:
            domain_id: The domain ID.
            inbox_id: The inbox ID.
        """
        data = self._http.get(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}"
        )
        return Inbox.model_validate(data)

    def update(
        self,
        domain_id: str,
        inbox_id: str,
        *,
        local_part: Optional[str] = None,
        webhook: Optional[dict[str, Any]] = None,
        status: Optional[str] = None,
    ) -> Inbox:
        """Update an inbox.

        Args:
            domain_id: The domain ID.
            inbox_id: The inbox ID.
            local_part: New local part (optional).
            webhook: New webhook config (optional).
            status: New status (optional).
        """
        payload = UpdateInboxPayload(
            local_part=local_part,
            webhook=webhook,
            status=status,
        )
        data = self._http.put(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}",
            json=payload.model_dump(exclude_none=True),
        )
        return Inbox.model_validate(data)

    def remove(self, domain_id: str, inbox_id: str) -> bool:
        """Delete an inbox.

        Args:
            domain_id: The domain ID.
            inbox_id: The inbox ID.

        Returns:
            True if the inbox was deleted.
        """
        data = self._http.delete(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}"
        )
        if isinstance(data, dict):
            return DeleteResult.model_validate(data).ok
        return True

    def set_webhook(
        self,
        domain_id: str,
        inbox_id: str,
        *,
        endpoint: str,
        events: Optional[list[str]] = None,
    ) -> Inbox:
        """Set a webhook on an inbox. Receives events when emails arrive.

        Args:
            domain_id: The domain ID.
            inbox_id: The inbox ID.
            endpoint: The webhook URL to call.
            events: Optional list of event types to subscribe to.
        """
        payload = SetInboxWebhookPayload(endpoint=endpoint, events=events)
        data = self._http.put(
            f"/v1/domains/{quote(domain_id)}/inboxes/{quote(inbox_id)}",
            json={"webhook": payload.model_dump(exclude_none=True)},
        )
        return Inbox.model_validate(data)


class _Threads:
    """Thread (conversation) management.

    A thread is a group of related email messages sharing a conversation.

    Example::

        # List threads for an inbox (paginated)
        result = client.threads.list(inbox_id="...", limit=20)

        # Get next page
        next_page = client.threads.list(inbox_id="...", cursor=result.next_cursor)

        # Get all messages in a thread
        messages = client.threads.messages(thread_id)
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def list(
        self,
        *,
        inbox_id: str | None = None,
        domain_id: str | None = None,
        limit: int = 20,
        cursor: str | None = None,
        order: str = "desc",
    ) -> ThreadList:
        """List email threads with cursor-based pagination.

        Args:
            inbox_id: Filter by inbox (recommended).
            domain_id: Filter by domain.
            limit: Max results per page (1–100, default 20).
            cursor: Pagination cursor from a previous response.
            order: Sort order — ``"desc"`` (newest first) or ``"asc"``.

        Returns:
            A ``ThreadList`` with ``data``, ``next_cursor``, and ``has_more``.
        """
        params: dict[str, Any] = {"limit": limit, "order": order}
        if inbox_id:
            params["inbox_id"] = inbox_id
        if domain_id:
            params["domain_id"] = domain_id
        if cursor:
            params["cursor"] = cursor

        raw = self._http.get("/v1/threads", params=params, unwrap_data=False)
        if isinstance(raw, dict):
            return ThreadList.model_validate(raw)
        if isinstance(raw, list):
            return ThreadList(data=[Thread.model_validate(t) for t in raw])
        return ThreadList()

    def messages(
        self,
        thread_id: str,
        *,
        limit: int = 50,
        order: str = "asc",
    ) -> list[Message]:
        """Get all messages in a thread.

        Args:
            thread_id: The thread (conversation) ID.
            limit: Max messages (1–1000, default 50).
            order: ``"asc"`` (oldest first, default) or ``"desc"``.

        Returns:
            List of messages in the thread.
        """
        data = self._http.get(
            f"/v1/threads/{quote(thread_id)}/messages",
            params={"limit": limit, "order": order},
        )
        if isinstance(data, list):
            return [Message.model_validate(m) for m in data]
        return [Message.model_validate(m) for m in (data or [])]


class _Messages:
    """Email sending and listing.

    Example::

        # Send an email
        result = client.messages.send(
            to="user@example.com",
            subject="Hello",
            html="<p>Hi there!</p>",
        )

        # List messages for an inbox
        messages = client.messages.list(inbox_id="...")
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def send(
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
        """Send an email.

        Args:
            to: Recipient email address(es).
            subject: Email subject line.
            html: HTML body content.
            text: Plain text body content (fallback).
            from_address: Sender address (optional, uses default).
            cc: CC recipients.
            bcc: BCC recipients.
            reply_to: Reply-to address.
            thread_id: Reply within an existing thread.
            domain_id: Send from a specific domain.
            inbox_id: Send from a specific inbox.
            attachments: List of attachment IDs from ``client.attachments.upload()``.
            headers: Custom email headers.
        """
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
        data = self._http.post(
            "/v1/messages/send",
            json=payload.model_dump(by_alias=True, exclude_none=True),
        )
        return SendMessageResult.model_validate(data)

    def list(
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
        """List messages with filters.

        Provide at least one of ``inbox_id``, ``domain_id``, or ``sender``.

        Args:
            inbox_id: Filter by inbox.
            domain_id: Filter by domain.
            sender: Filter by sender email.
            limit: Max results (1–1000, default 50).
            order: ``"asc"`` or ``"desc"`` (default).
            before: ISO date — only messages before this time.
            after: ISO date — only messages after this time.
        """
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

        data = self._http.get("/v1/messages", params=params)
        if isinstance(data, list):
            return [Message.model_validate(m) for m in data]
        return [Message.model_validate(m) for m in (data or [])]


class _Attachments:
    """Attachment upload and retrieval.

    Example::

        import base64

        # Upload a file
        with open("invoice.pdf", "rb") as f:
            content = base64.b64encode(f.read()).decode()

        upload = client.attachments.upload(
            content=content,
            filename="invoice.pdf",
            mime_type="application/pdf",
        )

        # Use in an email
        client.messages.send(
            to="user@example.com",
            subject="Invoice",
            html="<p>See attached.</p>",
            attachments=[upload.attachment_id],
        )

        # Get download URL
        url_info = client.attachments.url(upload.attachment_id)
    """

    def __init__(self, http: HttpClient):
        self._http = http

    def upload(
        self,
        content: str,
        filename: str,
        mime_type: str,
    ) -> AttachmentUpload:
        """Upload an attachment for later use in emails.

        Args:
            content: Base64-encoded file content.
            filename: Original filename (e.g. ``"invoice.pdf"``).
            mime_type: MIME type (e.g. ``"application/pdf"``).

        Returns:
            An ``AttachmentUpload`` with the ``attachment_id`` to use when sending.
        """
        payload = UploadAttachmentPayload(
            content=content,
            filename=filename,
            mime_type=mime_type,
        )
        data = self._http.post(
            "/v1/attachments/upload",
            json=payload.model_dump(exclude_none=True),
        )
        return AttachmentUpload.model_validate(data)

    def get(self, attachment_id: str) -> Attachment:
        """Get attachment metadata.

        Args:
            attachment_id: The attachment ID.
        """
        data = self._http.get(f"/v1/attachments/{quote(attachment_id)}")
        return Attachment.model_validate(data)

    def url(self, attachment_id: str, *, expires_in: int = 3600) -> AttachmentUrl:
        """Get a temporary download URL for an attachment.

        Args:
            attachment_id: The attachment ID.
            expires_in: URL expiration in seconds (default 3600).

        Returns:
            An ``AttachmentUrl`` with the download ``url``.
        """
        data = self._http.get(
            f"/v1/attachments/{quote(attachment_id)}/url",
            params={"expires_in": expires_in},
        )
        return AttachmentUrl.model_validate(data)


class CommuneClient:
    """Commune SDK client.

    Initialize with your API key to access all Commune features::

        from commune import CommuneClient

        client = CommuneClient(api_key="comm_...")

        # Manage domains
        domains = client.domains.list()

        # Manage inboxes
        inbox = client.inboxes.create(domain_id, local_part="support")

        # Browse threads
        threads = client.threads.list(inbox_id=inbox.id)

        # Read messages
        messages = client.threads.messages(threads.data[0].thread_id)

        # Send emails
        client.messages.send(to="user@example.com", subject="Hi", html="<p>Hello!</p>")

    Args:
        api_key: Your Commune API key (starts with ``comm_``).
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
        self._http = HttpClient(api_key=resolved_key, base_url=base_url, timeout=timeout)
        self.domains = _Domains(self._http)
        self.inboxes = _Inboxes(self._http)
        self.threads = _Threads(self._http)
        self.messages = _Messages(self._http)
        self.attachments = _Attachments(self._http)

    def close(self) -> None:
        """Close the underlying HTTP connection."""
        self._http.close()

    def __enter__(self) -> CommuneClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
