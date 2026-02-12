"""Typed request/response contracts for the Commune Python SDK."""

from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


# ── Enums / Literals ─────────────────────────────────────────────────────────

Channel = Literal["email"]
Direction = Literal["inbound", "outbound"]
ParticipantRole = Literal["sender", "to", "cc", "bcc", "mentioned", "participant"]


# ── Shared Base Model ────────────────────────────────────────────────────────


class ContractModel(BaseModel):
    """Base model with stable core fields and forward-compatible extras."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    # Dict-like helpers for backward compatibility with code that treats SDK
    # responses as mappings.
    def __getitem__(self, key: str) -> Any:
        data = self.model_dump()
        if key not in data:
            raise KeyError(key)
        return data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.model_dump().get(key, default)

    def items(self):
        return self.model_dump().items()

    def keys(self):
        return self.model_dump().keys()

    def values(self):
        return self.model_dump().values()


# ── Core Models ──────────────────────────────────────────────────────────────


class Participant(ContractModel):
    """A participant in an email message."""

    role: ParticipantRole
    identity: str


class MessageMetadata(ContractModel):
    """Metadata attached to every message."""

    created_at: str
    subject: Optional[str] = None
    in_reply_to: Optional[str] = None
    references: Optional[List[str]] = None
    is_private: Optional[bool] = None
    domain_id: Optional[str] = None
    inbox_id: Optional[str] = None
    inbox_address: Optional[str] = None
    message_id: Optional[str] = None
    provider: Optional[str] = None
    extracted_data: Optional[Dict[str, Any]] = None
    spam_score: Optional[float] = None
    spam_action: Optional[str] = None
    spam_flagged: Optional[bool] = None
    delivery_status: Optional[str] = None
    prompt_injection_checked: Optional[bool] = None
    prompt_injection_detected: Optional[bool] = None
    prompt_injection_risk: Optional[str] = None
    prompt_injection_score: Optional[float] = None
    prompt_injection_signals: Optional[str] = None


class Message(ContractModel):
    """A single email message."""

    id: Optional[str] = Field(None, alias="_id")
    channel: Channel = "email"
    message_id: str
    thread_id: str
    direction: Direction
    participants: List[Participant] = Field(default_factory=list)
    content: str = ""
    content_html: Optional[str] = None
    attachments: List[str] = Field(default_factory=list)
    created_at: str = ""
    metadata: MessageMetadata


# ── Threads ──────────────────────────────────────────────────────────────────


class Thread(ContractModel):
    """A thread (conversation) summary."""

    thread_id: str
    subject: Optional[str] = None
    last_message_at: str
    first_message_at: Optional[str] = None
    message_count: int = 0
    snippet: Optional[str] = None
    last_direction: Optional[Direction] = None
    inbox_id: Optional[str] = None
    domain_id: Optional[str] = None
    has_attachments: bool = False


class ThreadList(ContractModel):
    """Paginated list of threads."""

    data: List[Thread] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    has_more: bool = False


# ── Domains ──────────────────────────────────────────────────────────────────


class InboxWebhook(ContractModel):
    """Webhook configuration for an inbox."""

    endpoint: Optional[str] = None
    events: Optional[List[str]] = None
    secret: Optional[str] = None


class Inbox(ContractModel):
    """An inbox within a domain."""

    id: str
    local_part: str = Field("", alias="localPart")
    address: Optional[str] = None
    display_name: Optional[str] = Field(None, alias="displayName")
    agent: Optional[Dict[str, Any]] = None
    webhook: Optional[Union[InboxWebhook, str]] = None
    extraction_schema: Optional[Dict[str, Any]] = Field(None, alias="extractionSchema")
    created_at: Optional[str] = Field(None, alias="createdAt")
    status: Optional[str] = None
    domain_id: Optional[str] = None
    domain_name: Optional[str] = None


class DomainWebhook(ContractModel):
    """Webhook configuration for a domain."""

    id: Optional[str] = None
    endpoint: Optional[str] = None
    events: Optional[List[str]] = None
    secret: Optional[str] = None


class DomainDnsRecord(ContractModel):
    """Stable core DNS record fields with extensible extras."""

    record: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    value: Optional[str] = None
    status: Optional[str] = None
    ttl: Optional[Union[str, int]] = None
    priority: Optional[int] = None


class Domain(ContractModel):
    """A domain entry."""

    id: str
    name: Optional[str] = None
    status: Optional[str] = None
    region: Optional[str] = None
    records: Optional[List[DomainDnsRecord]] = None
    created_at: Optional[str] = Field(None, alias="createdAt")
    inboxes: Optional[List[Inbox]] = None


# ── Attachments ──────────────────────────────────────────────────────────────


class Attachment(ContractModel):
    """Attachment metadata."""

    attachment_id: str
    message_id: Optional[str] = None
    filename: str
    mime_type: str
    size: int
    source: Optional[str] = None
    storage_type: Optional[str] = None


class AttachmentUpload(ContractModel):
    """Response from uploading an attachment."""

    attachment_id: str
    filename: str
    mime_type: str
    size: int
    storage_type: Optional[str] = None


class AttachmentUrl(ContractModel):
    """A temporary URL to download an attachment."""

    url: str
    expires_in: int = Field(0, alias="expiresIn")
    filename: str
    mime_type: str = Field("", alias="mimeType")
    size: int = 0


# ── Payloads ─────────────────────────────────────────────────────────────────


class SendMessagePayload(ContractModel):
    """Payload for sending an email."""

    to: Union[str, List[str]]
    subject: str
    html: Optional[str] = None
    text: Optional[str] = None
    cc: Optional[List[str]] = None
    bcc: Optional[List[str]] = None
    reply_to: Optional[Union[str, List[str]]] = None
    thread_id: Optional[str] = None
    domain_id: Optional[str] = Field(None, alias="domainId")
    inbox_id: Optional[str] = Field(None, alias="inboxId")
    attachments: Optional[List[str]] = None
    headers: Optional[Dict[str, str]] = None
    from_address: Optional[str] = Field(None, alias="from")


class CreateDomainPayload(ContractModel):
    """Payload for creating a domain."""

    name: str
    region: Optional[str] = None


class CreateInboxPayload(ContractModel):
    """Payload for creating an inbox."""

    local_part: str
    domain_id: Optional[str] = None
    name: Optional[str] = None
    webhook: Optional[Dict[str, Any]] = None


class UpdateInboxPayload(ContractModel):
    """Payload for updating an inbox."""

    local_part: Optional[str] = None
    webhook: Optional[Dict[str, Any]] = None
    status: Optional[str] = None


class SetInboxWebhookPayload(ContractModel):
    """Payload for setting inbox webhooks."""

    endpoint: str
    events: Optional[List[str]] = None


class UploadAttachmentPayload(ContractModel):
    """Payload for uploading attachments."""

    content: str
    filename: str
    mime_type: str


# ── Structured Responses ─────────────────────────────────────────────────────


class DomainVerificationResult(ContractModel):
    """Typed response from domain verification."""

    id: Optional[str] = None
    status: Optional[str] = None


class SendMessageResult(ContractModel):
    """Typed response from sending a message."""

    id: Optional[str] = None
    message_id: Optional[str] = None
    thread_id: Optional[str] = None
    status: Optional[str] = None


class DeleteResult(ContractModel):
    """Typed common delete response."""

    ok: bool = False
