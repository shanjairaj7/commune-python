"""Webhook signature verification for Commune inbound webhooks."""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional


class WebhookVerificationError(Exception):
    """Raised when webhook signature verification fails."""


def verify_signature(
    payload: bytes | str,
    signature: str,
    secret: str,
    *,
    timestamp: Optional[str] = None,
    tolerance_seconds: int = 300,
) -> bool:
    """Verify a Commune webhook signature.

    Commune signs every webhook delivery with an HMAC-SHA256 signature
    using your inbox webhook secret. Always verify before processing.

    Args:
        payload: The raw request body (bytes or string).
        signature: The ``X-Commune-Signature`` header value.
        secret: Your inbox webhook secret.
        timestamp: The ``X-Commune-Timestamp`` header value (optional).
            If provided, the signature is verified against
            ``{timestamp}.{payload}`` and the timestamp is checked
            for freshness.
        tolerance_seconds: Maximum age of the webhook in seconds
            (default 300 = 5 minutes). Only used when ``timestamp``
            is provided.

    Returns:
        ``True`` if the signature is valid.

    Raises:
        WebhookVerificationError: If the signature is invalid or the
            timestamp is too old.

    Example::

        from commune.webhooks import verify_signature

        # In your webhook handler (e.g. Flask / FastAPI):
        verify_signature(
            payload=request.body,
            signature=request.headers["X-Commune-Signature"],
            secret="whsec_...",
            timestamp=request.headers.get("X-Commune-Timestamp"),
        )
    """
    if not signature:
        raise WebhookVerificationError("Missing signature")
    if not secret:
        raise WebhookVerificationError("Missing webhook secret")

    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    # Build the signed content
    if timestamp:
        signed_content = f"{timestamp}.".encode("utf-8") + payload
    else:
        signed_content = payload

    expected = hmac.new(
        secret.encode("utf-8"),
        signed_content,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise WebhookVerificationError("Invalid signature")

    # Check timestamp freshness
    if timestamp and tolerance_seconds > 0:
        try:
            ts = int(timestamp)
            age = abs(time.time() - ts)
            if age > tolerance_seconds:
                raise WebhookVerificationError(
                    f"Webhook timestamp too old ({int(age)}s > {tolerance_seconds}s)"
                )
        except ValueError:
            pass  # Non-numeric timestamp — skip freshness check

    return True
