"""Webhook signature verification for Commune outbound webhooks.

Commune signs every webhook delivery with HMAC-SHA256. The signature is
sent in the ``x-commune-signature`` header with a ``v1=`` prefix::

    x-commune-signature: v1={hex_digest}
    x-commune-timestamp: {unix_ms}

The signed content is ``{timestamp}.{body}`` where *timestamp* is the
value of the ``x-commune-timestamp`` header (Unix milliseconds).
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional


class WebhookVerificationError(Exception):
    """Raised when webhook signature verification fails."""


_V1_PREFIX = "v1="


def compute_signature(
    payload: bytes | str,
    secret: str,
    timestamp: str,
) -> str:
    """Compute the expected ``v1=`` signature for a webhook payload.

    This is useful for testing or for building your own verification
    logic. Most callers should use :func:`verify_signature` instead.

    Args:
        payload: The raw request body.
        secret: Your inbox webhook secret.
        timestamp: The ``x-commune-timestamp`` header value (Unix ms).

    Returns:
        The full signature string including the ``v1=`` prefix.
    """
    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    signed_content = f"{timestamp}.".encode("utf-8") + payload
    digest = hmac.new(
        secret.encode("utf-8"),
        signed_content,
        hashlib.sha256,
    ).hexdigest()
    return f"{_V1_PREFIX}{digest}"


def verify_signature(
    payload: bytes | str,
    signature: str,
    secret: str,
    *,
    timestamp: Optional[str] = None,
    tolerance_seconds: int = 300,
) -> bool:
    """Verify a Commune webhook signature.

    Commune signs every webhook delivery with HMAC-SHA256. The signature
    header uses the format ``v1={hex_digest}`` and the timestamp header
    contains Unix **milliseconds**.

    Args:
        payload: The raw request body (bytes or string).
        signature: The ``x-commune-signature`` header value
            (e.g. ``"v1=5a3f2b..."``).
        secret: Your inbox webhook secret.
        timestamp: The ``x-commune-timestamp`` header value (Unix ms).
            **Required** for proper verification — the backend always
            includes the timestamp in the signed content. If omitted,
            the signature is verified against the raw payload only
            (not recommended).
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
            signature=request.headers["x-commune-signature"],
            secret="whsec_...",
            timestamp=request.headers.get("x-commune-timestamp"),
        )
    """
    if not signature:
        raise WebhookVerificationError("Missing signature")
    if not secret:
        raise WebhookVerificationError("Missing webhook secret")

    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    # Build the signed content — must match backend:
    #   computeSignature(body, timestamp, secret) → v1=HMAC(secret, "{timestamp}.{body}")
    if timestamp:
        signed_content = f"{timestamp}.".encode("utf-8") + payload
    else:
        signed_content = payload

    digest = hmac.new(
        secret.encode("utf-8"),
        signed_content,
        hashlib.sha256,
    ).hexdigest()

    # The backend sends "v1={hex}", so we compare with the prefix.
    # Also accept raw hex for backward compatibility.
    expected_v1 = f"{_V1_PREFIX}{digest}"

    sig_to_compare = signature
    if not sig_to_compare.startswith(_V1_PREFIX):
        # Caller passed raw hex — compare against raw digest
        if not hmac.compare_digest(digest, sig_to_compare):
            raise WebhookVerificationError("Invalid signature")
    else:
        if not hmac.compare_digest(expected_v1, sig_to_compare):
            raise WebhookVerificationError("Invalid signature")

    # Check timestamp freshness — timestamp is Unix MILLISECONDS
    if timestamp and tolerance_seconds > 0:
        try:
            ts_ms = int(timestamp)
            age_ms = abs(time.time() * 1000 - ts_ms)
            age_s = age_ms / 1000
            if age_s > tolerance_seconds:
                raise WebhookVerificationError(
                    f"Webhook timestamp too old ({int(age_s)}s > {tolerance_seconds}s)"
                )
        except ValueError:
            pass  # Non-numeric timestamp — skip freshness check

    return True
