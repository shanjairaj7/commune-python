"""Webhook signature verification for Commune outbound webhooks.

Commune signs every webhook delivery with HMAC-SHA256. The signature is
sent in the ``x-commune-signature`` header with a ``v1=`` prefix::

    x-commune-signature: v1={hex_digest}
    x-commune-timestamp: {unix_ms}

The signed content is ``{timestamp}.{body}`` where *timestamp* is the
value of the ``x-commune-timestamp`` header (Unix milliseconds).

Call verify_signature() at the start of every webhook handler before
processing the payload. If it raises WebhookVerificationError, reject
the request with HTTP 401.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional


class WebhookVerificationError(Exception):
    """Raised when webhook signature verification fails.

    Catch this in your webhook handler and return HTTP 401 to reject the request.
    Do not process the payload if this is raised — the request may be forged or
    replayed.

    Example:
        from commune.webhooks import verify_signature, WebhookVerificationError

        try:
            verify_signature(payload, signature, secret, timestamp=timestamp)
        except WebhookVerificationError:
            return Response(status_code=401)
    """


_V1_PREFIX = "v1="


def compute_signature(
    payload: bytes | str,
    secret: str,
    timestamp: str,
) -> str:
    """Compute the expected HMAC-SHA256 signature for a webhook payload.

    This is useful for testing your webhook handler locally or for building
    your own custom verification logic. Most callers should use
    verify_signature() instead, which handles comparison and timestamp checks.

    Args:
        payload: The raw request body (bytes or str). Do NOT pass parsed JSON —
                 the signature is computed over the exact bytes Commune sent.
        secret: Your inbox webhook secret (from the Commune dashboard or
                inbox.webhook.secret after calling inboxes.set_webhook()).
        timestamp: The ``x-commune-timestamp`` header value (Unix milliseconds
                   as a string, e.g. "1706000000000").

    Returns:
        The full signature string including the ``v1=`` prefix,
        e.g. "v1=5a3f2b1c...". Compare this against the x-commune-signature
        header value using hmac.compare_digest() for timing-safe comparison.

    Example — generate a test signature for local testing:
        import json, time
        body = json.dumps({"event": "inbound", "sender": "user@example.com"})
        ts = str(int(time.time() * 1000))
        sig = compute_signature(body.encode(), secret="whsec_...", timestamp=ts)
        # sig → "v1=a1b2c3..."
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

    Call this at the start of every webhook handler before processing the payload.
    Commune signs outbound webhooks with HMAC-SHA256 using your inbox webhook secret.
    Verifying the signature ensures the request came from Commune and was not
    tampered with in transit, and that it is not a replayed old request.

    IMPORTANT: Pass the raw request body (bytes), not parsed JSON. Many frameworks
    parse the body before it reaches your handler — make sure to read raw bytes first.

        Flask:   request.get_data()
        FastAPI: await request.body()
        Django:  request.body
        Express: Use express.raw({ type: "*/*" }) middleware

    Args:
        payload: Raw request body bytes (NOT parsed JSON). The signature is
                 computed over the exact byte sequence Commune sent.
        signature: Value of the ``x-commune-signature`` header.
                   Format: "v1={hex_digest}" (e.g. "v1=5a3f2b1c...").
        secret: Your inbox webhook secret. Get this from the Commune dashboard
                or from inbox.webhook.secret after calling inboxes.set_webhook().
                Store it as an environment variable — do not hard-code it.
        timestamp: Value of the ``x-commune-timestamp`` header (Unix milliseconds).
                   REQUIRED for proper verification — Commune always includes the
                   timestamp in the signed content. If omitted, the signature is
                   verified against the raw payload only (not recommended).
        tolerance_seconds: Maximum age of the webhook in seconds before it is
                           rejected as a replay (default 300 = 5 minutes).
                           Set to 0 to disable freshness checking.

    Returns:
        True if the signature is valid and the timestamp is fresh.

    Raises:
        WebhookVerificationError: If the signature is invalid, the secret is
            missing, or the timestamp is too old (> tolerance_seconds).
            If this raises, reject the request with HTTP 401. Do not process
            the payload.

    Example — Flask:
        from flask import Flask, request
        from commune.webhooks import verify_signature, WebhookVerificationError
        import os

        app = Flask(__name__)

        @app.post("/webhook")
        def handle():
            try:
                verify_signature(
                    payload=request.get_data(),         # ← raw bytes, not request.json
                    signature=request.headers["x-commune-signature"],
                    secret=os.environ["COMMUNE_WEBHOOK_SECRET"],
                    timestamp=request.headers.get("x-commune-timestamp"),
                )
            except WebhookVerificationError:
                return {"error": "invalid signature"}, 401
            # Safe to process now
            data = request.json
            return process_email(data)

    Example — FastAPI:
        from fastapi import FastAPI, Request, HTTPException
        from commune.webhooks import verify_signature, WebhookVerificationError
        import json, os

        app = FastAPI()

        @app.post("/webhook")
        async def handle(request: Request):
            body = await request.body()     # ← raw bytes before any parsing
            try:
                verify_signature(
                    payload=body,
                    signature=request.headers["x-commune-signature"],
                    secret=os.environ["COMMUNE_WEBHOOK_SECRET"],
                    timestamp=request.headers.get("x-commune-timestamp"),
                )
            except WebhookVerificationError:
                raise HTTPException(status_code=401, detail="Invalid signature")
            payload = json.loads(body)
            return await process_email(payload)

    Example — Django:
        from django.http import HttpResponse, JsonResponse
        from commune.webhooks import verify_signature, WebhookVerificationError
        import json, os

        def webhook(request):
            try:
                verify_signature(
                    payload=request.body,               # ← raw bytes
                    signature=request.headers.get("X-Commune-Signature", ""),
                    secret=os.environ["COMMUNE_WEBHOOK_SECRET"],
                    timestamp=request.headers.get("X-Commune-Timestamp"),
                )
            except WebhookVerificationError:
                return HttpResponse(status=401)
            data = json.loads(request.body)
            return JsonResponse(process_email(data))
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
