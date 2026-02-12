"""Tests for webhook signature verification.

These tests mirror the backend's signing protocol exactly:
  - Signature format: ``v1={HMAC-SHA256(secret, "{timestamp_ms}.{body}")}``
  - Timestamp: Unix milliseconds (``Date.now()`` in Node.js)
  - Headers: ``x-commune-signature``, ``x-commune-timestamp``
"""

from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from commune.webhooks import verify_signature, compute_signature, WebhookVerificationError


SECRET = "whsec_test_secret_123"
PAYLOAD = b'{"type":"inbound","data":{"message_id":"msg_1"}}'


def _backend_sign(payload: bytes, secret: str, timestamp_ms: str) -> str:
    """Replicate the backend's computeSignature() exactly."""
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp_ms}.".encode("utf-8") + payload,
        hashlib.sha256,
    ).hexdigest()
    return f"v1={digest}"


# ── Core verification ────────────────────────────────────────────────────────

def test_valid_v1_signature_with_timestamp():
    """Standard flow: v1= prefixed signature with ms timestamp."""
    ts = str(int(time.time() * 1000))
    sig = _backend_sign(PAYLOAD, SECRET, ts)
    assert verify_signature(PAYLOAD, sig, SECRET, timestamp=ts) is True


def test_valid_signature_string_payload():
    """Payload passed as str instead of bytes."""
    ts = str(int(time.time() * 1000))
    sig = _backend_sign(PAYLOAD, SECRET, ts)
    assert verify_signature(PAYLOAD.decode("utf-8"), sig, SECRET, timestamp=ts) is True


def test_compute_signature_matches_backend():
    """compute_signature() produces the same output as the backend."""
    ts = "1707667200000"
    expected = _backend_sign(PAYLOAD, SECRET, ts)
    assert compute_signature(PAYLOAD, SECRET, ts) == expected


def test_raw_hex_accepted_for_backward_compat():
    """Raw hex (no v1= prefix) still works for backward compatibility."""
    ts = str(int(time.time() * 1000))
    full_sig = _backend_sign(PAYLOAD, SECRET, ts)
    raw_hex = full_sig[3:]  # strip "v1="
    assert verify_signature(PAYLOAD, raw_hex, SECRET, timestamp=ts) is True


# ── Error cases ──────────────────────────────────────────────────────────────

def test_invalid_signature_raises():
    ts = str(int(time.time() * 1000))
    with pytest.raises(WebhookVerificationError, match="Invalid signature"):
        verify_signature(PAYLOAD, "v1=bad_hex", SECRET, timestamp=ts)


def test_missing_signature_raises():
    with pytest.raises(WebhookVerificationError, match="Missing signature"):
        verify_signature(PAYLOAD, "", SECRET)


def test_missing_secret_raises():
    ts = str(int(time.time() * 1000))
    sig = _backend_sign(PAYLOAD, SECRET, ts)
    with pytest.raises(WebhookVerificationError, match="Missing webhook secret"):
        verify_signature(PAYLOAD, sig, "", timestamp=ts)


# ── Timestamp freshness ─────────────────────────────────────────────────────

def test_expired_timestamp_raises():
    """Timestamp 10 minutes old (600s) should fail with 300s tolerance."""
    old_ts = str(int(time.time() * 1000) - 600_000)
    sig = _backend_sign(PAYLOAD, SECRET, old_ts)
    with pytest.raises(WebhookVerificationError, match="too old"):
        verify_signature(PAYLOAD, sig, SECRET, timestamp=old_ts, tolerance_seconds=300)


def test_fresh_timestamp_passes():
    """Timestamp 10 seconds old should pass with 300s tolerance."""
    ts = str(int(time.time() * 1000) - 10_000)
    sig = _backend_sign(PAYLOAD, SECRET, ts)
    assert verify_signature(PAYLOAD, sig, SECRET, timestamp=ts, tolerance_seconds=300) is True


def test_no_timestamp_verifies_raw_payload():
    """Without timestamp, signature is computed over raw payload only."""
    digest = hmac.new(SECRET.encode(), PAYLOAD, hashlib.sha256).hexdigest()
    assert verify_signature(PAYLOAD, f"v1={digest}", SECRET) is True
