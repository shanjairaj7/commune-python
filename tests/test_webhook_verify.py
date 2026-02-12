"""Tests for webhook signature verification."""

from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from commune.webhooks import verify_signature, WebhookVerificationError


SECRET = "whsec_test_secret_123"
PAYLOAD = b'{"type":"inbound","data":{"message_id":"msg_1"}}'


def _sign(payload: bytes, secret: str, timestamp: str | None = None) -> str:
    if timestamp:
        signed = f"{timestamp}.".encode("utf-8") + payload
    else:
        signed = payload
    return hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()


def test_valid_signature_no_timestamp():
    sig = _sign(PAYLOAD, SECRET)
    assert verify_signature(PAYLOAD, sig, SECRET) is True


def test_valid_signature_with_timestamp():
    ts = str(int(time.time()))
    sig = _sign(PAYLOAD, SECRET, ts)
    assert verify_signature(PAYLOAD, sig, SECRET, timestamp=ts) is True


def test_valid_signature_string_payload():
    payload_str = PAYLOAD.decode("utf-8")
    sig = _sign(PAYLOAD, SECRET)
    assert verify_signature(payload_str, sig, SECRET) is True


def test_invalid_signature_raises():
    with pytest.raises(WebhookVerificationError, match="Invalid signature"):
        verify_signature(PAYLOAD, "bad_signature", SECRET)


def test_missing_signature_raises():
    with pytest.raises(WebhookVerificationError, match="Missing signature"):
        verify_signature(PAYLOAD, "", SECRET)


def test_missing_secret_raises():
    sig = _sign(PAYLOAD, SECRET)
    with pytest.raises(WebhookVerificationError, match="Missing webhook secret"):
        verify_signature(PAYLOAD, sig, "")


def test_expired_timestamp_raises():
    old_ts = str(int(time.time()) - 600)  # 10 minutes ago
    sig = _sign(PAYLOAD, SECRET, old_ts)
    with pytest.raises(WebhookVerificationError, match="too old"):
        verify_signature(PAYLOAD, sig, SECRET, timestamp=old_ts, tolerance_seconds=300)


def test_fresh_timestamp_passes():
    ts = str(int(time.time()) - 10)  # 10 seconds ago
    sig = _sign(PAYLOAD, SECRET, ts)
    assert verify_signature(PAYLOAD, sig, SECRET, timestamp=ts, tolerance_seconds=300) is True
