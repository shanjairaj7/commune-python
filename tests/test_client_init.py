"""Tests for client initialization and env var support."""

from __future__ import annotations

import os

import pytest

from commune import CommuneClient, AsyncCommuneClient


def test_client_with_explicit_api_key():
    client = CommuneClient(api_key="comm_test123")
    assert client._http._client.headers["authorization"] == "Bearer comm_test123"
    client.close()


def test_client_from_env_var(monkeypatch):
    monkeypatch.setenv("COMMUNE_API_KEY", "comm_from_env")
    client = CommuneClient()
    assert client._http._client.headers["authorization"] == "Bearer comm_from_env"
    client.close()


def test_client_explicit_key_overrides_env(monkeypatch):
    monkeypatch.setenv("COMMUNE_API_KEY", "comm_from_env")
    client = CommuneClient(api_key="comm_explicit")
    assert client._http._client.headers["authorization"] == "Bearer comm_explicit"
    client.close()


def test_client_no_key_raises():
    # Ensure env var is not set
    env_backup = os.environ.pop("COMMUNE_API_KEY", None)
    try:
        with pytest.raises(ValueError, match="No API key provided"):
            CommuneClient()
    finally:
        if env_backup is not None:
            os.environ["COMMUNE_API_KEY"] = env_backup


def test_async_client_no_key_raises():
    env_backup = os.environ.pop("COMMUNE_API_KEY", None)
    try:
        with pytest.raises(ValueError, match="No API key provided"):
            AsyncCommuneClient()
    finally:
        if env_backup is not None:
            os.environ["COMMUNE_API_KEY"] = env_backup


def test_client_custom_base_url():
    client = CommuneClient(api_key="comm_test", base_url="https://custom.api.com")
    assert client._http._base_url == "https://custom.api.com"
    client.close()


def test_client_context_manager():
    with CommuneClient(api_key="comm_test") as client:
        assert client.domains is not None
        assert client.inboxes is not None
        assert client.threads is not None
        assert client.messages is not None
        assert client.attachments is not None


def test_client_has_all_resource_namespaces():
    client = CommuneClient(api_key="comm_test")
    assert hasattr(client, "domains")
    assert hasattr(client, "inboxes")
    assert hasattr(client, "threads")
    assert hasattr(client, "messages")
    assert hasattr(client, "attachments")
    client.close()
