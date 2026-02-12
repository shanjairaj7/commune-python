"""Tests for domain and inbox client methods."""

from __future__ import annotations

import json

import httpx

from commune.types import Domain, Inbox, DomainDnsRecord, DomainVerificationResult
from conftest import install_mock_transport


def test_domains_list(client):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/domains"
        return httpx.Response(
            status_code=200,
            json={
                "data": [
                    {"id": "d_1", "name": "example.com", "status": "verified"},
                    {"id": "d_2", "name": "test.com", "status": "pending"},
                ]
            },
        )

    install_mock_transport(client, handler)
    domains = client.domains.list()
    assert len(domains) == 2
    assert isinstance(domains[0], Domain)
    assert domains[0].id == "d_1"
    assert domains[1].name == "test.com"


def test_domains_create(client):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert body["name"] == "new.com"
        return httpx.Response(
            status_code=201,
            json={"data": {"id": "d_new", "name": "new.com", "status": "not_started"}},
        )

    install_mock_transport(client, handler)
    domain = client.domains.create(name="new.com")
    assert domain.id == "d_new"
    assert domain.status == "not_started"


def test_domains_get(client):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/domains/d_1"
        return httpx.Response(
            status_code=200,
            json={"data": {"id": "d_1", "name": "example.com", "status": "verified"}},
        )

    install_mock_transport(client, handler)
    domain = client.domains.get("d_1")
    assert domain.name == "example.com"


def test_domains_verify(client):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/v1/domains/d_1/verify"
        return httpx.Response(
            status_code=200,
            json={"data": {"id": "d_1", "status": "verified"}},
        )

    install_mock_transport(client, handler)
    result = client.domains.verify("d_1")
    assert isinstance(result, DomainVerificationResult)
    assert result.status == "verified"


def test_inboxes_list_all(client):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/inboxes"
        return httpx.Response(
            status_code=200,
            json={
                "data": [
                    {"id": "i_1", "localPart": "support", "address": "support@example.com"},
                ]
            },
        )

    install_mock_transport(client, handler)
    inboxes = client.inboxes.list()
    assert len(inboxes) == 1
    assert isinstance(inboxes[0], Inbox)
    assert inboxes[0].local_part == "support"


def test_inboxes_list_by_domain(client):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/domains/d_1/inboxes"
        return httpx.Response(
            status_code=200,
            json={"data": [{"id": "i_1", "localPart": "billing", "address": "billing@example.com"}]},
        )

    install_mock_transport(client, handler)
    inboxes = client.inboxes.list(domain_id="d_1")
    assert inboxes[0].local_part == "billing"


def test_inboxes_create_auto_domain(client):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/inboxes"
        body = json.loads(request.content.decode("utf-8"))
        assert body["local_part"] == "agent"
        assert "domain_id" not in body
        return httpx.Response(
            status_code=201,
            json={"data": {"id": "i_new", "localPart": "agent", "address": "agent@agents.postking.io"}},
        )

    install_mock_transport(client, handler)
    inbox = client.inboxes.create(local_part="agent")
    assert inbox.address == "agent@agents.postking.io"


def test_inboxes_create_with_domain(client):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert body["local_part"] == "support"
        assert body["domain_id"] == "d_1"
        return httpx.Response(
            status_code=201,
            json={"data": {"id": "i_2", "localPart": "support", "address": "support@example.com"}},
        )

    install_mock_transport(client, handler)
    inbox = client.inboxes.create(local_part="support", domain_id="d_1")
    assert inbox.id == "i_2"


def test_inboxes_remove(client):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        return httpx.Response(status_code=200, json={"data": {"ok": True}})

    install_mock_transport(client, handler)
    result = client.inboxes.remove("d_1", "i_1")
    assert result is True


def test_inboxes_set_webhook(client):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert body["webhook"]["endpoint"] == "https://hook.example.com"
        return httpx.Response(
            status_code=200,
            json={"data": {"id": "i_1", "localPart": "support", "address": "support@example.com"}},
        )

    install_mock_transport(client, handler)
    inbox = client.inboxes.set_webhook("d_1", "i_1", endpoint="https://hook.example.com")
    assert isinstance(inbox, Inbox)
