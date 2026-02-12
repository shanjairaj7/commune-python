from __future__ import annotations

import json

import httpx

from commune.types import DomainDnsRecord
from conftest import install_mock_transport


def test_messages_send_serializes_alias_fields(client):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/messages/send":
            captured.update(json.loads(request.content.decode("utf-8")))
            return httpx.Response(
                status_code=200,
                json={
                    "data": {
                        "id": "msg_db_id",
                        "message_id": "msg_123",
                        "thread_id": "thread_123",
                        "status": "queued",
                    }
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    install_mock_transport(client, handler)

    result = client.messages.send(
        to="user@example.com",
        subject="Hello",
        text="Hi",
        domain_id="domain_1",
        inbox_id="inbox_1",
        from_address="support@example.com",
        headers={"X-Test": "1"},
    )

    assert captured["domainId"] == "domain_1"
    assert captured["inboxId"] == "inbox_1"
    assert captured["from"] == "support@example.com"
    assert "domain_id" not in captured
    assert "inbox_id" not in captured
    assert "from_address" not in captured

    assert result.message_id == "msg_123"
    assert result.get("thread_id") == "thread_123"


def test_attachment_upload_and_url_parsing(client):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/attachments/upload":
            body = json.loads(request.content.decode("utf-8"))
            assert body == {
                "content": "YmFzZTY0",
                "filename": "a.txt",
                "mime_type": "text/plain",
            }
            return httpx.Response(
                status_code=201,
                json={
                    "data": {
                        "attachment_id": "att_1",
                        "filename": "a.txt",
                        "mime_type": "text/plain",
                        "size": 7,
                        "storage_type": "database",
                    }
                },
            )

        if request.url.path == "/v1/attachments/att_1/url":
            return httpx.Response(
                status_code=200,
                json={
                    "data": {
                        "url": "https://download.example/att_1",
                        "expires_in": 7200,
                        "filename": "a.txt",
                        "mime_type": "text/plain",
                        "size": 7,
                    }
                },
            )

        raise AssertionError(f"Unexpected path: {request.url.path}")

    install_mock_transport(client, handler)

    upload = client.attachments.upload("YmFzZTY0", "a.txt", "text/plain")
    url_info = client.attachments.url("att_1", expires_in=7200)

    assert upload.attachment_id == "att_1"
    assert upload.storage_type == "database"
    assert url_info.expires_in == 7200
    assert url_info.mime_type == "text/plain"


def test_domain_records_are_typed_models(client):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/domains/domain_1/records"
        return httpx.Response(
            status_code=200,
            json={
                "data": [
                    {
                        "record": "SPF",
                        "type": "TXT",
                        "name": "example.com",
                        "value": "v=spf1 include:amazonses.com ~all",
                        "status": "pending",
                        "ttl": "Auto",
                        "provider_hint": "copy exactly",
                    }
                ]
            },
        )

    install_mock_transport(client, handler)

    records = client.domains.records("domain_1")

    assert len(records) == 1
    assert isinstance(records[0], DomainDnsRecord)
    assert records[0].record == "SPF"
    assert records[0].get("provider_hint") == "copy exactly"
