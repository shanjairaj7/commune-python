from __future__ import annotations

import httpx

from commune.types import Thread
from conftest import install_mock_transport


def test_threads_list_preserves_pagination_envelope(client):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/threads"
        assert request.url.params["inbox_id"] == "inbox_123"
        return httpx.Response(
            status_code=200,
            json={
                "data": [
                    {
                        "thread_id": "thread_1",
                        "subject": "Hello",
                        "last_message_at": "2026-02-12T00:00:00Z",
                        "message_count": 2,
                        "has_attachments": False,
                    }
                ],
                "next_cursor": "cursor_abc",
                "has_more": True,
            },
        )

    install_mock_transport(client, handler)

    result = client.threads.list(inbox_id="inbox_123", limit=20)

    assert result.next_cursor == "cursor_abc"
    assert result.has_more is True
    assert len(result.data) == 1
    assert isinstance(result.data[0], Thread)
    assert result.data[0].thread_id == "thread_1"
