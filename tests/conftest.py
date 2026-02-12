from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from commune import CommuneClient


@pytest.fixture
def client() -> CommuneClient:
    sdk_client = CommuneClient(api_key="comm_test")
    yield sdk_client
    sdk_client.close()


def install_mock_transport(client: CommuneClient, handler: Callable[[httpx.Request], httpx.Response]) -> None:
    original_client = client._http._client
    headers = dict(original_client.headers)
    original_client.close()
    client._http._client = httpx.Client(
        base_url=client._http._base_url,
        headers=headers,
        transport=httpx.MockTransport(handler),
    )
