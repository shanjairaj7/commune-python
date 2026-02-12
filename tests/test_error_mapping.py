from __future__ import annotations

import httpx
import pytest

from commune import AuthenticationError, NotFoundError, RateLimitError, ValidationError
from commune.exceptions import PermissionError as CommunePermissionError
from conftest import install_mock_transport


@pytest.mark.parametrize(
    "status,exc_type",
    [
        (400, ValidationError),
        (401, AuthenticationError),
        (403, CommunePermissionError),
        (404, NotFoundError),
        (429, RateLimitError),
    ],
)
def test_status_codes_map_to_typed_exceptions(client, status, exc_type):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/domains"
        return httpx.Response(status_code=status, json={"error": "nope"})

    install_mock_transport(client, handler)

    with pytest.raises(exc_type):
        client.domains.list()
