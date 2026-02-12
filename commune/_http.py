"""Internal HTTP helper for the Commune SDK."""

from __future__ import annotations

import os
from typing import Any
from importlib.metadata import PackageNotFoundError, version as package_version

import httpx

from commune.exceptions import (
    AuthenticationError,
    CommuneError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    ValidationError,
)

DEFAULT_BASE_URL = os.getenv("COMMUNE_BASE_URL", "https://api.commune.sh")


def _resolve_sdk_version() -> str:
    try:
        return package_version("commune-mail")
    except PackageNotFoundError:
        return "0.2.0"


class HttpClient:
    """Low-level HTTP client wrapping httpx."""

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        timeout: float = 30.0,
    ):
        self._base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"commune-mail-python/{_resolve_sdk_version()}",
            },
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def _handle_error(self, response: httpx.Response) -> None:
        """Raise the appropriate exception based on HTTP status."""
        try:
            body = response.json()
        except Exception:
            body = {}

        message = (
            body.get("error", {}).get("message")
            if isinstance(body.get("error"), dict)
            else body.get("error")
        ) or response.reason_phrase or "Unknown error"

        status = response.status_code
        if status == 401:
            raise AuthenticationError(str(message))
        if status == 403:
            raise PermissionDeniedError(str(message))
        if status == 404:
            raise NotFoundError(str(message))
        if status == 400:
            raise ValidationError(str(message))
        if status == 429:
            raise RateLimitError(str(message))
        raise CommuneError(str(message), status_code=status)

    def _unwrap(self, response: httpx.Response, *, unwrap_data: bool = True) -> Any:
        """Unwrap response JSON, extracting `data` if present."""
        if not response.is_success:
            self._handle_error(response)

        try:
            body = response.json()
        except Exception:
            return {}

        # The API usually wraps results in { data: ... }.
        # Callers can opt out when they need the full envelope.
        if unwrap_data and isinstance(body, dict) and "data" in body:
            return body["data"]
        return body

    def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        unwrap_data: bool = True,
    ) -> Any:
        """Perform a GET request."""
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        resp = self._client.get(path, params=clean_params or None)
        return self._unwrap(resp, unwrap_data=unwrap_data)

    def post(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        *,
        unwrap_data: bool = True,
    ) -> Any:
        """Perform a POST request."""
        resp = self._client.post(path, json=json)
        return self._unwrap(resp, unwrap_data=unwrap_data)

    def put(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        *,
        unwrap_data: bool = True,
    ) -> Any:
        """Perform a PUT request."""
        resp = self._client.put(path, json=json)
        return self._unwrap(resp, unwrap_data=unwrap_data)

    def delete(self, path: str, *, unwrap_data: bool = True) -> Any:
        """Perform a DELETE request."""
        resp = self._client.delete(path)
        return self._unwrap(resp, unwrap_data=unwrap_data)
