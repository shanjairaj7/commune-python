"""Commune SDK exceptions."""

from __future__ import annotations

from typing import Optional


class CommuneError(Exception):
    """Base exception for all Commune SDK errors.

    Attributes:
        message: Human-readable error description.
        status_code: HTTP status code from the API (if applicable).
    """

    def __init__(self, message: str, status_code: Optional[int] = None):
        self.message = message
        self.status_code = status_code
        super().__init__(message)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, status_code={self.status_code!r})"


class AuthenticationError(CommuneError):
    """Raised when authentication fails (401)."""

    def __init__(self, message: str = "Invalid or expired API key"):
        super().__init__(message, status_code=401)


class NotFoundError(CommuneError):
    """Raised when a resource is not found (404)."""

    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, status_code=404)


class ValidationError(CommuneError):
    """Raised when request validation fails (400)."""

    def __init__(self, message: str = "Invalid request"):
        super().__init__(message, status_code=400)


class PermissionDeniedError(CommuneError):
    """Raised when the API key lacks required permissions (403).

    .. note::
        Named ``PermissionDeniedError`` (not ``PermissionError``) to avoid
        shadowing the Python builtin ``PermissionError``.
    """

    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(message, status_code=403)


# Backward-compatible alias — use PermissionDeniedError in new code.
PermissionError = PermissionDeniedError  # type: ignore[assignment,misc]


class RateLimitError(CommuneError):
    """Raised when rate limits are exceeded (429)."""

    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message, status_code=429)
