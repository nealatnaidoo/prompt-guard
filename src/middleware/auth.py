"""API Key authentication middleware.

Validates requests using a constant-time comparison of the X-API-Key header
against the PROMPT_GUARD_API_KEY environment variable.

If the env var is unset, ALL requests are rejected (fail closed).
The /health endpoint is exempt from authentication.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Paths exempt from authentication
_EXEMPT_PATHS: frozenset[str] = frozenset({"/health"})


def _get_expected_key() -> str | None:
    """Read expected API key from environment. Returns None if unset."""
    return os.environ.get("PROMPT_GUARD_API_KEY")


async def require_api_key(
    request: Request,
    api_key: str | None = Depends(_API_KEY_HEADER),
) -> str | None:
    """FastAPI dependency that enforces API key authentication.

    Returns the validated API key on success, or None for exempt paths.
    Raises HTTP 401 on failure.
    """
    # Exempt paths skip auth
    if request.url.path in _EXEMPT_PATHS:
        return None

    expected = _get_expected_key()

    # Fail closed: if no key configured, reject everything
    if expected is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

    # Missing or empty key from client
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

    # Constant-time comparison
    if not hmac.compare_digest(api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

    return api_key
