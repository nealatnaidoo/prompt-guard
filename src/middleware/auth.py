"""Bearer token authentication middleware.

Validates requests using a constant-time comparison of the Bearer token
from the Authorization header against the PROMPT_GUARD_API_KEY environment
variable.

If the env var is unset, ALL requests are rejected (fail closed).
The /health and /v1/health endpoints are exempt from authentication.
"""

from __future__ import annotations

import hmac
import os

from fastapi import HTTPException, Request, status

# Paths exempt from authentication
_EXEMPT_PATHS: frozenset[str] = frozenset({"/health", "/v1/health"})


def _get_expected_key() -> str | None:
    """Read expected API key from environment. Returns None if unset."""
    return os.environ.get("PROMPT_GUARD_API_KEY")


def _extract_bearer_token(request: Request) -> str | None:
    """Extract Bearer token from the Authorization header.

    Returns None if the header is missing or does not use Bearer scheme.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0] != "Bearer":
        return None
    return parts[1] if parts[1] else None


async def require_api_key(
    request: Request,
) -> str | None:
    """FastAPI dependency that enforces Bearer token authentication.

    Returns the validated token on success, or None for exempt paths.
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

    # Extract Bearer token from Authorization header
    token = _extract_bearer_token(request)

    # Missing or empty token from client
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

    # Constant-time comparison
    if not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

    return token
