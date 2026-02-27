"""Request logging middleware.

Logs every request with: method, path, status_code, latency_ms, request_id,
and client IP using structlog. Skips logging for /health to reduce noise.
"""

from __future__ import annotations

import time

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = structlog.get_logger("prompt_guard.access")

# Paths to skip logging (noisy health checks)
_SKIP_LOG_PATHS: frozenset[str] = frozenset({"/health"})


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log method, path, status, latency, request_id, and client IP."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path in _SKIP_LOG_PATHS:
            return await call_next(request)

        start = time.monotonic()
        response = await call_next(request)
        latency_ms = (time.monotonic() - start) * 1000.0

        # Get request_id from state (set by RequestIdMiddleware) or header
        request_id = getattr(request.state, "request_id", None) or request.headers.get(
            "X-Request-ID", "unknown"
        )

        client_ip = request.client.host if request.client else "unknown"

        logger.info(
            "http_request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            latency_ms=round(latency_ms, 2),
            request_id=request_id,
            client_ip=client_ip,
        )

        return response
