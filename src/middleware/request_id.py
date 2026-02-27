"""Request ID middleware.

Accepts X-Request-ID from incoming request headers. If not present,
generates a UUID4. Attaches to response headers and makes available
to downstream handlers via request.state.request_id.
"""

from __future__ import annotations

import uuid

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a unique request ID to every request/response cycle."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Use client-provided ID or generate one
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        # Make available to downstream handlers
        request.state.request_id = request_id

        response = await call_next(request)

        # Attach to response headers
        response.headers["X-Request-ID"] = request_id

        return response
