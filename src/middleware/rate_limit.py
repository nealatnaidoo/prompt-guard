"""Rate limiting middleware using an in-memory token bucket algorithm.

Limits requests per-IP (or per-API-key when available). Configuration is
read from config/default.yaml rate_limiting section.

Returns 429 with Retry-After header when limit is exceeded.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


@dataclass
class TokenBucket:
    """Simple token bucket for rate limiting."""

    capacity: float
    refill_rate: float  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def consume(self) -> bool:
        """Try to consume one token. Returns True if allowed, False if rate limited."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    @property
    def retry_after(self) -> float:
        """Seconds until next token is available."""
        if self.tokens >= 1.0:
            return 0.0
        deficit = 1.0 - self.tokens
        return deficit / self.refill_rate


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-client rate limiting middleware using token bucket algorithm.

    Config keys (from rate_limiting section):
        requests_per_minute: int  (default 120)
        burst_size: int           (default 20)
    """

    def __init__(
        self,
        app: Any,
        requests_per_minute: int = 120,
        burst_size: int = 20,
    ) -> None:
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.refill_rate = requests_per_minute / 60.0  # tokens per second
        self._buckets: dict[str, TokenBucket] = {}

    def _get_client_key(self, request: Request) -> str:
        """Determine rate limit key: Bearer token if present, else client IP."""
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if token:
                return f"key:{token}"
        if request.client:
            return f"ip:{request.client.host}"
        return "ip:unknown"

    def _get_bucket(self, client_key: str) -> TokenBucket:
        """Get or create a token bucket for the client."""
        if client_key not in self._buckets:
            self._buckets[client_key] = TokenBucket(
                capacity=float(self.burst_size),
                refill_rate=self.refill_rate,
            )
        return self._buckets[client_key]

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        client_key = self._get_client_key(request)
        bucket = self._get_bucket(client_key)

        if not bucket.consume():
            retry_after = max(1, int(bucket.retry_after) + 1)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)
