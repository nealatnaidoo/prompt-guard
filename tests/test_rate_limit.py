"""Tests for rate limiting middleware.

Task: T016
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.middleware.rate_limit import RateLimitMiddleware, TokenBucket


# ---------------------------------------------------------------------------
# TokenBucket unit tests
# ---------------------------------------------------------------------------


class TestTokenBucket:
    """Verify token bucket algorithm."""

    def test_initial_tokens_equal_capacity(self):
        bucket = TokenBucket(capacity=10.0, refill_rate=2.0)
        assert bucket.tokens == 10.0

    def test_consume_reduces_tokens(self):
        bucket = TokenBucket(capacity=10.0, refill_rate=2.0)
        assert bucket.consume() is True
        assert bucket.tokens < 10.0

    def test_consume_fails_when_empty(self):
        bucket = TokenBucket(capacity=1.0, refill_rate=0.001)
        assert bucket.consume() is True
        assert bucket.consume() is False

    def test_tokens_refill_over_time(self):
        bucket = TokenBucket(capacity=5.0, refill_rate=100.0)
        # Drain all tokens
        for _ in range(5):
            bucket.consume()
        assert bucket.consume() is False
        # Wait for refill
        time.sleep(0.05)
        assert bucket.consume() is True

    def test_tokens_capped_at_capacity(self):
        bucket = TokenBucket(capacity=5.0, refill_rate=1000.0)
        time.sleep(0.01)
        bucket.consume()  # triggers refill
        assert bucket.tokens <= 5.0

    def test_retry_after_positive_when_empty(self):
        bucket = TokenBucket(capacity=1.0, refill_rate=1.0)
        bucket.consume()
        assert bucket.retry_after > 0.0

    def test_retry_after_zero_when_tokens_available(self):
        bucket = TokenBucket(capacity=5.0, refill_rate=1.0)
        assert bucket.retry_after == 0.0


# ---------------------------------------------------------------------------
# Middleware integration tests
# ---------------------------------------------------------------------------


def _make_rate_limit_app(
    requests_per_minute: int = 120,
    burst_size: int = 5,
) -> FastAPI:
    """Build a minimal app with rate limiting."""
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        requests_per_minute=requests_per_minute,
        burst_size=burst_size,
    )

    @app.get("/test")
    async def test_endpoint():
        return {"ok": True}

    return app


class TestRateLimitMiddleware:
    """Verify middleware behaviour."""

    def test_allows_requests_within_limit(self):
        app = _make_rate_limit_app(burst_size=10)
        with TestClient(app) as client:
            for _ in range(10):
                resp = client.get("/test")
                assert resp.status_code == 200

    def test_returns_429_when_burst_exceeded(self):
        app = _make_rate_limit_app(burst_size=3, requests_per_minute=60)
        with TestClient(app) as client:
            # Exhaust burst
            for _ in range(3):
                resp = client.get("/test")
                assert resp.status_code == 200
            # Next request should be rate limited
            resp = client.get("/test")
            assert resp.status_code == 429

    def test_429_response_body(self):
        app = _make_rate_limit_app(burst_size=1, requests_per_minute=60)
        with TestClient(app) as client:
            client.get("/test")
            resp = client.get("/test")
            assert resp.status_code == 429
            assert resp.json()["detail"] == "Rate limit exceeded"

    def test_429_has_retry_after_header(self):
        app = _make_rate_limit_app(burst_size=1, requests_per_minute=60)
        with TestClient(app, raise_server_exceptions=False) as client:
            client.get("/test")
            resp = client.get("/test")
            assert resp.status_code == 429
            assert "retry-after" in resp.headers

    def test_different_clients_have_separate_buckets(self):
        """Per-API-key limiting: different keys get independent limits."""
        app = _make_rate_limit_app(burst_size=1, requests_per_minute=60)
        with TestClient(app) as client:
            # Client A exhausts burst
            resp = client.get("/test", headers={"X-API-Key": "key-a"})
            assert resp.status_code == 200
            resp = client.get("/test", headers={"X-API-Key": "key-a"})
            assert resp.status_code == 429

            # Client B still has tokens
            resp = client.get("/test", headers={"X-API-Key": "key-b"})
            assert resp.status_code == 200

    def test_unknown_client_when_no_ip_or_key(self):
        """Line 81: fallback to 'ip:unknown' when request.client is None."""
        from unittest.mock import MagicMock
        middleware = RateLimitMiddleware(FastAPI())
        mock_request = MagicMock(spec=["headers", "client"])
        mock_request.headers = {}
        mock_request.client = None
        key = middleware._get_client_key(mock_request)
        assert key == "ip:unknown"

    def test_recovery_after_wait(self):
        app = _make_rate_limit_app(burst_size=1, requests_per_minute=6000)
        with TestClient(app) as client:
            client.get("/test")
            resp = client.get("/test")
            assert resp.status_code == 429
            # Wait for token refill (6000/min = 100/sec)
            time.sleep(0.02)
            resp = client.get("/test")
            assert resp.status_code == 200
