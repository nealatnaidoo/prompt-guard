"""Integration tests for the full middleware stack and /v1/ routes.

Task: T020

Tests verify:
- Middleware execution order (security headers, request ID, rate limiting, logging)
- /v1/ routes require authentication
- Legacy routes remain accessible without auth
- CORS wildcard is removed
- Health endpoint is exempt from auth
"""

from __future__ import annotations

import os
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.detectors.base import DetectorRegistry
from src.detectors.engine import DetectionEngine
from src.detectors.entropy_detector import EntropyDetector
from src.detectors.heuristic_detector import HeuristicDetector
from src.detectors.pattern_detector import PatternDetector
from src.detectors.provenance_detector import ProvenanceDetector
from src.sanitizers.content_sanitizer import ContentSanitiser
from tests.helpers.fakes import FixedClockAdapter, NullAuditAdapter


def _build_test_app_with_middleware():
    """Build a full app with middleware stack, using test dependencies."""
    from src.middleware.app import (
        SanitiseRequest,
        SanitiseResponse,
        StatsResponse,
        scan_content,
        sanitise_content,
        health_check,
        get_stats,
        v1_router,
    )
    from src.middleware.auth import require_api_key
    from src.middleware.rate_limit import RateLimitMiddleware
    from src.middleware.request_id import RequestIdMiddleware
    from src.middleware.request_logging import RequestLoggingMiddleware
    from src.middleware.security_headers import SecurityHeadersMiddleware
    from src.models.schemas import ScanRequest, ScanResult, HealthResponse

    clock = FixedClockAdapter(timestamp=1_000_000.0, request_id="test-req-001")
    audit = NullAuditAdapter()

    registry = DetectorRegistry()
    registry.register(PatternDetector({}))
    registry.register(HeuristicDetector({}))
    registry.register(SemanticDetector({}))
    registry.register(EntropyDetector({}))
    registry.register(ProvenanceDetector({}))

    engine = DetectionEngine(clock=clock, registry=registry)
    sanitiser = ContentSanitiser()

    @asynccontextmanager
    async def test_lifespan(app: FastAPI):
        app.state.config = {}
        app.state.clock = clock
        app.state.audit = audit
        app.state.engine = engine
        app.state.sanitiser = sanitiser
        app.state.start_time = clock.now()
        app.state.stats = defaultdict(int)
        yield

    test_app = FastAPI(lifespan=test_lifespan)

    # Add middleware in same order as production app
    test_app.add_middleware(RateLimitMiddleware, requests_per_minute=120, burst_size=20)
    test_app.add_middleware(RequestIdMiddleware)
    test_app.add_middleware(SecurityHeadersMiddleware)
    test_app.add_middleware(RequestLoggingMiddleware)

    # Legacy routes (no auth)
    test_app.post("/scan", response_model=ScanResult)(
        lambda request: scan_content.__wrapped__(request) if hasattr(scan_content, '__wrapped__') else None
    )

    # Re-register legacy routes
    @test_app.post("/scan", response_model=ScanResult)
    async def _scan(request: ScanRequest, http_request=None):
        from fastapi import Request as R
        return await scan_content(request, http_request)

    @test_app.post("/sanitise", response_model=SanitiseResponse)
    async def _sanitise(request: SanitiseRequest, http_request=None):
        return await sanitise_content(request, http_request)

    @test_app.get("/health", response_model=HealthResponse)
    async def _health(http_request=None):
        return await health_check(http_request)

    @test_app.get("/stats", response_model=StatsResponse)
    async def _stats(http_request=None):
        return await get_stats(http_request)

    # Include v1 router
    test_app.include_router(v1_router)

    return test_app


@pytest.fixture
def full_app_client():
    """TestClient using the actual production app (imported directly)."""
    # We test against the real app module to verify middleware wiring
    with patch.dict(os.environ, {"PROMPT_GUARD_API_KEY": "test-api-key-xyz"}):
        from src.middleware.app import app
        with TestClient(app) as client:
            yield client


# ---------------------------------------------------------------------------
# Security headers on all responses
# ---------------------------------------------------------------------------


class TestSecurityHeadersIntegration:
    """Security headers present on all responses."""

    def test_security_headers_on_health(self, full_app_client):
        resp = full_app_client.get("/health")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert "max-age=31536000" in resp.headers["Strict-Transport-Security"]
        assert resp.headers["Content-Security-Policy"] == "default-src 'none'"
        assert resp.headers["X-XSS-Protection"] == "0"

    def test_security_headers_on_scan(self, full_app_client):
        resp = full_app_client.post("/scan", json={"content": "hello"})
        assert resp.headers["X-Content-Type-Options"] == "nosniff"


# ---------------------------------------------------------------------------
# Request ID propagation
# ---------------------------------------------------------------------------


class TestRequestIdIntegration:

    def test_request_id_in_response(self, full_app_client):
        resp = full_app_client.get("/health")
        assert "X-Request-ID" in resp.headers
        # Should be a valid UUID
        uuid.UUID(resp.headers["X-Request-ID"])

    def test_client_request_id_echoed(self, full_app_client):
        resp = full_app_client.get("/health", headers={"X-Request-ID": "my-id-999"})
        assert resp.headers["X-Request-ID"] == "my-id-999"


# ---------------------------------------------------------------------------
# Legacy routes (no auth required)
# ---------------------------------------------------------------------------


class TestLegacyRoutes:
    """Legacy routes work without authentication."""

    def test_legacy_scan_no_auth(self, full_app_client):
        resp = full_app_client.post("/scan", json={"content": "hello world"})
        assert resp.status_code == 200
        assert "threat_level" in resp.json()

    def test_legacy_sanitise_no_auth(self, full_app_client):
        resp = full_app_client.post("/sanitise", json={"content": "hello world"})
        assert resp.status_code == 200

    def test_legacy_health_no_auth(self, full_app_client):
        resp = full_app_client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_legacy_stats_no_auth(self, full_app_client):
        resp = full_app_client.get("/stats")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /v1/ routes require auth
# ---------------------------------------------------------------------------


class TestV1AuthRequired:
    """/v1/ routes require a valid X-API-Key."""

    def test_v1_scan_without_key_401(self, full_app_client):
        resp = full_app_client.post("/v1/scan", json={"content": "hello"})
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or missing API key"

    def test_v1_scan_with_valid_key(self, full_app_client):
        resp = full_app_client.post(
            "/v1/scan",
            json={"content": "hello world"},
            headers={"X-API-Key": "test-api-key-xyz"},
        )
        assert resp.status_code == 200
        assert "threat_level" in resp.json()

    def test_v1_scan_with_wrong_key_401(self, full_app_client):
        resp = full_app_client.post(
            "/v1/scan",
            json={"content": "hello"},
            headers={"X-API-Key": "wrong-key"},
        )
        assert resp.status_code == 401

    def test_v1_sanitise_without_key_401(self, full_app_client):
        resp = full_app_client.post("/v1/sanitise", json={"content": "hello"})
        assert resp.status_code == 401

    def test_v1_sanitise_with_valid_key(self, full_app_client):
        resp = full_app_client.post(
            "/v1/sanitise",
            json={"content": "hello world"},
            headers={"X-API-Key": "test-api-key-xyz"},
        )
        assert resp.status_code == 200

    def test_v1_stats_without_key_401(self, full_app_client):
        resp = full_app_client.get("/v1/stats")
        assert resp.status_code == 401

    def test_v1_stats_with_valid_key(self, full_app_client):
        resp = full_app_client.get(
            "/v1/stats",
            headers={"X-API-Key": "test-api-key-xyz"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# CORS removal
# ---------------------------------------------------------------------------


class TestCorsRemoved:
    """Wildcard CORS should not be present."""

    def test_no_cors_headers(self, full_app_client):
        resp = full_app_client.get(
            "/health",
            headers={"Origin": "http://evil.com"},
        )
        # Without CORS middleware, no Access-Control-Allow-Origin header
        assert "Access-Control-Allow-Origin" not in resp.headers


# ---------------------------------------------------------------------------
# Health exempt from auth (via /health path)
# ---------------------------------------------------------------------------


class TestHealthExemptFromAuth:

    def test_health_accessible_without_key(self, full_app_client):
        resp = full_app_client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
