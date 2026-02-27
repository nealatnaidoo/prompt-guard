"""Tests for security headers middleware.

Task: T018
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.middleware.security_headers import SecurityHeadersMiddleware, _SECURITY_HEADERS


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/test")
    async def test_endpoint():
        return {"ok": True}

    return app


class TestSecurityHeaders:
    """Verify all security headers are present on responses."""

    def test_x_content_type_options(self):
        with TestClient(_make_app()) as client:
            resp = client.get("/test")
            assert resp.headers["X-Content-Type-Options"] == "nosniff"

    def test_x_frame_options(self):
        with TestClient(_make_app()) as client:
            resp = client.get("/test")
            assert resp.headers["X-Frame-Options"] == "DENY"

    def test_strict_transport_security(self):
        with TestClient(_make_app()) as client:
            resp = client.get("/test")
            assert resp.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"

    def test_content_security_policy(self):
        with TestClient(_make_app()) as client:
            resp = client.get("/test")
            assert resp.headers["Content-Security-Policy"] == "default-src 'none'"

    def test_x_xss_protection(self):
        with TestClient(_make_app()) as client:
            resp = client.get("/test")
            assert resp.headers["X-XSS-Protection"] == "0"

    def test_all_headers_present(self):
        with TestClient(_make_app()) as client:
            resp = client.get("/test")
            for header, value in _SECURITY_HEADERS.items():
                assert resp.headers[header] == value, f"Missing or wrong: {header}"

    def test_headers_on_error_response(self):
        """Security headers should be present even on 404."""
        with TestClient(_make_app()) as client:
            resp = client.get("/nonexistent")
            assert resp.status_code == 404
            assert resp.headers["X-Content-Type-Options"] == "nosniff"
            assert resp.headers["X-Frame-Options"] == "DENY"
