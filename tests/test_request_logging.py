"""Tests for request logging middleware.

Task: T019
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.middleware.request_logging import RequestLoggingMiddleware, _SKIP_LOG_PATHS


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/test")
    async def test_endpoint():
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/scan")
    async def scan():
        return {"scanned": True}

    return app


class TestRequestLogging:
    """Verify request logging behaviour."""

    def test_logs_request_info(self):
        app = _make_app()
        with patch("src.middleware.request_logging.logger") as mock_logger:
            with TestClient(app) as client:
                resp = client.get("/test")
                assert resp.status_code == 200

            mock_logger.info.assert_called_once()
            call_kwargs = mock_logger.info.call_args
            # First positional arg is event name
            assert call_kwargs[0][0] == "http_request"
            # Check keyword args
            kw = call_kwargs[1]
            assert kw["method"] == "GET"
            assert kw["path"] == "/test"
            assert kw["status_code"] == 200
            assert "latency_ms" in kw
            assert isinstance(kw["latency_ms"], float)
            assert "request_id" in kw
            assert "client_ip" in kw

    def test_logs_post_method(self):
        app = _make_app()
        with patch("src.middleware.request_logging.logger") as mock_logger:
            with TestClient(app) as client:
                client.post("/scan")

            kw = mock_logger.info.call_args[1]
            assert kw["method"] == "POST"
            assert kw["path"] == "/scan"

    def test_skips_health_logging(self):
        app = _make_app()
        with patch("src.middleware.request_logging.logger") as mock_logger:
            with TestClient(app) as client:
                resp = client.get("/health")
                assert resp.status_code == 200

            mock_logger.info.assert_not_called()

    def test_health_in_skip_paths(self):
        assert "/health" in _SKIP_LOG_PATHS

    def test_logs_status_code_for_errors(self):
        app = _make_app()
        with patch("src.middleware.request_logging.logger") as mock_logger:
            with TestClient(app) as client:
                resp = client.get("/nonexistent")
                assert resp.status_code == 404

            kw = mock_logger.info.call_args[1]
            assert kw["status_code"] == 404

    def test_latency_is_positive(self):
        app = _make_app()
        with patch("src.middleware.request_logging.logger") as mock_logger:
            with TestClient(app) as client:
                client.get("/test")

            kw = mock_logger.info.call_args[1]
            assert kw["latency_ms"] >= 0.0

    def test_uses_request_id_from_state(self):
        """When RequestIdMiddleware sets request.state.request_id, logging uses it."""
        from src.middleware.request_id import RequestIdMiddleware

        app = FastAPI()
        # Add logging outside, request_id inside (logging runs first in middleware stack)
        app.add_middleware(RequestLoggingMiddleware)
        app.add_middleware(RequestIdMiddleware)

        @app.get("/test")
        async def test_endpoint():
            return {"ok": True}

        with patch("src.middleware.request_logging.logger") as mock_logger:
            with TestClient(app) as client:
                client.get("/test", headers={"X-Request-ID": "custom-req-123"})

            kw = mock_logger.info.call_args[1]
            assert kw["request_id"] == "custom-req-123"
