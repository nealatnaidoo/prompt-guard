"""Tests for Bearer token authentication middleware.

Task: T015
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from unittest.mock import patch

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from src.middleware.auth import require_api_key, _EXEMPT_PATHS, _extract_bearer_token


# ---------------------------------------------------------------------------
# Test app factory
# ---------------------------------------------------------------------------

def _make_auth_app(env_key: str | None = None) -> FastAPI:
    """Build a minimal FastAPI app with auth dependency for testing."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield

    test_app = FastAPI(lifespan=lifespan)

    @test_app.get("/health")
    async def health():
        return {"status": "ok"}

    @test_app.get("/v1/health")
    async def v1_health():
        return {"status": "ok"}

    @test_app.post("/scan")
    async def scan(request: Request, _key: str | None = Depends(require_api_key)):
        return {"result": "scanned"}

    @test_app.get("/stats")
    async def stats(_key: str | None = Depends(require_api_key)):
        return {"total": 0}

    return test_app


# ---------------------------------------------------------------------------
# Auth enforcement
# ---------------------------------------------------------------------------


class TestBearerAuth:
    """Verify Bearer token validation logic."""

    def test_valid_key_returns_200(self):
        with patch.dict(os.environ, {"PROMPT_GUARD_API_KEY": "secret-key-123"}):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.post(
                    "/scan",
                    json={},
                    headers={"Authorization": "Bearer secret-key-123"},
                )
                assert resp.status_code == 200

    def test_invalid_key_returns_401(self):
        with patch.dict(os.environ, {"PROMPT_GUARD_API_KEY": "secret-key-123"}):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.post(
                    "/scan",
                    json={},
                    headers={"Authorization": "Bearer wrong-key"},
                )
                assert resp.status_code == 401
                assert resp.json()["detail"] == "Invalid or missing API key"

    def test_missing_key_returns_401(self):
        with patch.dict(os.environ, {"PROMPT_GUARD_API_KEY": "secret-key-123"}):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.post("/scan", json={})
                assert resp.status_code == 401
                assert resp.json()["detail"] == "Invalid or missing API key"

    def test_empty_bearer_token_returns_401(self):
        with patch.dict(os.environ, {"PROMPT_GUARD_API_KEY": "secret-key-123"}):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.post(
                    "/scan",
                    json={},
                    headers={"Authorization": "Bearer "},
                )
                assert resp.status_code == 401

    def test_non_bearer_scheme_returns_401(self):
        """Authorization header with non-Bearer scheme should be rejected."""
        with patch.dict(os.environ, {"PROMPT_GUARD_API_KEY": "secret-key-123"}):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.post(
                    "/scan",
                    json={},
                    headers={"Authorization": "Basic secret-key-123"},
                )
                assert resp.status_code == 401


class TestFailClosed:
    """When PROMPT_GUARD_API_KEY is unset, reject all non-exempt requests."""

    def test_no_env_var_rejects_all(self):
        env = {k: v for k, v in os.environ.items() if k != "PROMPT_GUARD_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.post(
                    "/scan",
                    json={},
                    headers={"Authorization": "Bearer any-key"},
                )
                assert resp.status_code == 401

    def test_no_env_var_rejects_without_header(self):
        env = {k: v for k, v in os.environ.items() if k != "PROMPT_GUARD_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.get("/stats")
                assert resp.status_code == 401


class TestHealthExemption:
    """The /health and /v1/health endpoints must be accessible without authentication."""

    def test_health_exempt_when_no_env_var(self):
        env = {k: v for k, v in os.environ.items() if k != "PROMPT_GUARD_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.get("/health")
                assert resp.status_code == 200
                assert resp.json()["status"] == "ok"

    def test_health_exempt_with_env_var(self):
        with patch.dict(os.environ, {"PROMPT_GUARD_API_KEY": "secret"}):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.get("/health")
                assert resp.status_code == 200

    def test_health_exempt_no_key_header(self):
        with patch.dict(os.environ, {"PROMPT_GUARD_API_KEY": "secret"}):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.get("/health")
                assert resp.status_code == 200

    def test_v1_health_exempt_when_no_env_var(self):
        env = {k: v for k, v in os.environ.items() if k != "PROMPT_GUARD_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.get("/v1/health")
                assert resp.status_code == 200
                assert resp.json()["status"] == "ok"

    def test_v1_health_exempt_with_env_var(self):
        with patch.dict(os.environ, {"PROMPT_GUARD_API_KEY": "secret"}):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.get("/v1/health")
                assert resp.status_code == 200


class TestExemptPaths:
    """Verify exempt paths set."""

    def test_health_in_exempt_paths(self):
        assert "/health" in _EXEMPT_PATHS

    def test_v1_health_in_exempt_paths(self):
        assert "/v1/health" in _EXEMPT_PATHS

    def test_exempt_path_returns_none_through_dependency(self):
        """require_api_key returns None for exempt paths."""
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            yield

        app = FastAPI(lifespan=lifespan)

        @app.get("/health")
        async def health(key: str | None = Depends(require_api_key)):
            return {"status": "ok", "auth_result": key}

        env = {k: v for k, v in os.environ.items() if k != "PROMPT_GUARD_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            with TestClient(app) as client:
                resp = client.get("/health")
                assert resp.status_code == 200
                assert resp.json()["auth_result"] is None


class TestConstantTimeComparison:
    """Verify hmac.compare_digest is used (via functional test)."""

    def test_timing_safe_comparison_rejects_prefix(self):
        """Even a prefix of the real key must be rejected."""
        with patch.dict(os.environ, {"PROMPT_GUARD_API_KEY": "secret-key-123"}):
            app = _make_auth_app()
            with TestClient(app) as client:
                resp = client.post(
                    "/scan",
                    json={},
                    headers={"Authorization": "Bearer secret-key"},
                )
                assert resp.status_code == 401


class TestExtractBearerToken:
    """Unit tests for _extract_bearer_token helper."""

    def test_valid_bearer_token(self):
        from unittest.mock import MagicMock
        request = MagicMock()
        request.headers = {"Authorization": "Bearer my-token"}
        assert _extract_bearer_token(request) == "my-token"

    def test_missing_authorization_header(self):
        from unittest.mock import MagicMock
        request = MagicMock()
        request.headers = {}
        assert _extract_bearer_token(request) is None

    def test_non_bearer_scheme(self):
        from unittest.mock import MagicMock
        request = MagicMock()
        request.headers = {"Authorization": "Basic abc123"}
        assert _extract_bearer_token(request) is None

    def test_empty_bearer_value(self):
        from unittest.mock import MagicMock
        request = MagicMock()
        request.headers = {"Authorization": "Bearer "}
        assert _extract_bearer_token(request) is None

    def test_no_space_in_header(self):
        from unittest.mock import MagicMock
        request = MagicMock()
        request.headers = {"Authorization": "Bearertoken"}
        assert _extract_bearer_token(request) is None
