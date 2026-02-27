"""Tests for Request ID middleware.

Task: T017
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.middleware.request_id import RequestIdMiddleware


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestIdMiddleware)

    @app.get("/test")
    async def test_endpoint(request: Request):
        return {"request_id": request.state.request_id}

    return app


class TestRequestIdMiddleware:
    """Verify request ID assignment and propagation."""

    def test_generates_uuid_when_no_header(self):
        app = _make_app()
        with TestClient(app) as client:
            resp = client.get("/test")
            assert resp.status_code == 200
            rid = resp.headers["X-Request-ID"]
            # Should be a valid UUID4
            parsed = uuid.UUID(rid)
            assert parsed.version == 4

    def test_uses_client_provided_id(self):
        app = _make_app()
        with TestClient(app) as client:
            resp = client.get("/test", headers={"X-Request-ID": "my-custom-id-123"})
            assert resp.status_code == 200
            assert resp.headers["X-Request-ID"] == "my-custom-id-123"

    def test_request_state_has_request_id(self):
        app = _make_app()
        with TestClient(app) as client:
            resp = client.get("/test", headers={"X-Request-ID": "state-test-id"})
            assert resp.status_code == 200
            assert resp.json()["request_id"] == "state-test-id"

    def test_generated_id_in_request_state(self):
        app = _make_app()
        with TestClient(app) as client:
            resp = client.get("/test")
            assert resp.status_code == 200
            body_id = resp.json()["request_id"]
            header_id = resp.headers["X-Request-ID"]
            assert body_id == header_id

    def test_each_request_gets_unique_id(self):
        app = _make_app()
        with TestClient(app) as client:
            ids = set()
            for _ in range(10):
                resp = client.get("/test")
                ids.add(resp.headers["X-Request-ID"])
            assert len(ids) == 10

    def test_empty_header_generates_new_id(self):
        app = _make_app()
        with TestClient(app) as client:
            resp = client.get("/test", headers={"X-Request-ID": ""})
            assert resp.status_code == 200
            rid = resp.headers["X-Request-ID"]
            # Empty string is falsy, so a new UUID should be generated
            uuid.UUID(rid)  # validates it's a UUID
