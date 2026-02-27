"""Async Python client for integrating Prompt Guard into your agent pipeline.

Usage:
    from prompt_guard.client import PromptGuardClient

    async with PromptGuardClient("http://localhost:8420") as guard:
        result = await guard.scan("some user input", source="user_input")
        if result.is_safe:
            # feed to your model
            ...
        else:
            print(f"Blocked: {result.summary}")
"""

from __future__ import annotations

import httpx
from typing import Any


class ScanResponse:
    """Wrapper around the scan API response for ergonomic usage."""

    def __init__(self, data: dict[str, Any]):
        self._data = data

    @property
    def is_safe(self) -> bool:
        return self._data.get("threat_level") in ("clean", "low")

    @property
    def threat_level(self) -> str:
        return self._data.get("threat_level", "unknown")

    @property
    def threat_score(self) -> float:
        return self._data.get("threat_score", 0.0)

    @property
    def action(self) -> str:
        return self._data.get("action_taken", "unknown")

    @property
    def findings(self) -> list[dict]:
        return self._data.get("findings", [])

    @property
    def summary(self) -> str:
        return self._data.get("summary", "")

    @property
    def sanitised_content(self) -> str | None:
        return self._data.get("sanitised_content")

    @property
    def raw(self) -> dict[str, Any]:
        return self._data


class PromptGuardClient:
    """Async HTTP client for the Prompt Guard service.

    Use as an async context manager for connection pooling:

        async with PromptGuardClient(base_url) as client:
            result = await client.scan(content)
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8420",
        timeout: float = 30.0,
        api_key: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        headers: dict[str, str] = {}
        if api_key:
            headers["X-API-Key"] = api_key
        self._client = httpx.AsyncClient(
            base_url=self.base_url, timeout=timeout, headers=headers
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self._client.aclose()

    async def scan(
        self,
        content: str,
        source: str = "unknown",
        metadata: dict[str, Any] | None = None,
        detectors: list[str] | None = None,
    ) -> ScanResponse:
        """Scan content for threats."""
        payload: dict[str, Any] = {
            "content": content,
            "source": source,
        }
        if metadata:
            payload["metadata"] = metadata
        if detectors:
            payload["detectors"] = detectors

        resp = await self._client.post("/scan", json=payload)
        resp.raise_for_status()
        return ScanResponse(resp.json())

    async def sanitise(
        self,
        content: str,
        source: str = "unknown",
        level: str = "standard",
        metadata: dict[str, Any] | None = None,
    ) -> ScanResponse:
        """Scan and sanitise content."""
        payload: dict[str, Any] = {
            "content": content,
            "source": source,
            "sanitise_level": level,
        }
        if metadata:
            payload["metadata"] = metadata

        resp = await self._client.post("/sanitise", json=payload)
        resp.raise_for_status()
        data = resp.json()
        # Merge sanitised_content into scan_result for unified response
        scan_data = data.get("scan_result", {})
        scan_data["sanitised_content"] = data.get("sanitised_content")
        scan_data["_sanitise_changes"] = data.get("changes", [])
        scan_data["_was_modified"] = data.get("was_modified", False)
        return ScanResponse(scan_data)

    async def health(self) -> dict[str, Any]:
        """Check service health."""
        resp = await self._client.get("/health")
        resp.raise_for_status()
        return resp.json()

    async def stats(self) -> dict[str, Any]:
        """Get runtime statistics."""
        resp = await self._client.get("/stats")
        resp.raise_for_status()
        return resp.json()
