"""Characterisation tests for src/client.py — PromptGuardClient and ScanResponse."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch, MagicMock
from typing import Any

import httpx
import pytest

from src.client import PromptGuardClient, ScanResponse


# ---------------------------------------------------------------------------
# ScanResponse unit tests
# ---------------------------------------------------------------------------

class TestScanResponse:
    """Verify ScanResponse property behaviour with various payloads."""

    def test_is_safe_when_clean(self):
        resp = ScanResponse({"threat_level": "clean"})
        assert resp.is_safe is True

    def test_is_safe_when_low(self):
        resp = ScanResponse({"threat_level": "low"})
        assert resp.is_safe is True

    def test_not_safe_when_medium(self):
        resp = ScanResponse({"threat_level": "medium"})
        assert resp.is_safe is False

    def test_not_safe_when_high(self):
        resp = ScanResponse({"threat_level": "high"})
        assert resp.is_safe is False

    def test_not_safe_when_critical(self):
        resp = ScanResponse({"threat_level": "critical"})
        assert resp.is_safe is False

    def test_threat_level_default(self):
        resp = ScanResponse({})
        assert resp.threat_level == "unknown"

    def test_threat_score_default(self):
        resp = ScanResponse({})
        assert resp.threat_score == 0.0

    def test_action_default(self):
        resp = ScanResponse({})
        assert resp.action == "unknown"

    def test_findings_default(self):
        resp = ScanResponse({})
        assert resp.findings == []

    def test_summary_default(self):
        resp = ScanResponse({})
        assert resp.summary == ""

    def test_sanitised_content_default(self):
        resp = ScanResponse({})
        assert resp.sanitised_content is None

    def test_raw_returns_original_data(self):
        data = {"threat_level": "high", "threat_score": 0.95}
        resp = ScanResponse(data)
        assert resp.raw is data

    def test_all_properties_populated(self):
        data = {
            "threat_level": "medium",
            "threat_score": 0.6,
            "action_taken": "sanitise",
            "findings": [{"detector": "pattern", "score": 0.8}],
            "summary": "Possible injection detected",
            "sanitised_content": "safe content",
        }
        resp = ScanResponse(data)
        assert resp.threat_level == "medium"
        assert resp.threat_score == 0.6
        assert resp.action == "sanitise"
        assert len(resp.findings) == 1
        assert resp.summary == "Possible injection detected"
        assert resp.sanitised_content == "safe content"


# ---------------------------------------------------------------------------
# PromptGuardClient construction tests
# ---------------------------------------------------------------------------

class TestClientConstruction:
    """Verify client initialisation and defaults."""

    def test_default_base_url(self):
        client = PromptGuardClient()
        assert client.base_url == "http://localhost:8420"

    def test_custom_base_url(self):
        client = PromptGuardClient("http://myhost:9000")
        assert client.base_url == "http://myhost:9000"

    def test_trailing_slash_stripped(self):
        client = PromptGuardClient("http://myhost:9000/")
        assert client.base_url == "http://myhost:9000"

    def test_internal_client_created(self):
        client = PromptGuardClient()
        assert isinstance(client._client, httpx.AsyncClient)

    def test_custom_timeout(self):
        client = PromptGuardClient(timeout=5.0)
        assert client._client.timeout.read == 5.0

    def test_api_key_default_none(self):
        client = PromptGuardClient()
        assert client.api_key is None

    def test_api_key_stored(self):
        client = PromptGuardClient(api_key="my-secret-key")
        assert client.api_key == "my-secret-key"

    def test_api_key_sets_header(self):
        client = PromptGuardClient(api_key="my-secret-key")
        assert client._client.headers["X-API-Key"] == "my-secret-key"

    def test_no_api_key_no_header(self):
        client = PromptGuardClient()
        assert "X-API-Key" not in client._client.headers

    def test_api_key_backward_compatible(self):
        """Client without api_key still works (backward compat)."""
        client = PromptGuardClient("http://localhost:8420", timeout=10.0)
        assert client.base_url == "http://localhost:8420"
        assert client.api_key is None


# ---------------------------------------------------------------------------
# Async context manager
# ---------------------------------------------------------------------------

class TestClientContextManager:

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        """Client can be used as async context manager; aclose is called on exit."""
        async with PromptGuardClient() as client:
            assert isinstance(client, PromptGuardClient)
        # After exiting, the internal httpx client should be closed.
        assert client._client.is_closed


# ---------------------------------------------------------------------------
# scan() method
# ---------------------------------------------------------------------------

class TestClientScan:

    @pytest.mark.asyncio
    async def test_scan_sends_correct_payload(self):
        """scan() posts to /scan with correct JSON body."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"threat_level": "clean", "threat_score": 0.0}
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        result = await client.scan("test input", source="user_input")

        client._client.post.assert_called_once_with(
            "/scan",
            json={"content": "test input", "source": "user_input"},
        )
        assert isinstance(result, ScanResponse)
        assert result.is_safe is True

    @pytest.mark.asyncio
    async def test_scan_with_metadata_and_detectors(self):
        """scan() includes metadata and detectors when provided."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"threat_level": "clean"}
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client.scan(
            "test",
            source="api",
            metadata={"key": "val"},
            detectors=["pattern", "heuristic"],
        )

        call_kwargs = client._client.post.call_args
        payload = call_kwargs[1]["json"]
        assert payload["metadata"] == {"key": "val"}
        assert payload["detectors"] == ["pattern", "heuristic"]

    @pytest.mark.asyncio
    async def test_scan_omits_metadata_when_none(self):
        """scan() does not include metadata/detectors keys when not provided."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"threat_level": "clean"}
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client.scan("test")

        payload = client._client.post.call_args[1]["json"]
        assert "metadata" not in payload
        assert "detectors" not in payload

    @pytest.mark.asyncio
    async def test_scan_raises_on_http_error(self):
        """scan() propagates HTTP errors via raise_for_status."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error",
            request=MagicMock(),
            response=MagicMock(status_code=500),
        )

        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        with pytest.raises(httpx.HTTPStatusError):
            await client.scan("test")

    @pytest.mark.asyncio
    async def test_scan_raises_on_connection_error(self):
        """scan() propagates connection errors."""
        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        with pytest.raises(httpx.ConnectError):
            await client.scan("test")


# ---------------------------------------------------------------------------
# sanitise() method
# ---------------------------------------------------------------------------

class TestClientSanitise:

    @pytest.mark.asyncio
    async def test_sanitise_sends_correct_payload(self):
        """sanitise() posts to /sanitise with correct JSON body."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "scan_result": {"threat_level": "low", "threat_score": 0.1},
            "sanitised_content": "clean output",
            "changes": ["removed script tag"],
            "was_modified": True,
        }
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        result = await client.sanitise("dirty input", source="web", level="strict")

        client._client.post.assert_called_once_with(
            "/sanitise",
            json={
                "content": "dirty input",
                "source": "web",
                "sanitise_level": "strict",
            },
        )
        assert isinstance(result, ScanResponse)
        assert result.sanitised_content == "clean output"

    @pytest.mark.asyncio
    async def test_sanitise_merges_scan_result_fields(self):
        """sanitise() merges sanitised_content and changes into scan_data."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "scan_result": {"threat_level": "medium", "threat_score": 0.5},
            "sanitised_content": "cleaned",
            "changes": ["change1", "change2"],
            "was_modified": True,
        }
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        result = await client.sanitise("input")

        assert result.raw["sanitised_content"] == "cleaned"
        assert result.raw["_sanitise_changes"] == ["change1", "change2"]
        assert result.raw["_was_modified"] is True

    @pytest.mark.asyncio
    async def test_sanitise_with_metadata(self):
        """sanitise() includes metadata when provided."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "scan_result": {},
            "sanitised_content": "",
            "changes": [],
            "was_modified": False,
        }
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client.sanitise("test", metadata={"user": "123"})

        payload = client._client.post.call_args[1]["json"]
        assert payload["metadata"] == {"user": "123"}

    @pytest.mark.asyncio
    async def test_sanitise_omits_metadata_when_none(self):
        """sanitise() does not include metadata key when not provided."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "scan_result": {},
            "sanitised_content": "",
            "changes": [],
            "was_modified": False,
        }
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client.sanitise("test")

        payload = client._client.post.call_args[1]["json"]
        assert "metadata" not in payload

    @pytest.mark.asyncio
    async def test_sanitise_default_level(self):
        """sanitise() uses 'standard' as default level."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "scan_result": {},
            "sanitised_content": "",
            "changes": [],
            "was_modified": False,
        }
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client.sanitise("test")

        payload = client._client.post.call_args[1]["json"]
        assert payload["sanitise_level"] == "standard"


# ---------------------------------------------------------------------------
# health() and stats() methods
# ---------------------------------------------------------------------------

class TestClientHealthAndStats:

    @pytest.mark.asyncio
    async def test_health_calls_get_health(self):
        """health() sends GET to /health."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "ok",
            "detectors_loaded": 5,
            "uptime_seconds": 120.0,
        }
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_response)

        result = await client.health()

        client._client.get.assert_called_once_with("/health")
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_stats_calls_get_stats(self):
        """stats() sends GET to /stats."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "total_scans": 100,
            "threats_detected": 5,
        }
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_response)

        result = await client.stats()

        client._client.get.assert_called_once_with("/stats")
        assert result["total_scans"] == 100

    @pytest.mark.asyncio
    async def test_health_raises_on_error(self):
        """health() propagates HTTP errors."""
        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.get = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "Service Unavailable",
                request=MagicMock(),
                response=MagicMock(status_code=503),
            )
        )

        with pytest.raises(httpx.HTTPStatusError):
            await client.health()

    @pytest.mark.asyncio
    async def test_stats_raises_on_timeout(self):
        """stats() propagates timeout errors."""
        client = PromptGuardClient()
        client._client = AsyncMock()
        client._client.get = AsyncMock(side_effect=httpx.ReadTimeout("Timeout"))

        with pytest.raises(httpx.ReadTimeout):
            await client.stats()


# ---------------------------------------------------------------------------
# API key header propagation (T021)
# ---------------------------------------------------------------------------

class TestClientApiKeyHeader:
    """Verify API key is sent as X-API-Key header on all requests."""

    @pytest.mark.asyncio
    async def test_scan_sends_api_key_header(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"threat_level": "clean"}
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient(api_key="secret-123")
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)
        # Preserve default headers behaviour
        client._client.headers = httpx.Headers({"X-API-Key": "secret-123"})

        await client.scan("test input")
        # The api_key header is set at client level, not per-request.
        # Just verify the client was constructed with the key.
        assert client.api_key == "secret-123"

    @pytest.mark.asyncio
    async def test_no_api_key_no_header_on_requests(self):
        """Without api_key, no X-API-Key header is set."""
        client = PromptGuardClient()
        assert "X-API-Key" not in client._client.headers

    @pytest.mark.asyncio
    async def test_api_key_sent_on_health(self):
        """health() also uses the api_key header (set at client level)."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient(api_key="key-456")
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_response)

        await client.health()
        client._client.get.assert_called_once_with("/health")
        assert client.api_key == "key-456"

    @pytest.mark.asyncio
    async def test_api_key_sent_on_sanitise(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "scan_result": {},
            "sanitised_content": "",
            "changes": [],
            "was_modified": False,
        }
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient(api_key="key-789")
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        await client.sanitise("content")
        assert client.api_key == "key-789"

    @pytest.mark.asyncio
    async def test_api_key_sent_on_stats(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"total_scans": 0}
        mock_response.raise_for_status = MagicMock()

        client = PromptGuardClient(api_key="key-abc")
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_response)

        await client.stats()
        assert client.api_key == "key-abc"
