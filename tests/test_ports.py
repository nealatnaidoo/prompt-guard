"""Port contract tests — verify fake adapters implement their ports correctly.

Task: T006
"""

from __future__ import annotations

from src.models.schemas import ScanResult
from src.ports.audit import AuditPort
from src.ports.clock import ClockPort
from src.ports.config import ConfigPort
from tests.helpers.fakes import FixedClockAdapter, InMemoryConfigAdapter, NullAuditAdapter


class TestFixedClockAdapter:

    def test_returns_configured_timestamp(self) -> None:
        clock = FixedClockAdapter(timestamp=12345.0)
        assert clock.now() == 12345.0

    def test_returns_configured_request_id(self) -> None:
        clock = FixedClockAdapter(request_id="test-id-abc")
        assert clock.generate_id() == "test-id-abc"

    def test_implements_clock_port(self) -> None:
        clock = FixedClockAdapter()
        assert isinstance(clock, ClockPort)

    def test_default_values(self) -> None:
        clock = FixedClockAdapter()
        assert clock.now() == 1000000.0
        assert clock.generate_id() == "fixed-id-0001"


class TestInMemoryConfigAdapter:

    def test_returns_configured_dict(self) -> None:
        config = InMemoryConfigAdapter(config={"key": "value", "nested": {"a": 1}})
        result = config.load()
        assert result == {"key": "value", "nested": {"a": 1}}

    def test_returns_empty_dict_by_default(self) -> None:
        config = InMemoryConfigAdapter()
        assert config.load() == {}

    def test_implements_config_port(self) -> None:
        config = InMemoryConfigAdapter()
        assert isinstance(config, ConfigPort)

    def test_returns_copy(self) -> None:
        """Modifying the returned dict should not affect future calls."""
        config = InMemoryConfigAdapter(config={"key": "value"})
        result1 = config.load()
        result1["key"] = "mutated"
        result2 = config.load()
        assert result2["key"] == "value"


class TestNullAuditAdapter:

    def test_does_not_raise(self) -> None:
        audit = NullAuditAdapter()
        result = ScanResult(request_id="test", timestamp=0.0)
        audit.log_scan(result)  # should not raise

    def test_records_calls(self) -> None:
        audit = NullAuditAdapter()
        result = ScanResult(request_id="test", timestamp=0.0)
        audit.log_scan(result, source_ip="127.0.0.1", extra={"k": "v"})
        assert len(audit.calls) == 1
        assert audit.calls[0][1] == "127.0.0.1"
        assert audit.calls[0][2] == {"k": "v"}

    def test_implements_audit_port(self) -> None:
        audit = NullAuditAdapter()
        assert isinstance(audit, AuditPort)
