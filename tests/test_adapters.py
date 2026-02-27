"""Tests for driven adapter implementations.

Task: T007
"""

from __future__ import annotations

import json


from src.adapters.clock import SystemClockAdapter
from src.adapters.config import YamlFileConfigAdapter
from src.adapters.audit import JsonlFileAuditAdapter
from src.models.schemas import (
    DetectorFinding,
    PolicyAction,
    ScanResult,
    ThreatCategory,
    ThreatLevel,
)
from src.ports.audit import AuditPort
from src.ports.clock import ClockPort
from src.ports.config import ConfigPort


class TestSystemClockAdapter:

    def test_now_returns_float(self) -> None:
        clock = SystemClockAdapter()
        result = clock.now()
        assert isinstance(result, float)
        assert result > 0

    def test_generate_id_format(self) -> None:
        clock = SystemClockAdapter()
        id_val = clock.generate_id()
        assert isinstance(id_val, str)
        assert len(id_val) == 16
        # Should be valid hex
        int(id_val, 16)

    def test_generate_id_unique(self) -> None:
        clock = SystemClockAdapter()
        ids = {clock.generate_id() for _ in range(100)}
        assert len(ids) == 100

    def test_implements_clock_port(self) -> None:
        assert isinstance(SystemClockAdapter(), ClockPort)


class TestYamlFileConfigAdapter:

    def test_loads_default_config(self) -> None:
        adapter = YamlFileConfigAdapter()
        config = adapter.load()
        assert isinstance(config, dict)

    def test_loads_from_path(self, tmp_path) -> None:
        config_file = tmp_path / "test.yaml"
        config_file.write_text("key: value\nnested:\n  a: 1\n")
        adapter = YamlFileConfigAdapter(path=config_file)
        config = adapter.load()
        assert config["key"] == "value"
        assert config["nested"]["a"] == 1

    def test_missing_file_returns_empty(self, tmp_path) -> None:
        adapter = YamlFileConfigAdapter(path=tmp_path / "nonexistent.yaml")
        config = adapter.load()
        assert config == {}

    def test_implements_config_port(self) -> None:
        assert isinstance(YamlFileConfigAdapter(), ConfigPort)


class TestJsonlFileAuditAdapter:

    def test_writes_jsonl_to_file(self, tmp_path) -> None:
        log_file = tmp_path / "audit.jsonl"
        adapter = JsonlFileAuditAdapter(config={
            "enabled": True,
            "destination": "file",
            "log_file": str(log_file),
            "log_clean": True,
        })

        result = ScanResult(
            request_id="test-001",
            timestamp=1000.0,
            threat_level=ThreatLevel.HIGH,
            threat_score=0.8,
            action_taken=PolicyAction.QUARANTINE,
            findings=[
                DetectorFinding(
                    detector="pattern",
                    score=0.8,
                    category=ThreatCategory.INJECTION,
                    evidence="test evidence",
                )
            ],
        )
        adapter.log_scan(result, source_ip="1.2.3.4")

        assert log_file.exists()
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["request_id"] == "test-001"
        assert record["source_ip"] == "1.2.3.4"

    def test_implements_audit_port(self) -> None:
        adapter = JsonlFileAuditAdapter(config={"enabled": False})
        assert isinstance(adapter, AuditPort)

    def test_disabled_does_not_write(self, tmp_path) -> None:
        log_file = tmp_path / "audit.jsonl"
        adapter = JsonlFileAuditAdapter(config={
            "enabled": False,
            "log_file": str(log_file),
        })
        result = ScanResult(request_id="test", timestamp=0.0)
        adapter.log_scan(result)
        assert not log_file.exists()
