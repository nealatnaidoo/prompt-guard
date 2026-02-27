"""Fake/stub implementations of port interfaces for testing.

These adapters provide deterministic, in-memory behaviour suitable for
unit and integration tests.
"""

from __future__ import annotations

from typing import Any

from src.detectors.base import DetectorRegistry
from src.detectors.entropy_detector import EntropyDetector
from src.detectors.heuristic_detector import HeuristicDetector
from src.detectors.pattern_detector import PatternDetector
from src.detectors.provenance_detector import ProvenanceDetector
from src.detectors.semantic_detector import SemanticDetector
from src.models.schemas import ScanResult
from src.ports.audit import AuditPort
from src.ports.clock import ClockPort
from src.ports.config import ConfigPort


def build_default_registry(config: dict[str, Any] | None = None) -> DetectorRegistry:
    """Build a DetectorRegistry with all five default detectors.

    This mirrors the registration logic from the composition root (app.py lifespan).
    Use this in tests that need a fully-wired engine without going through FastAPI.
    """
    cfg = config or {}
    registry = DetectorRegistry()
    registry.register(PatternDetector(cfg.get("pattern_detector", {})))
    registry.register(HeuristicDetector(cfg.get("heuristic_detector", {})))
    registry.register(SemanticDetector(cfg.get("semantic_detector", {})))
    registry.register(EntropyDetector(cfg.get("entropy_detector", {})))
    registry.register(ProvenanceDetector(cfg.get("provenance_detector", {})))
    return registry


class FixedClockAdapter(ClockPort):
    """Clock that returns pre-configured fixed values.

    Useful for deterministic tests where timestamps and IDs must be predictable.
    """

    def __init__(self, timestamp: float = 1000000.0, request_id: str = "fixed-id-0001"):
        self._timestamp = timestamp
        self._request_id = request_id

    def now(self) -> float:
        return self._timestamp

    def generate_id(self) -> str:
        return self._request_id


class InMemoryConfigAdapter(ConfigPort):
    """Config adapter that returns a pre-set dictionary."""

    def __init__(self, config: dict[str, Any] | None = None):
        self._config = config or {}

    def load(self) -> dict[str, Any]:
        return dict(self._config)


class NullAuditAdapter(AuditPort):
    """Audit adapter that silently discards all log calls.

    Optionally records calls for assertion in tests.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[ScanResult, str | None, dict[str, Any] | None]] = []

    def log_scan(
        self,
        result: ScanResult,
        source_ip: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.calls.append((result, source_ip, extra))
