"""Shared test fixtures."""

from __future__ import annotations

from collections import defaultdict

import pytest

from src.detectors.base import DetectorRegistry
from src.detectors.engine import DetectionEngine
from src.detectors.pattern_detector import PatternDetector
from src.detectors.heuristic_detector import HeuristicDetector
from src.detectors.semantic_detector import SemanticDetector
from src.detectors.entropy_detector import EntropyDetector
from src.detectors.provenance_detector import ProvenanceDetector
from src.sanitizers.content_sanitizer import ContentSanitiser
from tests.helpers.fakes import FixedClockAdapter, InMemoryConfigAdapter, NullAuditAdapter


@pytest.fixture
def engine():
    """Engine with real detectors (backward-compatible, no DI)."""
    return DetectionEngine()


@pytest.fixture
def di_engine():
    """Engine wired with DI: FixedClockAdapter + full detector registry."""
    clock = FixedClockAdapter(timestamp=1000000.0, request_id="test-id-0001")
    registry = DetectorRegistry()
    registry.register(PatternDetector({}))
    registry.register(HeuristicDetector({}))
    registry.register(SemanticDetector({}))
    registry.register(EntropyDetector({}))
    registry.register(ProvenanceDetector({}))
    return DetectionEngine(clock=clock, registry=registry)


@pytest.fixture
def fixed_clock():
    """A FixedClockAdapter for deterministic tests."""
    return FixedClockAdapter(timestamp=1000000.0, request_id="test-id-0001")


@pytest.fixture
def null_audit():
    """A NullAuditAdapter that records calls for assertion."""
    return NullAuditAdapter()


@pytest.fixture
def sanitiser():
    return ContentSanitiser()
