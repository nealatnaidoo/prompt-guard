"""Shared test fixtures."""

from __future__ import annotations


import pytest

from src.detectors.base import DetectorRegistry
from src.detectors.engine import DetectionEngine
from src.detectors.pattern_detector import PatternDetector
from src.detectors.heuristic_detector import HeuristicDetector
from src.detectors.semantic_detector import SemanticDetector
from src.detectors.entropy_detector import EntropyDetector
from src.detectors.provenance_detector import ProvenanceDetector
from src.sanitizers.content_sanitizer import ContentSanitiser
from tests.helpers.fakes import FixedClockAdapter, NullAuditAdapter, build_default_registry


@pytest.fixture
def full_registry():
    """A DetectorRegistry pre-loaded with all five default detectors."""
    return build_default_registry()


@pytest.fixture
def engine(full_registry):
    """Engine with real detectors and injected registry."""
    return DetectionEngine(registry=full_registry)


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
