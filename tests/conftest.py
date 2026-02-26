"""Shared test fixtures."""

import pytest
from prompt_guard.src.detectors.engine import DetectionEngine
from prompt_guard.src.sanitizers.content_sanitizer import ContentSanitiser


@pytest.fixture
def engine():
    return DetectionEngine()


@pytest.fixture
def sanitiser():
    return ContentSanitiser()
