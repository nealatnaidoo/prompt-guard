"""Base types for benchmark datasets."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Sample:
    """Normalised benchmark sample."""

    text: str
    is_malicious: bool
    category: str = "unknown"
    dataset: str = ""
    original_label: str = ""


@dataclass
class ScanOutcome:
    """Result of scanning one sample."""

    sample: Sample
    predicted_malicious: bool
    threat_level: str
    threat_score: float
    findings: list[dict] = field(default_factory=list)
    latency_ms: float = 0.0


class DatasetAdapter(ABC):
    """Base class for dataset downloaders/parsers."""

    name: str = ""
    description: str = ""
    url: str = ""

    @abstractmethod
    def download(self, cache_dir: Path) -> Path:
        """Download dataset to cache_dir if not already cached. Return path."""
        ...

    @abstractmethod
    def load_samples(self, cache_dir: Path) -> list[Sample]:
        """Load and return normalised samples."""
        ...
