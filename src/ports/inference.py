"""InferencePort — abstract interface for ML model inference.

This port removes ML framework dependencies (onnxruntime, transformers) from
the domain layer, enabling deterministic testing via fake adapters.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class InferenceResult:
    """Output from an ML inference call."""

    label: str
    score: float
    raw_logits: list[float] = field(default_factory=list)


class InferencePort(ABC):
    """Port for ML model inference."""

    @abstractmethod
    def predict(self, text: str) -> InferenceResult:
        """Run inference on a single text input. Returns label + confidence score."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the model is loaded and ready for inference."""
        ...
