"""ML-based detector using a fine-tuned transformer model for prompt injection detection.

Delegates inference to an InferencePort adapter (typically ONNX Runtime).
Falls back gracefully if the model is unavailable — returns empty findings
so the engine proceeds with the remaining rule-based detectors.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .base import BaseDetector
from ..models.schemas import DetectorFinding, ThreatCategory
from ..ports.inference import InferencePort


class MLDetector(BaseDetector):
    """Detects prompt injection using a fine-tuned transformer model."""

    name = "ml"
    version = "0.1.0"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        inference: InferencePort | None = None,
    ) -> None:
        super().__init__(config)
        self._inference = inference
        self._score_threshold: float = self.config.get("score_threshold", 0.5)
        self._high_confidence_threshold: float = self.config.get(
            "high_confidence_threshold", 0.85
        )

    async def scan(
        self, content: str, metadata: dict[str, Any]
    ) -> list[DetectorFinding]:
        if self._inference is None or not self._inference.is_available():
            return []

        result = await asyncio.to_thread(self._inference.predict, content)

        if result.label == "benign" or result.score < self._score_threshold:
            return []

        category = ThreatCategory.INJECTION
        if result.score >= self._high_confidence_threshold:
            category = ThreatCategory.INJECTION

        return [
            DetectorFinding(
                detector=self.name,
                score=result.score,
                category=category,
                evidence=(
                    f"ML model classified as '{result.label}' "
                    f"with {result.score:.0%} confidence"
                ),
                confidence=result.score,
                details={
                    "model_label": result.label,
                    "model_score": result.score,
                    "raw_logits": result.raw_logits,
                },
            )
        ]
