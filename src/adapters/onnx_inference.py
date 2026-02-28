"""OnnxInferenceAdapter — ONNX Runtime inference for the ML detector.

Lazy-loads the model and tokenizer on first predict() call so that:
  - Tests never trigger heavy imports
  - Missing onnxruntime/tokenizers packages degrade gracefully
  - Missing model files produce a warning, not a crash
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..ports.inference import InferencePort, InferenceResult

logger = logging.getLogger(__name__)


class OnnxInferenceAdapter(InferencePort):
    """Loads an ONNX model + tokenizer and runs inference."""

    def __init__(
        self,
        model_path: str,
        tokenizer_path: str,
        max_length: int = 512,
    ) -> None:
        self._model_path = Path(model_path)
        self._tokenizer_path = Path(tokenizer_path)
        self._max_length = max_length
        self._session = None  # onnxruntime.InferenceSession (lazy)
        self._tokenizer = None  # tokenizers.Tokenizer (lazy)
        self._labels: list[str] = ["benign", "injection"]
        self._load_error: str | None = None

    def _ensure_loaded(self) -> bool:
        """Lazy-load model and tokenizer on first call."""
        if self._session is not None:
            return True
        if self._load_error is not None:
            return False

        try:
            import onnxruntime as ort  # noqa: F811
            from tokenizers import Tokenizer

            if not self._model_path.exists():
                self._load_error = f"Model file not found: {self._model_path}"
                logger.warning("ml_model_missing: %s", self._load_error)
                return False

            if not self._tokenizer_path.exists():
                self._load_error = f"Tokenizer file not found: {self._tokenizer_path}"
                logger.warning("ml_tokenizer_missing: %s", self._load_error)
                return False

            self._session = ort.InferenceSession(
                str(self._model_path),
                providers=["CPUExecutionProvider"],
            )
            self._tokenizer = Tokenizer.from_file(str(self._tokenizer_path))
            self._tokenizer.enable_truncation(max_length=self._max_length)
            self._tokenizer.enable_padding(length=self._max_length)

            # Try to read label mapping from model metadata
            meta = self._session.get_modelmeta()
            if meta.custom_metadata_map and "labels" in meta.custom_metadata_map:
                import json

                self._labels = json.loads(meta.custom_metadata_map["labels"])

            logger.info("ml_model_loaded: %s", self._model_path)
            return True

        except ImportError as e:
            self._load_error = (
                f"ML dependencies not installed: {e}. "
                "Install with: pip install prompt-guard[ml]"
            )
            logger.warning("ml_deps_missing: %s", self._load_error)
            return False
        except Exception as e:
            self._load_error = str(e)
            logger.error("ml_model_load_error: %s", e)
            return False

    def predict(self, text: str) -> InferenceResult:
        if not self._ensure_loaded():
            return InferenceResult(label="benign", score=0.0)

        import numpy as np

        encoding = self._tokenizer.encode(text)
        input_ids = np.array([encoding.ids], dtype=np.int64)
        attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

        outputs = self._session.run(
            None,
            {"input_ids": input_ids, "attention_mask": attention_mask},
        )
        logits = outputs[0][0]  # shape: [num_classes]

        # Softmax
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / exp_logits.sum()

        predicted_idx = int(np.argmax(probs))
        return InferenceResult(
            label=self._labels[predicted_idx],
            score=float(probs[predicted_idx]),
            raw_logits=logits.tolist(),
        )

    def is_available(self) -> bool:
        return self._ensure_loaded()
