# Session State

**Saved**: 2026-02-28 07:31:34
**Branch**: main
**Project**: prompt-guard

## Original Intent

Train and implement a DeBERTa-v3 ML model as a 6th detector in the prompt-guard middleware to improve classification of attack surfaces not covered by the existing 5 rule-based detectors (novel jailbreak phrasings, multilingual attacks, indirect/subtle injections).

## Completed Work

- Explored entire codebase and identified that all 5 detectors are rule-based (no ML model despite config stubs)
- Researched HuggingFace models/datasets; selected `protectai/deberta-v3-base-prompt-injection-v2` (184M params)
- Created implementation plan (hexagonal architecture: port + adapter + detector)
- **Phase 1 — Port + Domain + Tests**:
  - Created `src/ports/inference.py` (InferencePort ABC + InferenceResult dataclass)
  - Created `src/detectors/ml_detector.py` (6th detector with graceful degradation)
  - Created `FakeInferenceAdapter` in `tests/helpers/fakes.py`
  - Created `tests/test_ml_detector.py` (11 unit tests, all passing)
- **Phase 2 — ONNX Adapter**:
  - Created `src/adapters/onnx_inference.py` (lazy-loading ONNX Runtime adapter)
  - Updated `pyproject.toml` with `[ml]` and `[training]` optional deps
  - Created `tests/test_ml_detector_integration.py` (3 integration tests)
- **Phase 3 — Wiring**:
  - Updated `config/default.yaml` (rebalanced weights, added ml_detector config)
  - Updated `src/middleware/app.py` (conditional ML detector registration)
  - Updated `tests/helpers/fakes.py` (include_ml param for build_default_registry)
- **Phase 4 — Training Pipeline**:
  - Created `scripts/training/train_ml_detector.py` (fine-tuning from protectai checkpoint)
  - Created `scripts/training/export_onnx.py` (ONNX export + validation)
  - Created `models/ml_detector/.gitignore`
- **Training executed** (~24.5 min on CPU): F1=0.957, Precision=0.985, Recall=0.931, Accuracy=0.962
  - Used 1578 samples from deepset (546) + jailbreak (1044) datasets
  - Harelix dataset unavailable (not on HuggingFace Hub)
- **ONNX export completed**: model.onnx (2.5 MB), PyTorch-ONNX diff 2.86e-06
- **All 518 tests pass** (11 ML unit + 3 integration + 504 existing)
- **Benchmark comparison** run (before vs after ML detector):
  - deepset: F1 0.313 → 0.970 (+0.657)
  - pint (Gandalf): F1 0.786 → 1.000 (+0.214)
  - jailbreak: F1 0.739 → 0.911 (+0.172)
  - notinject (FP calibration): FP rate 21.5% → 61.9% (+40.4% — needs tuning)

## In Progress

Benchmark analysis complete. Ready for threshold tuning to reduce false positives.

## Next Actions

1. **Tune score_threshold** — raise from 0.5 to ~0.7 to reduce NotInject false positives while preserving recall gains
2. **Adjust detector weights** — consider reducing ML weight from 0.20 to ~0.15 to soften borderline cases
3. **Re-run benchmark** after tuning to verify FP rate improves without major recall regression
4. **Commit all changes** — everything is uncommitted on main branch
5. **(Optional) Add hard negatives** — include NotInject-style benign samples with trigger words in training data
6. **(Optional) Quantize ONNX model** — ONNX quantization could reduce the 2.5MB model further and speed up inference

## Context & Decisions

- **Model choice**: DeBERTa-v3 from protectai/deberta-v3-base-prompt-injection-v2 (industry standard, 207K+ downloads)
- **Integration**: New 6th detector alongside existing 5 (not replacing semantic detector)
- **Runtime**: ONNX Runtime + tokenizers library (~50MB) for production; full PyTorch (~2GB) only for training
- **Architecture**: Hexagonal — InferencePort ABC in domain, OnnxInferenceAdapter in adapters layer
- **Training fix**: MPS (Apple Silicon GPU) caused OOM; forced CPU training with batch_size=8 + gradient_accumulation=2
- **Latency trade-off**: ML adds ~500ms/scan on CPU. GPU or batching would be faster in production.
- **False positive trade-off**: ML dramatically improves recall but increases FP rate on NotInject from 21.5% to 61.9%

## Files Modified

### New Files
- `src/ports/inference.py` — InferencePort ABC + InferenceResult
- `src/adapters/onnx_inference.py` — ONNX Runtime inference adapter
- `src/detectors/ml_detector.py` — ML detector (domain)
- `tests/test_ml_detector.py` — 11 unit tests
- `tests/test_ml_detector_integration.py` — 3 integration tests
- `scripts/training/train_ml_detector.py` — Fine-tuning pipeline
- `scripts/training/export_onnx.py` — ONNX export script
- `scripts/training/__init__.py` — Package init
- `models/ml_detector/.gitignore` — Excludes large model binaries
- `models/ml_detector/model.onnx` — Trained ONNX model (2.5 MB)
- `models/ml_detector/tokenizer.json` — Fast tokenizer
- `models/ml_detector/config.json` — Label mapping
- `models/ml_detector/training_report.json` — Training metrics
- `models/ml_detector/pytorch/` — PyTorch checkpoint (gitignored)

### Modified Files
- `config/default.yaml` — Rebalanced detector weights + ml_detector config section
- `src/middleware/app.py` — Conditional ML detector registration in lifespan
- `tests/helpers/fakes.py` — FakeInferenceAdapter + include_ml param
- `pyproject.toml` — Added [ml] and [training] optional dependency groups
- `scripts/benchmark/__main__.py` — Added --ml flag
- `scripts/benchmark/runner.py` — Support for ML detector in benchmark runner

## Blockers / Pending

- **NotInject FP rate** needs tuning (score_threshold and/or weights) before production use
- **No git commit yet** — all work is uncommitted
- **Harelix dataset unavailable** — could improve multilingual coverage if found or replaced

## User Notes

(none provided)
