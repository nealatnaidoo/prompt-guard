# Session State

**Saved**: 2026-02-28 12:05:00
**Branch**: main
**Project**: prompt-guard

## Original Intent

Train and implement a DeBERTa-v3 ML model as a 6th detector in the prompt-guard middleware to improve classification of attack surfaces not covered by the existing 5 rule-based detectors (novel jailbreak phrasings, multilingual attacks, indirect/subtle injections).

## Completed Work

- Explored entire codebase and identified that all 5 detectors are rule-based (no ML model)
- Researched HuggingFace models/datasets; selected `protectai/deberta-v3-base-prompt-injection-v2`
- Designed and implemented hexagonal architecture (InferencePort + OnnxInferenceAdapter + MLDetector)
- Created training pipeline with NotInject hard negatives
- Trained model: F1=0.986, Precision=0.973, Recall=1.000, Accuracy=0.990
- Exported to ONNX (2.5 MB, PyTorch-ONNX diff 2.86e-06)
- Wired ML detector into composition root, config, benchmark harness
- All 518 tests passing (14 new ML tests + 504 existing)
- Benchmark comparison shows massive recall improvements:
  - deepset: F1 0.313 → 0.970
  - pint (Gandalf): F1 0.786 → 1.000
  - jailbreak: F1 0.739 → 0.911
- PR #1 created, merged to main, branch deleted
- All work committed and pushed

## In Progress

Nothing — all work complete.

## Next Actions

1. **(Optional) Tune score_threshold** — raise from 0.5 to ~0.7 to further reduce NotInject false positives
2. **(Optional) Quantize ONNX model** — reduce 2.5MB model further and speed up inference
3. **(Optional) Add more training data** — multilingual datasets for non-English attack coverage
4. **(Optional) Deploy** — production deployment with `pip install prompt-guard[ml]`

## Context & Decisions

- **Model**: DeBERTa-v3 from protectai/deberta-v3-base-prompt-injection-v2 (184M params)
- **Integration**: New 6th detector alongside existing 5 (not replacing semantic)
- **Runtime**: ONNX Runtime + tokenizers (~50MB) for production; PyTorch (~2GB) only for training
- **Architecture**: Hexagonal — InferencePort ABC in domain, OnnxInferenceAdapter in adapters
- **Training**: CPU-only (MPS OOM on Apple Silicon), 1917 samples (deepset + jailbreak + NotInject hard negatives)
- **Latency**: ML adds ~500ms/scan on CPU; GPU/batching would be faster in production
- **PR #1**: Merged to main via `gh pr merge --merge --delete-branch`

## Files Modified

All changes merged to main via PR #1:
- `src/ports/inference.py` — InferencePort ABC + InferenceResult
- `src/adapters/onnx_inference.py` — ONNX Runtime inference adapter
- `src/detectors/ml_detector.py` — ML detector (domain)
- `tests/test_ml_detector.py` — 11 unit tests
- `tests/test_ml_detector_integration.py` — 3 integration tests
- `scripts/training/train_ml_detector.py` — Fine-tuning pipeline
- `scripts/training/export_onnx.py` — ONNX export script
- `config/default.yaml` — Rebalanced detector weights + ml_detector config
- `src/middleware/app.py` — Conditional ML detector registration
- `tests/helpers/fakes.py` — FakeInferenceAdapter + include_ml param
- `pyproject.toml` — [ml] and [training] optional dependency groups
- `scripts/benchmark/__main__.py` — --ml flag
- `scripts/benchmark/runner.py` — ML detector support in benchmark runner
- `models/ml_detector/` — tokenizer.json, config.json, training_report.json, .gitignore

## Blockers / Pending

None — all work complete and merged.

## User Notes

(none provided)
