#!/usr/bin/env python3
"""Export a fine-tuned PyTorch model to ONNX format.

Produces:
    models/ml_detector/
        model.onnx       # ONNX model for onnxruntime inference
        tokenizer.json   # Fast tokenizer for the tokenizers library
        config.json      # Label mapping + metadata

Usage:
    python scripts/training/export_onnx.py [--model-dir models/ml_detector]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _check_deps() -> None:
    missing = []
    for pkg in ("torch", "transformers", "onnxruntime", "optimum"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(
            f"Missing export dependencies: {', '.join(missing)}\n"
            "Install with: pip install prompt-guard[training]",
            file=sys.stderr,
        )
        sys.exit(1)


_check_deps()

import numpy as np
import onnxruntime as ort
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


def export_onnx(model_dir: Path) -> None:
    """Export PyTorch model to ONNX and save fast tokenizer."""
    pytorch_dir = model_dir / "pytorch"
    if not pytorch_dir.exists():
        print(
            f"ERROR: PyTorch model not found at {pytorch_dir}\n"
            "Run training first: python scripts/training/train_ml_detector.py",
            file=sys.stderr,
        )
        sys.exit(1)

    onnx_path = model_dir / "model.onnx"
    tokenizer_path = model_dir / "tokenizer.json"
    config_path = model_dir / "config.json"

    # Load PyTorch model
    print(f"Loading PyTorch model from {pytorch_dir}...")
    model = AutoModelForSequenceClassification.from_pretrained(str(pytorch_dir))
    tokenizer = AutoTokenizer.from_pretrained(str(pytorch_dir))

    # Switch to inference mode
    for param in model.parameters():
        param.requires_grad = False

    # Create dummy input for ONNX export
    dummy_text = "This is a test input for ONNX export."
    inputs = tokenizer(
        dummy_text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding="max_length",
    )

    # Export to ONNX
    print(f"Exporting to ONNX: {onnx_path}...")
    torch.onnx.export(
        model,
        (inputs["input_ids"], inputs["attention_mask"]),
        str(onnx_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size", 1: "sequence_length"},
            "attention_mask": {0: "batch_size", 1: "sequence_length"},
            "logits": {0: "batch_size"},
        },
        opset_version=14,
        do_constant_folding=True,
    )

    # Save fast tokenizer (tokenizers library format)
    print(f"Saving fast tokenizer: {tokenizer_path}...")
    if hasattr(tokenizer, "backend_tokenizer"):
        tokenizer.backend_tokenizer.save(str(tokenizer_path))
    else:
        # Fallback: save via save_pretrained and use tokenizer.json
        tokenizer.save_pretrained(str(model_dir / "tokenizer_hf"))
        hf_tokenizer_json = model_dir / "tokenizer_hf" / "tokenizer.json"
        if hf_tokenizer_json.exists():
            import shutil

            shutil.copy2(hf_tokenizer_json, tokenizer_path)
        else:
            print(
                "WARNING: Could not extract fast tokenizer JSON. "
                "You may need to use transformers tokenizer instead."
            )

    # Save config with label mapping
    labels = ["benign", "injection"]
    if hasattr(model.config, "id2label"):
        labels = [model.config.id2label[i] for i in range(model.config.num_labels)]

    config_data = {
        "labels": labels,
        "max_length": 512,
        "model_type": "deberta-v3",
        "base_model": "protectai/deberta-v3-base-prompt-injection-v2",
    }
    config_path.write_text(json.dumps(config_data, indent=2))
    print(f"Saved config: {config_path}")

    # Validate ONNX output matches PyTorch
    print("\nValidating ONNX output...")
    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    onnx_inputs = {
        "input_ids": inputs["input_ids"].numpy(),
        "attention_mask": inputs["attention_mask"].numpy(),
    }
    onnx_output = session.run(None, onnx_inputs)[0]

    with torch.no_grad():
        pytorch_output = model(**inputs).logits.numpy()

    max_diff = float(np.max(np.abs(onnx_output - pytorch_output)))
    print(f"  Max absolute difference: {max_diff:.6e}")

    if max_diff < 1e-4:
        print("  PASS: ONNX output matches PyTorch within tolerance")
    else:
        print(f"  WARNING: Difference {max_diff:.6e} exceeds 1e-4 tolerance")

    # Summary
    onnx_size_mb = onnx_path.stat().st_size / (1024 * 1024)
    print(f"\n{'=' * 60}")
    print("ONNX EXPORT COMPLETE")
    print(f"{'=' * 60}")
    print(f"  ONNX model:     {onnx_path} ({onnx_size_mb:.1f} MB)")
    print(f"  Tokenizer:      {tokenizer_path}")
    print(f"  Config:         {config_path}")
    print(f"  Labels:         {labels}")


def main():
    parser = argparse.ArgumentParser(description="Export fine-tuned model to ONNX")
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path("models/ml_detector"),
        help="Model directory (default: models/ml_detector)",
    )
    args = parser.parse_args()
    export_onnx(args.model_dir)


if __name__ == "__main__":
    main()
