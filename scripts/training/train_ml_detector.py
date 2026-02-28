#!/usr/bin/env python3
"""Fine-tune a DeBERTa-v3 model for prompt injection detection.

Starting from protectai/deberta-v3-base-prompt-injection-v2, fine-tunes on
additional datasets to improve coverage of:
  - Novel jailbreak phrasings
  - Multilingual attacks
  - Indirect / subtle injection

Usage:
    pip install prompt-guard[training]
    python scripts/training/train_ml_detector.py [--output-dir models/ml_detector]

Produces:
    models/ml_detector/
        pytorch/           # Fine-tuned PyTorch checkpoint
        training_report.json  # Training metrics and dataset stats
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from urllib.request import urlopen

# ---------------------------------------------------------------------------
# Lazy imports — fail fast with a helpful message if deps are missing
# ---------------------------------------------------------------------------


def _check_deps() -> None:
    missing = []
    for pkg in ("torch", "transformers", "datasets", "sklearn"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(
            f"Missing training dependencies: {', '.join(missing)}\n"
            "Install with: pip install prompt-guard[training]",
            file=sys.stderr,
        )
        sys.exit(1)


_check_deps()

import numpy as np
import torch
from datasets import ClassLabel, Dataset, DatasetDict, concatenate_datasets, load_dataset
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
MAX_LENGTH = 256  # Reduced for training; inference supports up to 512
SEED = 42

# HuggingFace datasets to merge for training
HF_DATASETS = {
    "deepset": {
        "name": "deepset/prompt-injections",
        "text_field": "text",
        "label_field": "label",
        "malicious_values": [1],
    },
    "jailbreak": {
        "name": "jackhhao/jailbreak-classification",
        "text_field": "prompt",
        "label_field": "type",
        "malicious_values": ["jailbreak"],
    },
    "harelix": {
        "name": "Harelix/Prompt-Injection-Mixed-Techniques-2024",
        "text_field": "text",
        "label_field": "label",
        "malicious_values": ["injection", 1],
    },
}

# Hard-negative datasets (all-benign samples that contain trigger words)
# These teach the model to distinguish genuine injection from benign text
# that happens to use security-adjacent vocabulary.
NOTINJECT_URLS = [
    "https://raw.githubusercontent.com/SaFoLab-WISC/InjecGuard/main/datasets/NotInject_one.json",
    "https://raw.githubusercontent.com/SaFoLab-WISC/InjecGuard/main/datasets/NotInject_two.json",
    "https://raw.githubusercontent.com/SaFoLab-WISC/InjecGuard/main/datasets/NotInject_three.json",
]


# ---------------------------------------------------------------------------
# Dataset loading & normalisation
# ---------------------------------------------------------------------------


def load_and_normalise(ds_key: str, ds_config: dict) -> Dataset | None:
    """Load a HuggingFace dataset and normalise to {text: str, label: int}."""
    try:
        print(f"  Loading {ds_config['name']}...")
        ds = load_dataset(ds_config["name"], split="train")
    except Exception as e:
        print(f"  WARNING: Could not load {ds_config['name']}: {e}")
        return None

    text_field = ds_config["text_field"]
    label_field = ds_config["label_field"]
    malicious = ds_config["malicious_values"]

    texts = []
    labels = []
    for row in ds:
        text = row.get(text_field) or row.get("text") or row.get("prompt") or ""
        if not text or not str(text).strip():
            continue
        raw_label = row.get(label_field, 0)
        is_malicious = raw_label in malicious or str(raw_label).lower() in [
            str(v).lower() for v in malicious
        ]
        texts.append(str(text).strip())
        labels.append(1 if is_malicious else 0)

    print(f"    {ds_key}: {len(texts)} samples ({sum(labels)} malicious, {len(texts) - sum(labels)} benign)")
    return Dataset.from_dict({"text": texts, "label": labels})


def load_notinject() -> Dataset | None:
    """Load NotInject hard-negative dataset from GitHub.

    NotInject contains benign prompts that use trigger words commonly
    associated with prompt injection (e.g. "ignore", "instructions",
    "jailbreak"). All samples are benign (label=0). Including these
    in training teaches the model to look at intent and context rather
    than keyword presence alone.

    Source: https://github.com/SaFoLab-WISC/InjecGuard
    """
    print("  Loading NotInject (hard negatives) from GitHub...")
    texts = []
    for url in NOTINJECT_URLS:
        try:
            with urlopen(url, timeout=30) as resp:  # noqa: S310
                rows = json.loads(resp.read())
        except Exception as e:
            print(f"    WARNING: Could not fetch {url}: {e}")
            continue
        for row in rows:
            text = row.get("prompt", "")
            if text and text.strip():
                texts.append(text.strip())

    if not texts:
        print("    WARNING: No NotInject samples loaded")
        return None

    labels = [0] * len(texts)  # All benign
    print(f"    notinject: {len(texts)} samples (0 malicious, {len(texts)} benign)")
    return Dataset.from_dict({"text": texts, "label": labels})


def deduplicate(dataset: Dataset) -> Dataset:
    """Remove duplicate texts, keeping the first occurrence."""
    seen: set[str] = set()
    keep_indices = []
    for i, text in enumerate(dataset["text"]):
        h = hashlib.md5(text.encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            keep_indices.append(i)
    deduped = dataset.select(keep_indices)
    print(f"  Deduplicated: {len(dataset)} -> {len(deduped)} samples")
    return deduped


def prepare_datasets() -> DatasetDict:
    """Load, merge, deduplicate, and split all datasets."""
    print("\n=== Loading datasets ===")
    parts = []
    for key, cfg in HF_DATASETS.items():
        ds = load_and_normalise(key, cfg)
        if ds is not None:
            parts.append(ds)

    # Hard negatives: benign samples with trigger words
    notinject_ds = load_notinject()
    if notinject_ds is not None:
        parts.append(notinject_ds)

    if not parts:
        print("ERROR: No datasets loaded successfully.", file=sys.stderr)
        sys.exit(1)

    merged = concatenate_datasets(parts)
    print(f"\n  Merged total: {len(merged)} samples")
    merged = deduplicate(merged)

    # Cast label to ClassLabel so stratified split works
    merged = merged.cast_column(
        "label", ClassLabel(names=["benign", "injection"])
    )

    # Stratified split: 80% train, 10% val, 10% test
    split1 = merged.train_test_split(test_size=0.2, seed=SEED, stratify_by_column="label")
    split2 = split1["test"].train_test_split(test_size=0.5, seed=SEED, stratify_by_column="label")

    splits = DatasetDict(
        {
            "train": split1["train"],
            "validation": split2["train"],
            "test": split2["test"],
        }
    )

    for name, ds in splits.items():
        n_mal = sum(ds["label"])
        print(f"  {name}: {len(ds)} samples ({n_mal} malicious, {len(ds) - n_mal} benign)")

    return splits


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


def compute_metrics(eval_pred):
    """Compute metrics for the Trainer."""
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    return {
        "accuracy": accuracy_score(labels, predictions),
        "f1": f1_score(labels, predictions, average="binary"),
        "precision": precision_score(labels, predictions, average="binary"),
        "recall": recall_score(labels, predictions, average="binary"),
    }


def train(output_dir: Path) -> dict:
    """Fine-tune the model and return training report."""
    pytorch_dir = output_dir / "pytorch"
    pytorch_dir.mkdir(parents=True, exist_ok=True)

    # Load datasets
    splits = prepare_datasets()

    # Load model and tokenizer from pre-trained checkpoint
    print(f"\n=== Loading base model: {BASE_MODEL} ===")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=2,
        id2label={0: "benign", 1: "injection"},
        label2id={"benign": 0, "injection": 1},
    )

    # Tokenize datasets
    def tokenize_fn(examples):
        return tokenizer(
            examples["text"],
            truncation=True,
            max_length=MAX_LENGTH,
            padding="max_length",
        )

    print("\n=== Tokenizing datasets ===")
    tokenized = splits.map(tokenize_fn, batched=True, remove_columns=["text"])

    # Training arguments
    # Force CPU to avoid MPS out-of-memory on Apple Silicon
    use_cpu = not torch.cuda.is_available()
    training_args = TrainingArguments(
        output_dir=str(pytorch_dir / "checkpoints"),
        eval_strategy="steps",
        eval_steps=50,
        save_strategy="steps",
        save_steps=50,
        save_total_limit=2,
        learning_rate=2e-5,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=16,
        gradient_accumulation_steps=2,  # effective batch_size = 16
        num_train_epochs=3,
        weight_decay=0.01,
        warmup_ratio=0.1,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_steps=25,
        seed=SEED,
        fp16=torch.cuda.is_available(),
        use_cpu=use_cpu,
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["validation"],
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=3)],
    )

    # Train
    print("\n=== Training ===")
    train_result = trainer.train()

    # Save best model
    print(f"\n=== Saving model to {pytorch_dir} ===")
    trainer.save_model(str(pytorch_dir))
    tokenizer.save_pretrained(str(pytorch_dir))

    # Evaluate on test set
    print("\n=== Evaluating on test set ===")
    test_results = trainer.evaluate(tokenized["test"])

    # Detailed classification report
    predictions = trainer.predict(tokenized["test"])
    pred_labels = np.argmax(predictions.predictions, axis=-1)
    true_labels = predictions.label_ids

    report_str = classification_report(
        true_labels, pred_labels, target_names=["benign", "injection"]
    )
    cm = confusion_matrix(true_labels, pred_labels)
    print(f"\n{report_str}")
    print(f"Confusion matrix:\n{cm}")

    # Build training report
    report = {
        "base_model": BASE_MODEL,
        "max_length": MAX_LENGTH,
        "datasets": {
            name: {"samples": len(ds)} for name, ds in splits.items()
        },
        "training_loss": train_result.training_loss,
        "test_metrics": {
            k.replace("eval_", ""): round(v, 4)
            for k, v in test_results.items()
            if isinstance(v, (int, float))
        },
        "classification_report": report_str,
        "confusion_matrix": cm.tolist(),
        "hyperparameters": {
            "learning_rate": 2e-5,
            "epochs": 3,
            "batch_size": 16,
            "warmup_ratio": 0.1,
            "weight_decay": 0.01,
            "seed": SEED,
        },
    }

    report_path = output_dir / "training_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"\n=== Training report saved to {report_path} ===")

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Fine-tune ML detector model")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("models/ml_detector"),
        help="Directory for model output (default: models/ml_detector)",
    )
    args = parser.parse_args()

    report = train(args.output_dir)

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Test F1:        {report['test_metrics'].get('f1', 'N/A')}")
    print(f"  Test Precision: {report['test_metrics'].get('precision', 'N/A')}")
    print(f"  Test Recall:    {report['test_metrics'].get('recall', 'N/A')}")
    print(f"  Test Accuracy:  {report['test_metrics'].get('accuracy', 'N/A')}")
    print(f"\n  PyTorch model:  {args.output_dir / 'pytorch'}")
    print(f"  Next step:      python scripts/training/export_onnx.py")


if __name__ == "__main__":
    main()
