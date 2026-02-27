"""Report formatting — stdout summary + JSON serialisation."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .metrics import CategoryMetrics, MetricsReport


def print_summary(report: MetricsReport) -> None:
    """Print a human-readable summary to stdout."""
    w = sys.stdout.write

    w(f"\n  {'─' * 50}\n")
    w(f"  Results: {report.dataset} ({report.total_samples} samples)\n")
    w(f"  {'─' * 50}\n")
    w(f"  Accuracy:  {report.accuracy:.3f}\n")
    w(f"  Precision: {report.precision:.3f}\n")
    w(f"  Recall:    {report.recall:.3f}\n")
    w(f"  F1 Score:  {report.f1:.3f}\n")
    w(f"\n")
    w(f"  Confusion Matrix:\n")
    w(f"  {'':>18s} Predicted\n")
    w(f"  {'':>18s} {'Benign':>8s} {'Malicious':>10s}\n")
    w(f"  {'Actual Benign':>18s} {report.tn:>8d} {report.fp:>10d}\n")
    w(f"  {'Actual Malicious':>18s} {report.fn:>8d} {report.tp:>10d}\n")
    w(f"\n")
    w(f"  Latency: avg={report.avg_latency_ms:.1f}ms"
      f"  p50={report.p50_latency_ms:.1f}ms"
      f"  p99={report.p99_latency_ms:.1f}ms\n")

    if report.by_category and len(report.by_category) > 1:
        w(f"\n  Per-Category Breakdown:\n")
        w(f"  {'Category':<25s} {'Samples':>7s} {'Prec':>6s} {'Recall':>7s} {'F1':>6s}\n")
        w(f"  {'─' * 55}\n")
        for cat, cm in sorted(report.by_category.items()):
            w(f"  {cat:<25s} {cm.total:>7d}"
              f" {cm.precision:>6.3f} {cm.recall:>7.3f} {cm.f1:>6.3f}\n")

    w(f"  {'─' * 50}\n")
    sys.stdout.flush()


def _serialise_category(cm: CategoryMetrics) -> dict:
    return {
        "category": cm.category,
        "total": cm.total,
        "tp": cm.tp,
        "fp": cm.fp,
        "tn": cm.tn,
        "fn": cm.fn,
        "precision": round(cm.precision, 4),
        "recall": round(cm.recall, 4),
        "f1": round(cm.f1, 4),
        "accuracy": round(cm.accuracy, 4),
    }


def serialise_report(report: MetricsReport) -> dict:
    """Convert MetricsReport to JSON-safe dict."""
    return {
        "dataset": report.dataset,
        "total_samples": report.total_samples,
        "metrics": {
            "tp": report.tp,
            "fp": report.fp,
            "tn": report.tn,
            "fn": report.fn,
            "precision": round(report.precision, 4),
            "recall": round(report.recall, 4),
            "f1": round(report.f1, 4),
            "accuracy": round(report.accuracy, 4),
        },
        "latency": {
            "avg_ms": round(report.avg_latency_ms, 2),
            "p50_ms": round(report.p50_latency_ms, 2),
            "p99_ms": round(report.p99_latency_ms, 2),
        },
        "by_category": {
            cat: _serialise_category(cm)
            for cat, cm in sorted(report.by_category.items())
        }
        if report.by_category
        else None,
    }


def save_json_report(
    reports: dict[str, MetricsReport],
    results_dir: Path,
    config: dict,
) -> Path:
    """Save full benchmark report as JSON. Returns the file path."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = results_dir / f"benchmark_{timestamp}.json"

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config": config,
        "datasets": {
            name: serialise_report(report)
            for name, report in reports.items()
        },
    }

    report_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    return report_path
