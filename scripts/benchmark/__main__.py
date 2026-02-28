"""Prompt Guard Benchmark Harness.

Usage:
    python -m scripts.benchmark                         # Run all datasets
    python -m scripts.benchmark --dataset deepset       # Run one dataset
    python -m scripts.benchmark --dataset pint --limit 100
    python -m scripts.benchmark --endpoint http://localhost:8420
    python -m scripts.benchmark --threshold high
    python -m scripts.benchmark --list
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .datasets import REGISTRY
from .metrics import compute_metrics
from .report import print_summary, save_json_report
from .runner import BenchmarkRunner

CACHE_DIR = Path(".benchmarks/datasets")
RESULTS_DIR = Path(".benchmarks/results")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prompt Guard Benchmark Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Datasets:\n"
            + "\n".join(
                f"  {name:<12s} {adapter.description}"
                for name, adapter in REGISTRY.items()
            )
        ),
    )
    parser.add_argument(
        "--dataset",
        choices=[*REGISTRY, "all"],
        default="all",
        help="Dataset to run (default: all)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max samples per dataset",
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        default=None,
        help="Remote server URL (default: in-process TestClient)",
    )
    parser.add_argument(
        "--threshold",
        choices=["low", "medium", "high"],
        default="medium",
        help="Minimum threat_level to count as positive (default: medium)",
    )
    parser.add_argument(
        "--ml",
        action="store_true",
        help="Enable ML detector (requires ONNX model at models/ml_detector/)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available datasets and exit",
    )
    args = parser.parse_args()

    if args.list:
        print("\nAvailable datasets:\n")
        for name, adapter in REGISTRY.items():
            print(f"  {name:<12s} {adapter.description}")
            print(f"  {'':12s} {adapter.url}\n")
        return 0

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    dataset_names = (
        [args.dataset] if args.dataset != "all" else list(REGISTRY)
    )

    mode = "remote" if args.endpoint else "in-process"
    print(f"\nPrompt Guard Benchmark Harness")
    print(f"  Mode:      {mode}")
    print(f"  ML model:  {'enabled' if args.ml else 'disabled'}")
    print(f"  Threshold: {args.threshold}")
    print(f"  Datasets:  {', '.join(dataset_names)}")
    if args.limit:
        print(f"  Limit:     {args.limit} samples/dataset")

    runner = BenchmarkRunner(
        endpoint=args.endpoint,
        threshold=args.threshold,
        include_ml=args.ml,
    )

    all_reports = {}
    total_start = time.monotonic()

    for ds_name in dataset_names:
        adapter = REGISTRY[ds_name]
        print(f"\n{'=' * 60}")
        print(f"  Dataset: {adapter.description}")
        print(f"{'=' * 60}")

        try:
            adapter.download(CACHE_DIR)
            outcomes = runner.run_dataset(adapter, CACHE_DIR, limit=args.limit)
            report = compute_metrics(outcomes, ds_name)
            all_reports[ds_name] = report
            print_summary(report)
        except Exception as e:
            print(f"\n  ERROR: {e}", file=sys.stderr)
            continue

    total_elapsed = time.monotonic() - total_start
    runner.close()

    if not all_reports:
        print("\nNo datasets completed successfully.", file=sys.stderr)
        return 1

    # Save JSON report
    config = {
        "threshold": args.threshold,
        "endpoint": args.endpoint,
        "mode": mode,
        "limit": args.limit,
    }
    report_path = save_json_report(all_reports, RESULTS_DIR, config)

    # Final summary
    print(f"\n{'=' * 60}")
    print(f"  BENCHMARK COMPLETE")
    print(f"{'=' * 60}")
    print(f"  Datasets run:  {len(all_reports)}")
    print(f"  Total time:    {total_elapsed:.1f}s")
    print(f"  Report saved:  {report_path}")

    # Quick summary table
    print(f"\n  {'Dataset':<12s} {'Samples':>8s} {'Prec':>7s} {'Recall':>7s}"
          f" {'F1':>7s} {'Acc':>7s}")
    print(f"  {'─' * 52}")
    for name, report in all_reports.items():
        print(
            f"  {name:<12s} {report.total_samples:>8d}"
            f" {report.precision:>7.3f} {report.recall:>7.3f}"
            f" {report.f1:>7.3f} {report.accuracy:>7.3f}"
        )
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
