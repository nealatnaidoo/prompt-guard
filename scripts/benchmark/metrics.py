"""Metrics computation for benchmark results."""

from __future__ import annotations

from dataclasses import dataclass, field

from .datasets.base import ScanOutcome


@dataclass
class CategoryMetrics:
    """Metrics for a single category."""

    category: str
    total: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total > 0 else 0.0


@dataclass
class MetricsReport:
    """Full metrics for one dataset run."""

    dataset: str
    total_samples: int
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    avg_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    by_category: dict[str, CategoryMetrics] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0


def _percentile(values: list[float], pct: float) -> float:
    """Simple percentile without numpy."""
    if not values:
        return 0.0
    sorted_v = sorted(values)
    idx = int(len(sorted_v) * pct / 100.0)
    idx = min(idx, len(sorted_v) - 1)
    return sorted_v[idx]


def compute_metrics(outcomes: list[ScanOutcome], dataset_name: str) -> MetricsReport:
    """Compute full metrics from scan outcomes."""
    tp = fp = tn = fn = 0
    latencies = []

    for o in outcomes:
        latencies.append(o.latency_ms)
        if o.sample.is_malicious and o.predicted_malicious:
            tp += 1
        elif not o.sample.is_malicious and o.predicted_malicious:
            fp += 1
        elif not o.sample.is_malicious and not o.predicted_malicious:
            tn += 1
        else:
            fn += 1

    # Per-category breakdown
    categories: dict[str, list[ScanOutcome]] = {}
    for o in outcomes:
        cat = o.sample.category
        categories.setdefault(cat, []).append(o)

    by_category: dict[str, CategoryMetrics] = {}
    for cat, cat_outcomes in sorted(categories.items()):
        cm = CategoryMetrics(category=cat, total=len(cat_outcomes))
        for o in cat_outcomes:
            if o.sample.is_malicious and o.predicted_malicious:
                cm.tp += 1
            elif not o.sample.is_malicious and o.predicted_malicious:
                cm.fp += 1
            elif not o.sample.is_malicious and not o.predicted_malicious:
                cm.tn += 1
            else:
                cm.fn += 1
        by_category[cat] = cm

    return MetricsReport(
        dataset=dataset_name,
        total_samples=len(outcomes),
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        avg_latency_ms=sum(latencies) / len(latencies) if latencies else 0.0,
        p50_latency_ms=_percentile(latencies, 50),
        p99_latency_ms=_percentile(latencies, 99),
        by_category=by_category,
    )
