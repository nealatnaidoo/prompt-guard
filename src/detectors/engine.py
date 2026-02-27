"""Detection engine — orchestrates all detectors and computes final verdict."""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any

import logging

from .base import BaseDetector, DetectorRegistry
from ..models.schemas import (
    DetectorFinding,
    PolicyAction,
    ScanRequest,
    ScanResult,
    ThreatLevel,
)
from ..ports.clock import ClockPort

logger = logging.getLogger(__name__)

# Default detector weights
_DEFAULT_WEIGHTS: dict[str, float] = {
    "pattern": 0.30,
    "heuristic": 0.25,
    "semantic": 0.25,
    "entropy": 0.10,
    "provenance": 0.10,
}


class DetectionEngine:
    """Orchestrates the full detection pipeline.

    Flow:
    1. Pre-process content (length check, hash)
    2. Run all detectors (optionally in parallel)
    3. Aggregate scores using weighted combination
    4. Apply threat-level classification
    5. Return structured result
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        clock: ClockPort | None = None,
        registry: DetectorRegistry | None = None,
    ):
        self.config = config or {}
        self.clock = clock
        self.registry = registry if registry is not None else DetectorRegistry()
        # Copy default weights to avoid mutating module-level dict (BUG fix)
        self.weights: dict[str, float] = dict(
            self.config.get("detector_weights", _DEFAULT_WEIGHTS)
        )
        self.threat_threshold = self.config.get("threat_threshold", 0.65)
        self.max_content_length = self.config.get("max_content_length", 500_000)
        self.parallel = self.config.get("parallel_detectors", True)

        # Only register default detectors if no registry was injected
        if registry is None:
            self._register_default_detectors()

    def _register_default_detectors(self) -> None:
        # Lazy imports to allow the engine to be instantiated without concrete detectors
        # when a pre-populated registry is injected.
        from .pattern_detector import PatternDetector
        from .heuristic_detector import HeuristicDetector
        from .semantic_detector import SemanticDetector
        from .entropy_detector import EntropyDetector
        from .provenance_detector import ProvenanceDetector

        cfg = self.config
        self.registry.register(PatternDetector(cfg.get("pattern_detector", {})))
        self.registry.register(HeuristicDetector(cfg.get("heuristic_detector", {})))
        self.registry.register(SemanticDetector(cfg.get("semantic_detector", {})))
        self.registry.register(EntropyDetector(cfg.get("entropy_detector", {})))
        self.registry.register(ProvenanceDetector(cfg.get("provenance_detector", {})))

    def register_detector(self, detector: BaseDetector, weight: float = 0.1) -> None:
        """Register a custom detector with a given weight."""
        self.registry.register(detector)
        self.weights[detector.name] = weight
        # Re-normalise weights
        total = sum(self.weights.values())
        self.weights = {k: v / total for k, v in self.weights.items()}

    async def scan(self, request: ScanRequest) -> ScanResult:
        """Run the full detection pipeline."""
        start = time.perf_counter()

        # Use injected clock if available, otherwise fall back to inline generation
        if self.clock is not None:
            request_id = self.clock.generate_id()
            timestamp = self.clock.now()
        else:
            import uuid as _uuid
            request_id = _uuid.uuid4().hex[:16]
            timestamp = time.time()

        result = ScanResult(
            request_id=request_id,
            timestamp=timestamp,
            content_hash=hashlib.sha256(request.content.encode()).hexdigest()[:32],
        )

        # ── Pre-checks ──────────────────────────────────────────────────
        if len(request.content) > self.max_content_length:
            result.threat_level = ThreatLevel.HIGH
            result.threat_score = 0.90
            result.action_taken = PolicyAction.REJECT
            result.summary = f"Content exceeds maximum length ({len(request.content):,} > {self.max_content_length:,})"
            result.latency_ms = (time.perf_counter() - start) * 1000
            return result

        if not request.content.strip():
            result.summary = "Empty content"
            result.latency_ms = (time.perf_counter() - start) * 1000
            return result

        # ── Determine which detectors to run ────────────────────────────
        detectors = self.registry.all()
        if request.detectors:
            detectors = [
                d for d in detectors if d.name in request.detectors
            ]

        # ── Run detectors ───────────────────────────────────────────────
        metadata = {
            **request.metadata,
            "source": request.source,
        }

        all_findings: list[DetectorFinding] = []

        if self.parallel and len(detectors) > 1:
            tasks = [d.scan(request.content, metadata) for d in detectors]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, r in enumerate(results):
                if isinstance(r, Exception):
                    logger.error(
                        "detector_error: detector=%s error=%s",
                        detectors[i].name,
                        str(r),
                    )
                else:
                    all_findings.extend(r)
        else:
            for detector in detectors:
                try:
                    findings = await detector.scan(request.content, metadata)
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error(
                        "detector_error: detector=%s error=%s",
                        detector.name,
                        str(e),
                    )

        result.findings = all_findings

        # ── Aggregate scores ────────────────────────────────────────────
        result.threat_score = self._aggregate_scores(all_findings)
        result.threat_level = self._classify_threat(result.threat_score, all_findings)

        # ── Determine action ────────────────────────────────────────────
        if request.policy_override:
            result.action_taken = request.policy_override
        else:
            result.action_taken = self._determine_action(result.threat_level)

        # ── Generate summary ────────────────────────────────────────────
        result.summary = self._generate_summary(result)

        result.latency_ms = (time.perf_counter() - start) * 1000
        return result

    def _aggregate_scores(self, findings: list[DetectorFinding]) -> float:
        """Compute weighted threat score from all findings."""
        if not findings:
            return 0.0

        # Group findings by detector
        detector_scores: dict[str, float] = {}
        for f in findings:
            key = f.detector
            # Take the max score per detector (worst finding)
            current = detector_scores.get(key, 0.0)
            # Weight by confidence
            effective = f.score * f.confidence
            detector_scores[key] = max(current, effective)

        # Weighted combination
        weighted_sum = 0.0
        weight_sum = 0.0
        for detector_name, score in detector_scores.items():
            weight = self.weights.get(detector_name, 0.1)
            weighted_sum += score * weight
            weight_sum += weight

        if weight_sum == 0:
            return 0.0

        base_score = weighted_sum / weight_sum

        # Boost: multiple detectors agreeing increases confidence
        agreeing_detectors = sum(1 for s in detector_scores.values() if s > 0.5)
        if agreeing_detectors >= 4:
            base_score = min(1.0, base_score * 1.25)
        elif agreeing_detectors >= 3:
            base_score = min(1.0, base_score * 1.15)

        # Critical finding override: any single finding >= 0.95 forces high score
        max_finding = max((f.score * f.confidence for f in findings), default=0.0)
        if max_finding >= 0.90:
            base_score = max(base_score, 0.80)

        return round(min(1.0, base_score), 4)

    def _classify_threat(self, score: float, findings: list[DetectorFinding]) -> ThreatLevel:
        """Classify overall threat level."""
        # Check for critical-category findings regardless of score
        critical_categories = {
            "prompt_injection",
            "jailbreak",
            "data_exfiltration",
        }
        has_critical = any(
            f.category.value in critical_categories and f.score >= 0.90
            for f in findings
        )

        if has_critical or score >= 0.85:
            return ThreatLevel.CRITICAL
        elif score >= 0.65:
            return ThreatLevel.HIGH
        elif score >= 0.40:
            return ThreatLevel.MEDIUM
        elif score >= 0.20:
            return ThreatLevel.LOW
        return ThreatLevel.CLEAN

    def _determine_action(self, threat_level: ThreatLevel) -> PolicyAction:
        """Map threat level to policy action."""
        policy_map = {
            ThreatLevel.CLEAN: PolicyAction.PASS,
            ThreatLevel.LOW: PolicyAction.PASS,
            ThreatLevel.MEDIUM: PolicyAction.WARN,
            ThreatLevel.HIGH: PolicyAction.QUARANTINE,
            ThreatLevel.CRITICAL: PolicyAction.REJECT,
        }
        return policy_map.get(threat_level, PolicyAction.REJECT)

    @staticmethod
    def _generate_summary(result: ScanResult) -> str:
        """Generate human-readable summary."""
        if not result.findings:
            return "No threats detected."

        categories = set(f.category.value for f in result.findings)
        top_finding = max(result.findings, key=lambda f: f.score)

        parts = [
            f"Threat level: {result.threat_level.value.upper()} "
            f"(score: {result.threat_score:.2f})",
            f"Categories: {', '.join(sorted(categories))}",
            f"Top finding: [{top_finding.detector}] {top_finding.evidence[:120]}",
            f"Action: {result.action_taken.value}",
        ]
        return " | ".join(parts)
