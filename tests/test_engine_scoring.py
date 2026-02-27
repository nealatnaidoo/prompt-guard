"""Tests for DetectionEngine._aggregate_scores boost ordering.

Verifies BUG-001 fix: the 4-detector boost (1.25x) must be checked
before the 3-detector boost (1.15x).
"""

import unittest

from src.detectors.engine import DetectionEngine
from src.models.schemas import DetectorFinding, ThreatCategory


class TestAggregateScoresBoost(unittest.TestCase):
    """Verify multi-detector agreement boost logic."""

    def setUp(self):
        self.engine = DetectionEngine()

    def _make_finding(self, detector: str, score: float) -> DetectorFinding:
        """Create a minimal DetectorFinding for scoring tests."""
        return DetectorFinding(
            detector=detector,
            score=score,
            category=ThreatCategory.INJECTION,
            evidence="test evidence",
            confidence=1.0,
        )

    def test_four_detector_boost_applies_1_25x(self):
        """When 4+ detectors agree (score > 0.5), the 1.25x boost must apply."""
        # Four detectors each with score 0.6 (all > 0.5 threshold)
        findings = [
            self._make_finding("pattern", 0.6),
            self._make_finding("heuristic", 0.6),
            self._make_finding("semantic", 0.6),
            self._make_finding("entropy", 0.6),
        ]
        score = self.engine._aggregate_scores(findings)

        # Base weighted score: each detector has score 0.6
        # Weights: pattern=0.30, heuristic=0.25, semantic=0.25, entropy=0.10
        # weighted_sum = 0.6*0.30 + 0.6*0.25 + 0.6*0.25 + 0.6*0.10 = 0.6*0.90 = 0.54
        # weight_sum = 0.30 + 0.25 + 0.25 + 0.10 = 0.90
        # base_score = 0.54 / 0.90 = 0.6
        # After 1.25x boost: 0.6 * 1.25 = 0.75
        expected_base = 0.6
        expected_boosted = min(1.0, expected_base * 1.25)
        self.assertAlmostEqual(score, round(expected_boosted, 4), places=3)

    def test_three_detector_boost_applies_1_15x(self):
        """When exactly 3 detectors agree, the 1.15x boost must apply."""
        findings = [
            self._make_finding("pattern", 0.6),
            self._make_finding("heuristic", 0.6),
            self._make_finding("semantic", 0.6),
        ]
        score = self.engine._aggregate_scores(findings)

        # Weights: pattern=0.30, heuristic=0.25, semantic=0.25
        # weighted_sum = 0.6*0.30 + 0.6*0.25 + 0.6*0.25 = 0.6*0.80 = 0.48
        # weight_sum = 0.30 + 0.25 + 0.25 = 0.80
        # base_score = 0.48 / 0.80 = 0.6
        # After 1.15x boost: 0.6 * 1.15 = 0.69
        expected_base = 0.6
        expected_boosted = min(1.0, expected_base * 1.15)
        self.assertAlmostEqual(score, round(expected_boosted, 4), places=3)

    def test_two_detector_no_boost(self):
        """When fewer than 3 detectors agree, no boost is applied."""
        findings = [
            self._make_finding("pattern", 0.6),
            self._make_finding("heuristic", 0.6),
        ]
        score = self.engine._aggregate_scores(findings)

        # Weights: pattern=0.30, heuristic=0.25
        # weighted_sum = 0.6*0.30 + 0.6*0.25 = 0.6*0.55 = 0.33
        # weight_sum = 0.30 + 0.25 = 0.55
        # base_score = 0.33 / 0.55 = 0.6
        # No boost applied
        expected_base = 0.6
        self.assertAlmostEqual(score, round(expected_base, 4), places=3)

    def test_four_detector_gets_higher_boost_than_three(self):
        """The 4-detector case must produce a higher score than the 3-detector case
        given the same per-detector scores."""
        findings_4 = [
            self._make_finding("pattern", 0.6),
            self._make_finding("heuristic", 0.6),
            self._make_finding("semantic", 0.6),
            self._make_finding("entropy", 0.6),
        ]
        findings_3 = [
            self._make_finding("pattern", 0.6),
            self._make_finding("heuristic", 0.6),
            self._make_finding("semantic", 0.6),
        ]
        score_4 = self.engine._aggregate_scores(findings_4)
        score_3 = self.engine._aggregate_scores(findings_3)

        # 4 detectors should get 1.25x boost, 3 detectors get 1.15x
        # Both have the same base_score of 0.6 (weighted average is 0.6 in both cases)
        # So score_4 = 0.75 > score_3 = 0.69
        self.assertGreater(score_4, score_3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
