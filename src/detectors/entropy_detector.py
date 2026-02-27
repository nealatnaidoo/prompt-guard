"""Entropy detector — information-theoretic anomaly detection.

Catches obfuscated payloads, encoded instructions, and
statistically anomalous content segments.
"""

from __future__ import annotations

import base64
import math
import re
from typing import Any

from .base import BaseDetector
from ..models.schemas import DetectorFinding, ThreatCategory


class EntropyDetector(BaseDetector):
    """Detects encoded or obfuscated content through entropy analysis.

    High entropy in natural-language contexts suggests encoded payloads.
    Low entropy in code contexts may suggest repetitive padding attacks.
    """

    name = "entropy"
    version = "0.2.0"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.high_threshold = self.config.get("high_entropy_threshold", 5.5)
        self.b64_min_len = self.config.get("base64_min_length", 40)
        self.hex_min_len = self.config.get("hex_min_length", 32)

    async def scan(self, content: str, metadata: dict[str, Any]) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        findings.extend(self._check_segment_entropy(content))
        findings.extend(self._check_base64_segments(content))
        findings.extend(self._check_hex_segments(content))
        findings.extend(self._check_nested_encoding(content))

        return findings

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq: dict[str, int] = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def _check_segment_entropy(self, content: str) -> list[DetectorFinding]:
        """Check for high-entropy segments within otherwise normal text."""
        findings: list[DetectorFinding] = []

        # Split into ~200-char windows with overlap
        window = 200
        step = 100
        overall_entropy = self._shannon_entropy(content)

        for i in range(0, len(content) - window, step):
            segment = content[i:i + window]
            seg_entropy = self._shannon_entropy(segment)

            # Flag segments with significantly higher entropy than the overall content
            if seg_entropy > self.high_threshold and seg_entropy > overall_entropy + 1.5:
                findings.append(
                    DetectorFinding(
                        detector=self.name,
                        score=min(0.85, 0.4 + (seg_entropy - self.high_threshold) * 0.2),
                        category=ThreatCategory.ENCODING_ATTACK,
                        evidence=f"High-entropy segment at offset {i}: H={seg_entropy:.2f} (overall={overall_entropy:.2f})",
                        location=f"offset:{i}-{i + window}",
                        confidence=0.68,
                        details={"segment_entropy": seg_entropy, "overall_entropy": overall_entropy},
                    )
                )

        # Deduplicate overlapping windows — keep highest score
        if len(findings) > 3:
            findings.sort(key=lambda f: f.score, reverse=True)
            findings = findings[:3]

        return findings

    def _check_base64_segments(self, content: str) -> list[DetectorFinding]:
        """Detect potential base64-encoded payloads."""
        findings: list[DetectorFinding] = []

        # Find long base64-like strings
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{%d,}={0,2}' % self.b64_min_len)

        for m in b64_pattern.finditer(content):
            candidate = m.group()
            try:
                decoded = base64.b64decode(candidate, validate=True).decode('utf-8', errors='ignore')
                # Check if decoded content looks like instructions
                if any(kw in decoded.lower() for kw in [
                    'ignore', 'system', 'prompt', 'instruction', 'override',
                    'execute', 'admin', 'password', 'secret', 'token',
                ]):
                    findings.append(
                        DetectorFinding(
                            detector=self.name,
                            score=0.92,
                            category=ThreatCategory.ENCODING_ATTACK,
                            evidence=f"Base64 payload decodes to suspicious content: {decoded[:100]}",
                            location=f"offset:{m.start()}-{m.end()}",
                            confidence=0.90,
                            details={"encoded_length": len(candidate), "decoded_preview": decoded[:200]},
                        )
                    )
                elif len(decoded) > 20:
                    # Even non-suspicious decoded base64 is worth noting
                    findings.append(
                        DetectorFinding(
                            detector=self.name,
                            score=0.45,
                            category=ThreatCategory.ENCODING_ATTACK,
                            evidence=f"Base64 segment ({len(candidate)} chars) decodes to readable text",
                            location=f"offset:{m.start()}-{m.end()}",
                            confidence=0.55,
                            details={"encoded_length": len(candidate)},
                        )
                    )
            except Exception:
                pass  # Not valid base64

        return findings

    def _check_hex_segments(self, content: str) -> list[DetectorFinding]:
        """Detect hex-encoded content."""
        hex_pattern = re.compile(r'(?:0x)?(?:[0-9a-fA-F]{2}\s*){%d,}' % (self.hex_min_len // 2))

        findings: list[DetectorFinding] = []
        for m in hex_pattern.finditer(content):
            hex_str = re.sub(r'[\s0x]', '', m.group())
            try:
                decoded = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
                if len(decoded) > 10:
                    score = 0.55
                    if any(kw in decoded.lower() for kw in ['ignore', 'system', 'prompt', 'override']):
                        score = 0.88
                    findings.append(
                        DetectorFinding(
                            detector=self.name,
                            score=score,
                            category=ThreatCategory.ENCODING_ATTACK,
                            evidence=f"Hex-encoded content decodes to: {decoded[:100]}",
                            location=f"offset:{m.start()}-{m.end()}",
                            confidence=score - 0.1,
                            details={"hex_length": len(hex_str), "decoded_preview": decoded[:200]},
                        )
                    )
            except Exception:
                pass

        return findings

    def _check_nested_encoding(self, content: str) -> list[DetectorFinding]:
        """Detect multi-layer encoding (e.g., base64 of base64 of instructions)."""
        max_depth = self.config.get("max_decode_depth", 5)
        current = content
        depth = 0
        suspicious_at_depth: int | None = None

        # Try iterative base64 decoding
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
        for _ in range(max_depth):
            matches = b64_pattern.findall(current)
            if not matches:
                break

            decoded_any = False
            for candidate in matches:
                try:
                    decoded = base64.b64decode(candidate, validate=True).decode('utf-8', errors='ignore')
                    if len(decoded) > 10:
                        current = decoded
                        depth += 1
                        decoded_any = True

                        if any(kw in decoded.lower() for kw in [
                            'ignore', 'system', 'prompt', 'instruction', 'override', 'execute',
                        ]):
                            suspicious_at_depth = depth
                        break
                except Exception:
                    continue

            if not decoded_any:
                break

        if depth >= 2:
            score = min(0.95, 0.6 + depth * 0.12)
            if suspicious_at_depth:
                score = min(0.98, score + 0.15)

            return [
                DetectorFinding(
                    detector=self.name,
                    score=score,
                    category=ThreatCategory.ENCODING_ATTACK,
                    evidence=f"Nested encoding detected: {depth} layers deep"
                             + (f", suspicious at depth {suspicious_at_depth}" if suspicious_at_depth else ""),
                    confidence=min(0.92, 0.5 + depth * 0.15),
                    details={"encoding_depth": depth, "suspicious_depth": suspicious_at_depth},
                )
            ]

        return []
