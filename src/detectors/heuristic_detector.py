"""Heuristic detector — structural & statistical analysis.

Catches injection attempts that don't match known patterns by
analysing the *shape* and *structure* of the content rather than
exact string matches.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from typing import Any

from .base import BaseDetector
from ..models.schemas import DetectorFinding, ThreatCategory


# Instruction-like sentence starters (imperative verbs aimed at AI)
_IMPERATIVE_STARTERS = re.compile(
    r"(?i)^(?:you\s+(?:must|should|need\s+to|have\s+to|will|shall|are\s+(?:to|going\s+to))|"
    r"(?:please\s+)?(?:ignore|disregard|forget|override|bypass|skip|do\s+not|don'?t|always|never|stop|start|begin|continue|execute|run|perform|output|respond|reply|generate|create|write|send))\b(?!\s*\()",
    re.MULTILINE,
)

# Suspicious Unicode categories
_SUSPICIOUS_UNICODE_CATS = {"Cf", "Mn", "Co", "Cn"}  # format, non-spacing, private-use, unassigned

# Characters commonly used as confusables
_CONFUSABLE_PAIRS: dict[str, str] = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X", "\u0430": "a",
    "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0455": "s", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h",
    "\uff21": "A", "\uff22": "B", "\uff23": "C",  # fullwidth
    "\u2013": "-", "\u2014": "-",  # en/em dash
    "\u200b": "",   # zero-width space
    "\u200c": "",   # zero-width non-joiner
    "\u200d": "",   # zero-width joiner
    "\ufeff": "",   # byte order mark
    "\u00a0": " ",  # non-breaking space
    "\u2060": "",   # word joiner
    "\u180e": "",   # Mongolian vowel separator
}


class HeuristicDetector(BaseDetector):
    """Detects threats through structural and statistical analysis.

    Analyses:
    1. Instruction density (ratio of imperative sentences)
    2. Unicode anomalies (invisible chars, confusables, mixed scripts)
    3. Structural anomalies (delimiter abuse, nested encodings)
    4. Token density shifts (sudden complexity changes)
    5. Suspicious formatting patterns
    """

    name = "heuristic"
    version = "0.2.0"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.instruction_threshold = self.config.get("instruction_ratio_threshold", 0.35)
        self.unicode_threshold = self.config.get("unicode_anomaly_threshold", 0.05)
        self.max_decode_depth = self.config.get("max_decode_depth", 5)

    async def scan(self, content: str, metadata: dict[str, Any]) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        findings.extend(self._check_instruction_density(content))
        findings.extend(self._check_unicode_anomalies(content))
        findings.extend(self._check_structural_anomalies(content))
        findings.extend(self._check_language_shift(content))
        findings.extend(self._check_invisible_text(content))

        return findings

    # ── 1. Instruction density ──────────────────────────────────────────

    def _check_instruction_density(self, content: str) -> list[DetectorFinding]:
        sentences = [s.strip() for s in re.split(r'[.!?\n]+', content) if s.strip()]
        if not sentences:
            return []

        imperative_count = sum(1 for s in sentences if _IMPERATIVE_STARTERS.match(s))
        ratio = imperative_count / len(sentences)

        if ratio >= self.instruction_threshold:
            score = min(0.95, 0.5 + ratio)
            return [
                DetectorFinding(
                    detector=self.name,
                    score=score,
                    category=ThreatCategory.INJECTION,
                    evidence=f"{imperative_count}/{len(sentences)} sentences are imperative ({ratio:.0%})",
                    confidence=min(0.9, 0.5 + ratio * 0.5),
                    details={"ratio": ratio, "imperative_count": imperative_count},
                )
            ]
        return []

    # ── 2. Unicode anomalies ────────────────────────────────────────────

    def _check_unicode_anomalies(self, content: str) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        if not content:
            return findings

        # Check for suspicious Unicode categories
        suspicious_chars: list[tuple[int, str, str]] = []
        for i, ch in enumerate(content):
            cat = unicodedata.category(ch)
            if cat in _SUSPICIOUS_UNICODE_CATS:
                suspicious_chars.append((i, ch, cat))

        ratio = len(suspicious_chars) / len(content) if content else 0
        if ratio > self.unicode_threshold:
            findings.append(
                DetectorFinding(
                    detector=self.name,
                    score=min(0.9, 0.5 + ratio * 5),
                    category=ThreatCategory.CONFUSABLE_CHARS,
                    evidence=f"{len(suspicious_chars)} suspicious Unicode chars ({ratio:.1%} of content)",
                    confidence=0.80,
                    details={"categories": dict(Counter(c[2] for c in suspicious_chars))},
                )
            )

        # Check for confusable characters (homoglyphs)
        confusable_count = sum(1 for ch in content if ch in _CONFUSABLE_PAIRS)
        if confusable_count > 3:
            findings.append(
                DetectorFinding(
                    detector=self.name,
                    score=min(0.85, 0.4 + confusable_count * 0.05),
                    category=ThreatCategory.CONFUSABLE_CHARS,
                    evidence=f"{confusable_count} Unicode confusable characters detected",
                    confidence=0.75,
                    details={"confusable_count": confusable_count},
                )
            )

        # Check for mixed scripts (Latin + Cyrillic in same word = suspicious)
        words = content.split()
        mixed_script_words = 0
        for word in words:
            scripts = set()
            for ch in word:
                try:
                    name = unicodedata.name(ch, "")
                    if "LATIN" in name:
                        scripts.add("latin")
                    elif "CYRILLIC" in name:
                        scripts.add("cyrillic")
                    elif "GREEK" in name:
                        scripts.add("greek")
                except ValueError:
                    pass
            if len(scripts) > 1:
                mixed_script_words += 1

        if mixed_script_words > 0:
            findings.append(
                DetectorFinding(
                    detector=self.name,
                    score=min(0.90, 0.6 + mixed_script_words * 0.1),
                    category=ThreatCategory.CONFUSABLE_CHARS,
                    evidence=f"{mixed_script_words} words with mixed Unicode scripts",
                    confidence=0.85,
                    details={"mixed_script_words": mixed_script_words},
                )
            )

        return findings

    # ── 3. Structural anomalies ─────────────────────────────────────────

    def _check_structural_anomalies(self, content: str) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        # Check for delimiter abuse (many separators suggesting section injection)
        delimiter_patterns = [
            r'={5,}', r'-{5,}', r'#{5,}', r'\*{5,}',
            r'<{3,}', r'>{3,}', r'~{5,}',
        ]
        delimiter_count = sum(
            len(re.findall(p, content)) for p in delimiter_patterns
        )
        if delimiter_count >= 3:
            findings.append(
                DetectorFinding(
                    detector=self.name,
                    score=min(0.80, 0.3 + delimiter_count * 0.1),
                    category=ThreatCategory.INJECTION,
                    evidence=f"{delimiter_count} heavy delimiter sequences (possible section injection)",
                    confidence=0.65,
                    details={"delimiter_count": delimiter_count},
                )
            )

        # Check for XML/HTML tag injection targeting AI systems
        ai_tags = re.findall(
            r'</?(?:system|prompt|instructions?|rules?|context|tool_?(?:use|result)|function_?(?:call|result)|message|thinking|anthr)\b[^>]*>',
            content,
            re.IGNORECASE,
        )
        if ai_tags:
            findings.append(
                DetectorFinding(
                    detector=self.name,
                    score=0.90,
                    category=ThreatCategory.INJECTION,
                    evidence=f"AI-targeted XML tags found: {', '.join(ai_tags[:5])}",
                    confidence=0.88,
                    details={"tags": ai_tags[:10]},
                )
            )

        return findings

    # ── 4. Language / tone shift detection ──────────────────────────────

    def _check_language_shift(self, content: str) -> list[DetectorFinding]:
        """Detect abrupt shifts from informational to instructional tone."""
        lines = content.split('\n')
        if len(lines) < 5:
            return []

        # Split content into halves and compare instruction density
        mid = len(lines) // 2
        first_half = '\n'.join(lines[:mid])
        second_half = '\n'.join(lines[mid:])

        def instruction_ratio(text: str) -> float:
            sents = [s.strip() for s in re.split(r'[.!?\n]+', text) if s.strip()]
            if not sents:
                return 0.0
            return sum(1 for s in sents if _IMPERATIVE_STARTERS.match(s)) / len(sents)

        r1 = instruction_ratio(first_half)
        r2 = instruction_ratio(second_half)
        shift = abs(r2 - r1)

        if shift > 0.3 and max(r1, r2) > 0.4:
            return [
                DetectorFinding(
                    detector=self.name,
                    score=min(0.88, 0.5 + shift),
                    category=ThreatCategory.INDIRECT_INJECTION,
                    evidence=f"Instruction density shift: {r1:.0%} → {r2:.0%} (Δ={shift:.0%})",
                    confidence=0.72,
                    details={"first_half_ratio": r1, "second_half_ratio": r2},
                )
            ]
        return []

    # ── 5. Invisible text detection ─────────────────────────────────────

    def _check_invisible_text(self, content: str) -> list[DetectorFinding]:
        """Detect zero-width and other invisible characters that may hide instructions."""
        invisible_chars = {
            '\u200b': 'ZERO WIDTH SPACE',
            '\u200c': 'ZERO WIDTH NON-JOINER',
            '\u200d': 'ZERO WIDTH JOINER',
            '\u2060': 'WORD JOINER',
            '\u180e': 'MONGOLIAN VOWEL SEPARATOR',
            '\ufeff': 'BYTE ORDER MARK',
            '\u00ad': 'SOFT HYPHEN',
            '\u034f': 'COMBINING GRAPHEME JOINER',
            '\u061c': 'ARABIC LETTER MARK',
            '\u2061': 'FUNCTION APPLICATION',
            '\u2062': 'INVISIBLE TIMES',
            '\u2063': 'INVISIBLE SEPARATOR',
            '\u2064': 'INVISIBLE PLUS',
        }

        found: dict[str, int] = {}
        for ch in content:
            if ch in invisible_chars:
                name = invisible_chars[ch]
                found[name] = found.get(name, 0) + 1

        total = sum(found.values())
        if total > 2:
            return [
                DetectorFinding(
                    detector=self.name,
                    score=min(0.90, 0.5 + total * 0.05),
                    category=ThreatCategory.ENCODING_ATTACK,
                    evidence=f"{total} invisible Unicode characters found",
                    confidence=0.82,
                    details={"invisible_chars": found},
                )
            ]
        return []
