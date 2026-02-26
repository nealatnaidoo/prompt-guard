"""Semantic detector — instruction-vs-data classification.

Uses lightweight NLP heuristics (and optionally an LLM judge) to
determine whether content is *data* (safe) or *instructions aimed
at the model* (suspicious).
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseDetector
from ..models.schemas import DetectorFinding, ThreatCategory


# Phrases that signal the content is *talking to* an AI, not providing data
_AI_ADDRESSING_PATTERNS = [
    r"(?i)\b(?:you|your)\s+(?:task|job|role|goal|purpose|objective)\s+(?:is|are|will\s+be)",
    r"(?i)\b(?:as\s+an?\s+)?(?:AI|LLM|language\s+model|assistant|chatbot|agent|model)\b.*?\b(?:you\s+(?:should|must|will|need\s+to)|please|always|never)\b",
    r"(?i)\b(?:respond|reply|answer|output|generate|produce|return)\s+(?:only|exclusively|nothing\s+but|with\s+(?:only|just))\b",
    r"(?i)\b(?:from\s+now\s+on|henceforth|going\s+forward|for\s+(?:all|every)\s+(?:future|subsequent))\b",
    r"(?i)\b(?:do\s+not|don'?t|never|refuse\s+to|cannot|must\s+not)\s+(?:mention|reveal|disclose|share|tell|show|display|output)\b",
    r"(?i)\b(?:your|the)\s+(?:system\s+)?prompt\b",
    r"(?i)\b(?:context\s+window|token\s+limit|training\s+(?:data|cutoff))\b",
    r"(?i)\b(?:tool\s+(?:use|call|result)|function\s+call(?:ing)?|API\s+(?:call|key|endpoint))\b",
]

# Structural patterns that suggest template/prompt formatting
_TEMPLATE_PATTERNS = [
    r"\{\{.*?\}\}",  # Handlebars-style
    r"\{%.*?%\}",    # Jinja-style
    r"\$\{.*?\}",    # Template literal
    r"<<[A-Z_]+>>",  # Placeholder markers
    r"\[(?:USER|SYSTEM|ASSISTANT|INPUT|OUTPUT|CONTEXT)\]", # Role markers
]

# Context poisoning: content that tries to establish false context
_POISONING_PATTERNS = [
    r"(?i)(?:(?:the\s+)?(?:user|customer|client)\s+(?:has\s+)?(?:already\s+)?(?:confirmed|agreed|approved|authorized|consented|verified|validated))",
    r"(?i)(?:(?:this\s+(?:has\s+been|was|is)\s+)?(?:pre-?approved|pre-?authorized|whitelisted|allowlisted))",
    r"(?i)(?:(?:previous|earlier|prior)\s+(?:conversation|interaction|message|context)\s+(?:established|confirmed|verified|showed))",
    r"(?i)(?:(?:according\s+to|per|as\s+(?:stated|mentioned)\s+in)\s+(?:the\s+)?(?:policy|guidelines?|rules?|instructions?)\s*,?\s*(?:you\s+(?:should|must|can|are\s+(?:allowed|permitted))))",
]


class SemanticDetector(BaseDetector):
    """Detects semantic injection through content classification.

    Classifies content segments as:
    - DATA: factual information, code, documentation
    - INSTRUCTION: directives aimed at the AI model
    - POISONING: false context establishment

    A high ratio of INSTRUCTION segments in content that should
    be pure DATA indicates injection.
    """

    name = "semantic"
    version = "0.2.0"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._ai_patterns = [re.compile(p, re.MULTILINE | re.DOTALL) for p in _AI_ADDRESSING_PATTERNS]
        self._template_patterns = [re.compile(p) for p in _TEMPLATE_PATTERNS]
        self._poisoning_patterns = [re.compile(p, re.MULTILINE) for p in _POISONING_PATTERNS]

    async def scan(self, content: str, metadata: dict[str, Any]) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        findings.extend(self._check_ai_addressing(content))
        findings.extend(self._check_template_injection(content))
        findings.extend(self._check_context_poisoning(content))
        findings.extend(self._check_multi_turn_manipulation(content))

        return findings

    def _check_ai_addressing(self, content: str) -> list[DetectorFinding]:
        """Detect content that directly addresses or instructs an AI system."""
        matches: list[tuple[str, re.Match]] = []
        for pattern in self._ai_patterns:
            for m in pattern.finditer(content):
                matches.append((m.group()[:150], m))

        if not matches:
            return []

        # Score based on density of AI-addressing language
        score = min(0.95, 0.4 + len(matches) * 0.12)
        evidence_samples = [m[0] for m in matches[:3]]

        return [
            DetectorFinding(
                detector=self.name,
                score=score,
                category=ThreatCategory.INJECTION,
                evidence=f"{len(matches)} AI-addressing patterns: {'; '.join(evidence_samples)}",
                confidence=min(0.90, 0.5 + len(matches) * 0.1),
                details={"match_count": len(matches), "samples": evidence_samples},
            )
        ]

    def _check_template_injection(self, content: str) -> list[DetectorFinding]:
        """Detect prompt template syntax that could manipulate formatting."""
        matches: list[str] = []
        for pattern in self._template_patterns:
            matches.extend(m.group() for m in pattern.finditer(content))

        if len(matches) < 2:
            return []

        return [
            DetectorFinding(
                detector=self.name,
                score=min(0.80, 0.4 + len(matches) * 0.08),
                category=ThreatCategory.INJECTION,
                evidence=f"{len(matches)} template syntax markers: {', '.join(matches[:5])}",
                confidence=0.70,
                details={"templates": matches[:10]},
            )
        ]

    def _check_context_poisoning(self, content: str) -> list[DetectorFinding]:
        """Detect attempts to establish false context or pre-authorisation."""
        findings: list[DetectorFinding] = []
        all_matches: list[str] = []

        for pattern in self._poisoning_patterns:
            for m in pattern.finditer(content):
                all_matches.append(m.group()[:150])

        if all_matches:
            findings.append(
                DetectorFinding(
                    detector=self.name,
                    score=min(0.90, 0.5 + len(all_matches) * 0.15),
                    category=ThreatCategory.POISONED_CONTEXT,
                    evidence=f"Context poisoning: {'; '.join(all_matches[:3])}",
                    confidence=0.78,
                    details={"poisoning_matches": all_matches[:10]},
                )
            )

        return findings

    def _check_multi_turn_manipulation(self, content: str) -> list[DetectorFinding]:
        """Detect patterns that try to simulate multi-turn conversation."""
        # Look for fake conversation turns embedded in content
        fake_turn_patterns = [
            r'(?:Human|User|Assistant|System|Claude|GPT|AI)\s*:\s*.{10,}',
            r'(?:###\s*)?(?:Human|User|Assistant|System)\s*\n',
            r'<(?:human|user|assistant|system)>.*?</(?:human|user|assistant|system)>',
        ]

        turn_count = 0
        for p in fake_turn_patterns:
            turn_count += len(re.findall(p, content, re.IGNORECASE | re.DOTALL))

        if turn_count >= 2:
            return [
                DetectorFinding(
                    detector=self.name,
                    score=min(0.92, 0.5 + turn_count * 0.15),
                    category=ThreatCategory.INJECTION,
                    evidence=f"{turn_count} simulated conversation turns detected",
                    confidence=0.82,
                    details={"fake_turn_count": turn_count},
                )
            ]
        return []
