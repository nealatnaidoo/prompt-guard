"""Pattern-based detector using curated regex rules.

This detector catches known injection patterns, jailbreak templates,
and common attack signatures using layered regular expressions.
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseDetector
from ..models.schemas import DetectorFinding, ThreatCategory


# ── Pattern Definitions ─────────────────────────────────────────────────────
# Each rule: (name, pattern, category, base_score, confidence)

_INJECTION_PATTERNS: list[tuple[str, str, ThreatCategory, float, float]] = [
    # ── Direct injection attempts ────────────────────────────────────────
    (
        "system_prompt_override",
        r"(?i)(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|system|original)\s+(?:instructions?|prompts?|rules?|guidelines?|constraints?|directives?)",
        ThreatCategory.INJECTION,
        0.95,
        0.92,
    ),
    (
        "new_instruction_injection",
        r"(?i)(?:new|updated?|revised?|actual|real|true)\s+(?:system\s+)?(?:instructions?|prompts?|rules?|directives?)\s*[:=]",
        ThreatCategory.INJECTION,
        0.90,
        0.88,
    ),
    (
        "role_reassignment",
        r"(?i)(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you(?:'re|\s+are))|roleplay\s+as|switch\s+(?:to|into)\s+(?:a\s+)?(?:mode|role|persona))",
        ThreatCategory.JAILBREAK,
        0.88,
        0.85,
    ),
    (
        "system_tag_injection",
        r"(?:<\|?(?:system|im_start|im_end|endof(?:text|turn))\|?>|<<\s*SYS\s*>>|\[INST\]|\[/INST\]|<\|(?:user|assistant|tool)\|>)",
        ThreatCategory.INJECTION,
        0.95,
        0.95,
    ),
    (
        "delimiter_injection",
        r"(?:---+\s*(?:system|instructions?|rules?)\s*---+|={3,}\s*(?:new|system)\s*={3,}|#{3,}\s*(?:SYSTEM|ADMIN|OVERRIDE))",
        ThreatCategory.INJECTION,
        0.85,
        0.82,
    ),

    # ── Jailbreak patterns ──────────────────────────────────────────────
    (
        "dan_jailbreak",
        r"(?i)\b(?:DAN|do\s+anything\s+now|Developer\s+Mode|DUDE|STAN|KEVIN)\b\s*(?:mode|prompt|enabled|activated|jailbreak)?",
        ThreatCategory.JAILBREAK,
        0.92,
        0.88,
    ),
    (
        "hypothetical_bypass",
        r"(?i)(?:hypothetically|theoretically|in\s+a\s+fictional\s+(?:world|scenario|story)|imagine\s+(?:you|that|a\s+world)\s+(?:where|in\s+which)\s+(?:there\s+(?:are|were)\s+no|you\s+(?:had|have)\s+no)\s+(?:restrictions?|rules?|limits?|guidelines?)|(?:fictional|imaginary)\s+(?:world|scenario)\s+where\s+(?:there\s+(?:are|were)\s+)?no\s+(?:restrictions?|rules?|limits?|guidelines?))",
        ThreatCategory.JAILBREAK,
        0.80,
        0.75,
    ),
    (
        "filter_evasion",
        r"(?i)(?:without\s+(?:any\s+)?(?:restrictions?|filters?|safeguards?|limitations?|constraints?)|remove\s+(?:all\s+)?(?:filters?|safeguards?|safety)|(?:unrestricted|uncensored|unfiltered)\s+(?:mode|response|output))",
        ThreatCategory.JAILBREAK,
        0.88,
        0.85,
    ),
    (
        "persona_switch",
        r"(?i)(?:(?:from\s+now\s+on|henceforth|for\s+the\s+rest)\s+(?:you\s+are|you're|act\s+as|behave\s+as|respond\s+as)|(?:imagine|suppose|assume|consider)\s+(?:you(?:'re|\s+are|\s+were)|that\s+you(?:'re|\s+are))\s+(?:a|an|the)\b|play\s+(?:the\s+)?(?:role|part|character)\s+of|(?:can|could|would)\s+you\s+(?:be|act\s+as|pretend|play)\b)",
        ThreatCategory.JAILBREAK,
        0.85,
        0.82,
    ),
    (
        "hypothetical_simple",
        r"(?i)(?:(?:what\s+if|suppose|assuming|imagine|consider)\s+(?:there\s+(?:were|are)\s+no|you\s+(?:had|have|were)\s+(?:no|free\s+from|without))\s+(?:rules?|restrictions?|limits?|guidelines?|filters?|safeguards?|constraints?)|in\s+a\s+(?:world|scenario|situation)\s+(?:where|with(?:out))\s+(?:no\s+)?(?:rules?|restrictions?|limits?|safety))",
        ThreatCategory.JAILBREAK,
        0.82,
        0.78,
    ),
    (
        "jailbreak_extended",
        r"(?i)\b(?:jailbreak|jail\s*break|unlock(?:ed)?\s+mode|(?:un)?censored\s+(?:mode|version)|(?:no|zero|without)\s+(?:filter|restriction|safety|guardrail)s?\s+mode|(?:enable|activate|enter|switch\s+to)\s+(?:god|admin|sudo|unrestricted|unfiltered|unlimited)\s+mode)\b",
        ThreatCategory.JAILBREAK,
        0.90,
        0.87,
    ),

    # ── Data exfiltration ───────────────────────────────────────────────
    (
        "data_exfil_request",
        r"(?i)(?:(?:reveal|show|display|output|print|leak|expose|share|tell\s+me)\s+(?:your|the|all)?\s*(?:system\s+prompt|instructions?|training\s+data|config(?:uration)?|API\s+keys?|secrets?|passwords?|tokens?|credentials?))",
        ThreatCategory.DATA_EXFILTRATION,
        0.90,
        0.88,
    ),
    (
        "markdown_exfil",
        r"!\[(?:[^\]]*)\]\(https?://[^)]*(?:\?|&)(?:q|data|text|content|payload|exfil)=",
        ThreatCategory.DATA_EXFILTRATION,
        0.92,
        0.90,
    ),
    (
        "url_exfil_via_image",
        r"(?i)(?:include|embed|render|display)\s+(?:an?\s+)?(?:image|img|picture)\s+from\s+(?:https?://)",
        ThreatCategory.DATA_EXFILTRATION,
        0.75,
        0.70,
    ),

    # ── Privilege escalation ────────────────────────────────────────────
    (
        "admin_claim",
        r"(?i)(?:i\s+am\s+(?:the\s+)?(?:admin|administrator|developer|owner|superuser|root)|admin\s+(?:override|access|mode|privileges?)|(?:sudo|root|admin)\s+(?:mode|access)\s+(?:enabled|granted|activated))",
        ThreatCategory.PRIVILEGE_ESCALATION,
        0.88,
        0.85,
    ),
    (
        "tool_abuse",
        r"(?i)(?:execute|run|call|invoke)\s+(?:the\s+)?(?:following\s+)?(?:command|code|script|function|tool|shell|bash|terminal|system)\s*[:\(]",
        ThreatCategory.PRIVILEGE_ESCALATION,
        0.70,
        0.65,
    ),

    # ── Social engineering ──────────────────────────────────────────────
    (
        "urgency_manipulation",
        r"(?i)(?:(?:this\s+is\s+)?(?:very\s+)?urgent|emergency|critical|(?:you\s+)?must\s+(?:immediately|now|right\s+away)|time[- ]sensitive|do\s+(?:it\s+)?now\s+(?:or|before))",
        ThreatCategory.SOCIAL_ENGINEERING,
        0.60,
        0.55,
    ),
    (
        "authority_impersonation",
        r"(?i)(?:(?:this\s+(?:is|message\s+is)\s+from|on\s+behalf\s+of|authorized\s+by|approved\s+by)\s+(?:the\s+)?(?:system|admin|developer|anthropic|openai|company|management|IT\s+(?:department|team)))",
        ThreatCategory.SOCIAL_ENGINEERING,
        0.85,
        0.82,
    ),

    # ── Indirect injection (content that instructs the model) ───────────
    (
        "hidden_instruction",
        r"(?i)(?:when\s+(?:you|the\s+(?:AI|model|assistant|bot))\s+(?:read|see|encounter|process)\s+this|(?:AI|model|assistant|bot)\s*:\s*(?:please|you\s+(?:should|must|need\s+to)))",
        ThreatCategory.INDIRECT_INJECTION,
        0.85,
        0.80,
    ),
    (
        "instruction_in_data",
        r"(?i)(?:IMPORTANT\s*(?:INSTRUCTION|NOTE|MESSAGE)\s*(?:FOR|TO)\s*(?:THE\s+)?(?:AI|MODEL|ASSISTANT|BOT|CLAUDE|GPT|AGENT))",
        ThreatCategory.INDIRECT_INJECTION,
        0.92,
        0.90,
    ),

    # ── Encoding attacks ────────────────────────────────────────────────
    (
        "base64_payload",
        r"(?:(?:base64|b64)[\s_-]*(?:decode|decode|eval|exec)|atob\s*\(|(?:decode|from)_?base64)",
        ThreatCategory.ENCODING_ATTACK,
        0.75,
        0.70,
    ),
    (
        "unicode_escape_abuse",
        r"(?:\\u[0-9a-fA-F]{4}){4,}|(?:\\x[0-9a-fA-F]{2}){6,}",
        ThreatCategory.ENCODING_ATTACK,
        0.72,
        0.68,
    ),
    (
        "rot13_obfuscation",
        r"(?i)(?:rot13|caesar\s+cipher|decode\s+the\s+following)\s*[:=]?\s*[a-zA-Z]{10,}",
        ThreatCategory.ENCODING_ATTACK,
        0.68,
        0.60,
    ),
    (
        "multilingual_override",
        (
            r"(?i)(?:"
            # German
            r"(?:vergiss|ignorier[e]?|überspring[e]?|missacht[e]?)\s+(?:alle[ns]?\s+)?(?:vorherige[n]?\s+)?(?:Anweisungen|Instruktionen|Regeln|Befehle)"
            r"|"
            # French
            r"(?:ignore[zr]?|oublie[zr]?)\s+(?:les?\s+)?(?:instructions?\s+)?(?:précédentes?|antérieures?|ci-dessus)"
            r"|"
            # Spanish
            r"(?:ignora|olvida|descarta)\s+(?:las?\s+)?(?:instrucciones?\s+)?(?:previas?|anteriores?)"
            r"|"
            # Portuguese
            r"(?:ignore|esqueça|descarte)\s+(?:as?\s+)?(?:instruções?\s+)?(?:anteriores?|prévias?)"
            r"|"
            # Chinese (simplified)
            r"忽略|无视|忘记|丢弃|之前的指令|先前的指示"
            r"|"
            # Japanese
            r"(?:無視|忘れて|以前の指示)"
            r"|"
            # Korean
            r"(?:무시|잊어|이전\s*지시)"
            r")"
        ),
        ThreatCategory.INJECTION,
        0.90,
        0.85,
    ),
]


class PatternDetector(BaseDetector):
    """Detects threats via curated regex pattern matching.

    This is the first and fastest line of defence. It catches
    known attack signatures with high specificity.
    """

    name = "pattern"
    version = "0.3.0"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._compiled: list[tuple[str, re.Pattern, ThreatCategory, float, float]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        flags = re.MULTILINE | re.DOTALL
        if self.config.get("case_insensitive", True):
            flags |= re.IGNORECASE

        for name, pattern, category, score, confidence in _INJECTION_PATTERNS:
            try:
                compiled = re.compile(pattern, flags)
                self._compiled.append((name, compiled, category, score, confidence))
            except re.error:
                continue  # skip malformed patterns in dev

    async def scan(self, content: str, metadata: dict[str, Any]) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        for rule_name, pattern, category, base_score, confidence in self._compiled:
            for match in pattern.finditer(content):
                findings.append(
                    DetectorFinding(
                        detector=self.name,
                        score=base_score,
                        category=category,
                        evidence=match.group()[:200],  # truncate long matches
                        location=f"offset:{match.start()}-{match.end()}",
                        confidence=confidence,
                        details={"rule": rule_name},
                    )
                )

        # Deduplicate overlapping findings from same category
        return self._deduplicate(findings)

    @staticmethod
    def _deduplicate(findings: list[DetectorFinding]) -> list[DetectorFinding]:
        """Keep highest-scoring finding per category per location range."""
        if len(findings) <= 1:
            return findings

        seen: dict[str, DetectorFinding] = {}
        for f in findings:
            key = f"{f.category}:{f.location}"
            if key not in seen or f.score > seen[key].score:
                seen[key] = f
        return list(seen.values())
