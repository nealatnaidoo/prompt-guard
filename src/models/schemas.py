"""Core data models for Prompt Guard analysis pipeline.

Pure stdlib implementation — no pydantic dependency required.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Enums ───────────────────────────────────────────────────────────────────

class ContentSource(str, Enum):
    USER_INPUT = "user_input"
    WEB_SCRAPE = "web_scrape"
    API_RESPONSE = "api_response"
    FILE_UPLOAD = "file_upload"
    UNKNOWN = "unknown"


class ThreatLevel(str, Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    INSTRUCTION_OVERRIDE = "instruction_override"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ENCODING_ATTACK = "encoding_attack"
    CONFUSABLE_CHARS = "confusable_characters"
    POISONED_CONTEXT = "poisoned_context"
    INDIRECT_INJECTION = "indirect_injection"
    SOCIAL_ENGINEERING = "social_engineering"
    RESOURCE_ABUSE = "resource_abuse"


class PolicyAction(str, Enum):
    PASS = "pass"
    WARN = "warn"
    SANITISE = "sanitise"
    QUARANTINE = "quarantine"
    REJECT = "reject"


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class ScanRequest:
    """Incoming content to be scanned."""
    content: str
    source: ContentSource = ContentSource.UNKNOWN
    metadata: dict[str, Any] = field(default_factory=dict)
    detectors: list[str] | None = None
    policy_override: PolicyAction | None = None


@dataclass
class DetectorFinding:
    """A single finding from one detector."""
    detector: str
    score: float
    category: ThreatCategory
    evidence: str
    location: str | None = None
    confidence: float = 0.8
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete analysis result."""
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: float = field(default_factory=time.time)
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    threat_score: float = 0.0
    action_taken: PolicyAction = PolicyAction.PASS
    findings: list[DetectorFinding] = field(default_factory=list)
    sanitised_content: str | None = None
    content_hash: str | None = None
    latency_ms: float = 0.0
    summary: str = ""

    def add_finding(self, finding: DetectorFinding) -> None:
        self.findings.append(finding)

    @property
    def is_threat(self) -> bool:
        return self.threat_level not in (ThreatLevel.CLEAN, ThreatLevel.LOW)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "threat_level": self.threat_level.value,
            "threat_score": self.threat_score,
            "action_taken": self.action_taken.value,
            "finding_count": len(self.findings),
            "findings": [
                {
                    "detector": f.detector,
                    "score": f.score,
                    "category": f.category.value,
                    "evidence": f.evidence[:200],
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
            "content_hash": self.content_hash,
            "latency_ms": self.latency_ms,
            "summary": self.summary,
        }
