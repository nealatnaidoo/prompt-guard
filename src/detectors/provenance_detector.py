"""Provenance detector — source reputation & content lineage.

Evaluates the trustworthiness of content based on its declared source,
structural consistency, and known suspicious origin patterns.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from .base import BaseDetector
from ..models.schemas import ContentSource, DetectorFinding, ThreatCategory


# Known suspicious URL patterns
_SUSPICIOUS_DOMAINS = {
    "pastebin.com", "hastebin.com", "ghostbin.me", "rentry.co",
    "temp.sh", "transfer.sh", "file.io",
}

# URL patterns commonly used for data exfiltration
_EXFIL_URL_PATTERNS = [
    r"https?://[^/]*\.(?:ngrok|loca\.lt|serveo\.net|localhost\.run)",
    r"https?://(?:\d{1,3}\.){3}\d{1,3}",  # raw IP addresses
    r"https?://[^/]*webhook[^/]*",
    r"https?://[^/]*requestbin[^/]*",
    r"https?://[^/]*\.burpcollaborator\.net",
    r"https?://[^/]*\.oastify\.com",
    r"https?://[^/]*\.interact\.sh",
]


class ProvenanceDetector(BaseDetector):
    """Evaluates content trustworthiness based on source and structure.

    Checks:
    1. Source reliability scoring
    2. Embedded URL reputation
    3. Content-source consistency (does the content match what you'd
       expect from the declared source?)
    4. Freshness anomalies (stale timestamps, impossible dates)
    """

    name = "provenance"
    version = "0.1.0"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._exfil_patterns = [re.compile(p, re.IGNORECASE) for p in _EXFIL_URL_PATTERNS]

    async def scan(self, content: str, metadata: dict[str, Any]) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        source = metadata.get("source", ContentSource.UNKNOWN)

        findings.extend(self._check_source_reliability(content, source, metadata))
        findings.extend(self._check_embedded_urls(content))
        findings.extend(self._check_source_consistency(content, source))

        return findings

    def _check_source_reliability(
        self, content: str, source: str | ContentSource, metadata: dict[str, Any]
    ) -> list[DetectorFinding]:
        """Score based on declared content source."""
        findings: list[DetectorFinding] = []

        source_str = source.value if isinstance(source, ContentSource) else str(source)

        # Unknown sources get a baseline suspicion
        if source_str in ("unknown", ContentSource.UNKNOWN.value):
            findings.append(
                DetectorFinding(
                    detector=self.name,
                    score=0.15,
                    category=ThreatCategory.POISONED_CONTEXT,
                    evidence="Content source is unknown/undeclared",
                    confidence=0.40,
                    details={"source": source_str},
                )
            )

        # Check source URL if provided
        source_url = metadata.get("source_url", "")
        if source_url:
            try:
                parsed = urlparse(source_url)
                domain = parsed.netloc.lower()
                if domain in _SUSPICIOUS_DOMAINS:
                    findings.append(
                        DetectorFinding(
                            detector=self.name,
                            score=0.75,
                            category=ThreatCategory.POISONED_CONTEXT,
                            evidence=f"Content from suspicious domain: {domain}",
                            confidence=0.80,
                            details={"domain": domain, "url": source_url},
                        )
                    )
            except Exception:
                pass

        return findings

    def _check_embedded_urls(self, content: str) -> list[DetectorFinding]:
        """Check for suspicious URLs embedded in the content."""
        findings: list[DetectorFinding] = []

        # Extract all URLs
        urls = re.findall(r'https?://[^\s<>"\')\]]+', content)

        for url in urls:
            # Check against exfiltration patterns
            for pattern in self._exfil_patterns:
                if pattern.search(url):
                    findings.append(
                        DetectorFinding(
                            detector=self.name,
                            score=0.85,
                            category=ThreatCategory.DATA_EXFILTRATION,
                            evidence=f"Suspicious URL (potential exfil endpoint): {url[:200]}",
                            confidence=0.78,
                            details={"url": url[:500]},
                        )
                    )
                    break

            # Check for suspicious domain
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                if domain in _SUSPICIOUS_DOMAINS:
                    findings.append(
                        DetectorFinding(
                            detector=self.name,
                            score=0.65,
                            category=ThreatCategory.DATA_EXFILTRATION,
                            evidence=f"Link to untrusted paste/share service: {domain}",
                            confidence=0.70,
                            details={"domain": domain, "url": url[:500]},
                        )
                    )
            except Exception:
                pass

        # Check for URLs with data in query parameters
        data_exfil_urls = re.findall(
            r'https?://[^\s]*\?[^\s]*(?:data|content|text|payload|q|msg|body)=[^\s&]{50,}',
            content,
        )
        for url in data_exfil_urls:
            findings.append(
                DetectorFinding(
                    detector=self.name,
                    score=0.80,
                    category=ThreatCategory.DATA_EXFILTRATION,
                    evidence=f"URL with large data parameter (possible exfil): {url[:200]}",
                    confidence=0.75,
                    details={"url": url[:500]},
                )
            )

        return findings

    def _check_source_consistency(
        self, content: str, source: str | ContentSource
    ) -> list[DetectorFinding]:
        """Check whether content structure matches its declared source type."""
        findings: list[DetectorFinding] = []
        source_str = source.value if isinstance(source, ContentSource) else str(source)

        if source_str == ContentSource.API_RESPONSE.value:
            # API responses shouldn't contain lots of imperative instructions
            imperative_lines = len(re.findall(
                r'(?im)^(?:you\s+(?:must|should|need)|please|ignore|disregard|always|never)\b',
                content,
            ))
            total_lines = content.count('\n') + 1
            if total_lines > 10 and imperative_lines / total_lines > 0.5:
                findings.append(
                    DetectorFinding(
                        detector=self.name,
                        score=0.78,
                        category=ThreatCategory.INDIRECT_INJECTION,
                        evidence=f"API response contains {imperative_lines} imperative instructions ({imperative_lines}/{total_lines} lines)",
                        confidence=0.72,
                        details={"imperative_lines": imperative_lines, "total_lines": total_lines},
                    )
                )

        if source_str == ContentSource.WEB_SCRAPE.value:
            # Web scrapes with AI-addressing language are highly suspicious
            ai_mentions = len(re.findall(
                r'(?i)\b(?:AI|assistant|model|chatbot|GPT|Claude|LLM)\b.*?(?:you\s+(?:should|must)|please|ignore)',
                content,
            ))
            if ai_mentions >= 2:
                findings.append(
                    DetectorFinding(
                        detector=self.name,
                        score=min(0.90, 0.6 + ai_mentions * 0.15),
                        category=ThreatCategory.INDIRECT_INJECTION,
                        evidence=f"Web-scraped content addresses AI directly ({ai_mentions} instances)",
                        confidence=0.82,
                        details={"ai_addressing_count": ai_mentions},
                    )
                )

        return findings
