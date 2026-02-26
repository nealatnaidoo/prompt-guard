"""Structured audit logging for all scan operations."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import logging

from ..models.schemas import ScanResult

logger = logging.getLogger("prompt_guard.audit")


class AuditLogger:
    """Append-only audit logger for scan results.

    Writes structured JSONL records for every scan operation,
    enabling forensic analysis and compliance reporting.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.destination = self.config.get("destination", "both")
        self.log_file = self.config.get("log_file", "./logs/prompt_guard_audit.jsonl")
        self.log_clean = self.config.get("log_clean", False)
        self._file_handle = None

        if self.enabled and self.destination in ("file", "both"):
            self._ensure_log_dir()

    def _ensure_log_dir(self) -> None:
        log_dir = Path(self.log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)

    def log_scan(
        self,
        result: ScanResult,
        source_ip: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Log a scan result."""
        if not self.enabled:
            return

        # Skip clean results if not logging them
        if not self.log_clean and not result.is_threat:
            return

        record = {
            "timestamp": time.time(),
            "request_id": result.request_id,
            "threat_level": result.threat_level.value,
            "threat_score": result.threat_score,
            "action_taken": result.action_taken.value,
            "content_hash": result.content_hash,
            "finding_count": len(result.findings),
            "categories": list(set(f.category.value for f in result.findings)),
            "detectors_triggered": list(set(f.detector for f in result.findings)),
            "top_score": max((f.score for f in result.findings), default=0.0),
            "latency_ms": result.latency_ms,
            "source_ip": source_ip,
            "summary": result.summary,
        }

        if extra:
            record["extra"] = extra

        # Include finding details for threats
        if result.is_threat:
            record["findings"] = [
                {
                    "detector": f.detector,
                    "category": f.category.value,
                    "score": f.score,
                    "confidence": f.confidence,
                    "evidence": f.evidence[:300],
                }
                for f in result.findings
            ]

        self._write(record)

    def _write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, default=str)

        if self.destination in ("stdout", "both"):
            logger.info(line)

        if self.destination in ("file", "both"):
            try:
                with open(self.log_file, "a") as f:
                    f.write(line + "\n")
            except OSError as e:
                logger.error(f"Audit write error: {e}")
