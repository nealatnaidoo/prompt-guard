"""JsonlFileAuditAdapter — audit logging to JSONL files.

Wraps the existing AuditLogger logic from src/utils/audit.py.
"""

from __future__ import annotations

from typing import Any

from ..models.schemas import ScanResult
from ..ports.audit import AuditPort
from ..utils.audit import AuditLogger


class JsonlFileAuditAdapter(AuditPort):
    """Production adapter that logs scan results as JSONL.

    Delegates to the existing AuditLogger implementation.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self._logger = AuditLogger(config)

    def log_scan(
        self,
        result: ScanResult,
        source_ip: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Log a scan result via the underlying AuditLogger."""
        self._logger.log_scan(result, source_ip=source_ip, extra=extra)
