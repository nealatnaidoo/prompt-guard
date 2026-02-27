"""AuditPort — abstract interface for scan audit logging.

Decouples the application from concrete logging destinations (file, stdout, etc.).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..models.schemas import ScanResult


class AuditPort(ABC):
    """Port for audit-logging scan results."""

    @abstractmethod
    def log_scan(
        self,
        result: ScanResult,
        source_ip: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Log a scan result for audit/compliance purposes."""
        ...
