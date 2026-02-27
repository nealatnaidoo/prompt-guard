"""SystemClockAdapter — real clock and ID generation using stdlib."""

from __future__ import annotations

import time
import uuid

from ..ports.clock import ClockPort


class SystemClockAdapter(ClockPort):
    """Production adapter that uses real system time and UUID generation."""

    def now(self) -> float:
        """Return the current time as epoch seconds."""
        return time.time()

    def generate_id(self) -> str:
        """Return a 16-character hex ID from uuid4."""
        return uuid.uuid4().hex[:16]
