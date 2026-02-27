"""ClockPort — abstract interface for time and ID generation.

This port removes non-deterministic calls (time.time, uuid.uuid4) from the domain,
enabling deterministic testing via fake adapters.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class ClockPort(ABC):
    """Port for time and unique-ID generation."""

    @abstractmethod
    def now(self) -> float:
        """Return the current timestamp as a float (epoch seconds)."""
        ...

    @abstractmethod
    def generate_id(self) -> str:
        """Return a unique request identifier string."""
        ...
