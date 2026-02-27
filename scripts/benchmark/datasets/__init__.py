"""Dataset adapter registry."""

from __future__ import annotations

from .base import DatasetAdapter
from .deepset import DeepsetAdapter
from .jailbreak import JailbreakAdapter
from .notinject import NotInjectAdapter
from .pint import PintAdapter

REGISTRY: dict[str, DatasetAdapter] = {
    "deepset": DeepsetAdapter(),
    "pint": PintAdapter(),
    "jailbreak": JailbreakAdapter(),
    "notinject": NotInjectAdapter(),
}

__all__ = ["REGISTRY", "DatasetAdapter"]
