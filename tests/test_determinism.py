"""Determinism verification tests.

Task: T008 - Verify that domain models are free of non-deterministic calls.
"""

from __future__ import annotations

import ast
import inspect
from dataclasses import fields

import pytest

from src.models.schemas import ScanResult, SanitiseResult


class TestScanResultDeterminism:

    def test_scan_result_request_id_is_required(self) -> None:
        """request_id must be a required field with no default."""
        f = next(f for f in fields(ScanResult) if f.name == "request_id")
        from dataclasses import MISSING
        assert f.default is MISSING
        assert f.default_factory is MISSING  # type: ignore[comparison-overlap]

    def test_scan_result_timestamp_is_required(self) -> None:
        """timestamp must be a required field with no default."""
        f = next(f for f in fields(ScanResult) if f.name == "timestamp")
        from dataclasses import MISSING
        assert f.default is MISSING
        assert f.default_factory is MISSING  # type: ignore[comparison-overlap]

    def test_scan_result_raises_without_required_fields(self) -> None:
        """ScanResult() without request_id and timestamp raises TypeError."""
        with pytest.raises(TypeError):
            ScanResult()  # type: ignore[call-arg]

    def test_schemas_no_uuid_import(self) -> None:
        """The schemas module should not import uuid."""
        import src.models.schemas as mod
        source = inspect.getsource(mod)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "uuid", "schemas.py must not import uuid"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "uuid", "schemas.py must not import from uuid"

    def test_schemas_no_time_import(self) -> None:
        """The schemas module should not import time."""
        import src.models.schemas as mod
        source = inspect.getsource(mod)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "time", "schemas.py must not import time"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "time", "schemas.py must not import from time"


class TestSanitiseResultIsDomain:

    def test_sanitise_result_is_dataclass(self) -> None:
        from dataclasses import is_dataclass
        assert is_dataclass(SanitiseResult)

    def test_sanitise_result_fields(self) -> None:
        names = {f.name for f in fields(SanitiseResult)}
        assert names == {"content", "changes", "original_length", "sanitised_length"}

    def test_sanitise_result_was_modified_property(self) -> None:
        r = SanitiseResult(content="x", changes=["a"], original_length=1, sanitised_length=1)
        assert r.was_modified is True
        r2 = SanitiseResult(content="x", changes=[], original_length=1, sanitised_length=1)
        assert r2.was_modified is False

    def test_sanitise_result_to_dict(self) -> None:
        r = SanitiseResult(content="x", changes=["a"], original_length=2, sanitised_length=1)
        d = r.to_dict()
        assert d == {
            "content": "x",
            "changes": ["a"],
            "original_length": 2,
            "sanitised_length": 1,
            "was_modified": True,
        }
