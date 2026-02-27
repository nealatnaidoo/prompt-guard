# BUG-002: Module-Level Mutable _DEFAULT_WEIGHTS Shared Reference

- **Source**: verify_deep
- **Date**: 2026-02-27
- **Severity**: low
- **Priority**: low
- **Status**: open
- **Location**: `src/detectors/engine.py:26-31`

## Description

`_DEFAULT_WEIGHTS` is a module-level mutable dict. While the constructor creates a copy via `dict()`, the pattern is fragile. If the copy were removed in a future edit, cross-instance weight pollution would occur.

## Recommended Fix

Use `types.MappingProxyType` or a frozen dict to make `_DEFAULT_WEIGHTS` immutable at the module level.
