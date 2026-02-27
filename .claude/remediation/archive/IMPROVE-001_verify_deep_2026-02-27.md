# IMPROVE-001: ScanResult Defaults Weaken Spec Intent

- **Source**: verify_deep
- **Date**: 2026-02-27
- **Severity**: medium
- **Priority**: medium
- **Status**: open
- **Location**: `src/models/schemas.py:80-81`

## Description

Spec T008 AC1/AC2 states request_id and timestamp should have "no defaults -- must be provided explicitly." Current implementation uses `request_id: str = ""` and `timestamp: float = 0.0` which are technically defaults. Consider removing defaults to enforce explicit construction.
