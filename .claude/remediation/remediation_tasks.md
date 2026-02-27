# Remediation Tasks: Prompt Guard

**Last Updated**: 2026-02-27
**Source**: Deep Verify Review

---

## Priority: High

### BUG-001: Engine Fallback Path Retains Non-Deterministic uuid/time Calls
- **Severity**: medium
- **Location**: `src/detectors/engine.py:96-102`
- **Source**: verify_deep (2026-02-27)
- **Status**: open
- **Detail**: When `self.clock is None`, inline `uuid.uuid4()` and `time.time()` calls bypass determinism guarantee. Remove fallback or default to `SystemClockAdapter()`.

---

## Priority: Medium

### IMPROVE-001: ScanResult Defaults Weaken Spec Intent
- **Severity**: medium
- **Location**: `src/models/schemas.py:80-81`
- **Source**: verify_deep (2026-02-27)
- **Status**: open
- **Detail**: `request_id: str = ""` and `timestamp: float = 0.0` allow construction without explicit values. Spec intent was "no defaults." Consider removing defaults.

---

## Priority: Low

### BUG-002: Module-Level Mutable _DEFAULT_WEIGHTS
- **Severity**: low
- **Location**: `src/detectors/engine.py:26-31`
- **Source**: verify_deep (2026-02-27)
- **Status**: open
- **Detail**: Mutable module-level dict; currently safe due to `dict()` copy in constructor but fragile. Use `MappingProxyType` or frozen dict.

### IMPROVE-002: Engine Conditional Concrete Detector Imports (No Inbox File)
- **Priority**: low
- **Status**: advisory
- **Detail**: `_register_default_detectors()` has lazy imports of 5 concrete detectors. Move to factory or composition root for full hexagonal purity.

### IMPROVE-003: Zero Coverage on cli.py and client.py (No Inbox File)
- **Priority**: low
- **Status**: deferred (per spec -- out of scope)
- **Detail**: `src/cli.py` (0%) and `src/client.py` (0%) have no tests. Tracked for future sprint.

---

## Resolved (This Sprint)

| ID | Description | Resolved By |
|----|-------------|-------------|
| BUG-001 (spec) | Unreachable branch in _aggregate_scores | T003 |
| BUG-002 (spec) | Missing HealthResponse class | T002 |
| BUG-003 (spec) | Hardcoded path in test file | T001 |
