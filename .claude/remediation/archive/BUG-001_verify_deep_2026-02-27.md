# BUG-001: Engine Fallback Path Retains Non-Deterministic uuid/time Calls

- **Source**: verify_deep
- **Date**: 2026-02-27
- **Severity**: medium
- **Priority**: high
- **Status**: open
- **Location**: `src/detectors/engine.py:96-102`

## Description

When `self.clock is None`, the engine falls back to `import uuid; uuid.uuid4().hex[:16]` and `time.time()`. This defeats the determinism guarantee established by T008/T009. While the production composition root always injects a clock, the fallback path is a governance violation.

## Evidence

```python
# engine.py lines 96-102
if self.clock is not None:
    request_id = self.clock.generate_id()
    timestamp = self.clock.now()
else:
    import uuid as _uuid
    request_id = _uuid.uuid4().hex[:16]
    timestamp = time.time()
```

## Recommended Fix

Remove the fallback entirely. Make `clock` a required parameter or default to `SystemClockAdapter()`.

## Impact

Any code path constructing `DetectionEngine()` without a clock will produce non-deterministic output, violating NFR-1.
