# Quality Gates: Prompt Guard Retrofit

**Version**: 1
**Created**: 2026-02-26

---

## Gate 1: Tests Pass (Every Task)

**Command**: `pytest tests/ -v`
**Threshold**: All tests green (zero failures)
**When**: After every task completion
**Blocking**: Yes -- no task is complete until all tests pass

---

## Gate 2: Coverage (Post-Epic 2)

**Command**: `pytest tests/ -v --cov=src --cov-report=term-missing`
**Threshold**: >= 80% line coverage
**When**: After T014 (final task)
**Blocking**: Yes -- retrofit is not complete below 80%

---

## Gate 3: Determinism Check (After T008)

**Command**: Manual inspection or grep
**Check**: `src/models/schemas.py` does not import `uuid`, `time`, `random`, or `datetime`
**Verification**:
```bash
grep -n "^import uuid\|^import time\|^import random\|^from datetime" src/models/schemas.py
```
**Threshold**: Zero matches
**When**: After T008 and all subsequent tasks
**Blocking**: Yes

---

## Gate 4: Import Boundary Check (After T009)

**Check**: `src/detectors/engine.py` does not import concrete detector classes
**Verification**:
```bash
grep -n "from.*pattern_detector\|from.*heuristic_detector\|from.*semantic_detector\|from.*entropy_detector\|from.*provenance_detector" src/detectors/engine.py
```
**Threshold**: Zero matches
**When**: After T009 and all subsequent tasks
**Blocking**: Yes

---

## Gate 5: No Module-Level Singleton (After T010)

**Check**: `src/middleware/app.py` does not have `state = AppState()` at module level
**Verification**:
```bash
grep -n "^state = AppState" src/middleware/app.py
```
**Threshold**: Zero matches
**When**: After T010 and all subsequent tasks
**Blocking**: Yes

---

## Gate 6: Type Hints (Every Task)

**Command**: `mypy src/ --ignore-missing-imports` (on modified files)
**Threshold**: No new errors introduced
**When**: After every task that modifies production code
**Blocking**: Advisory (warn, not block)

---

## Gate 7: Backward Compatibility (After T011)

**Check**: All 30 original attack vector tests pass
**Command**: `pytest tests/test_attack_vectors.py -v`
**Threshold**: All 30 tests green
**When**: After T011 and all subsequent tasks
**Blocking**: Yes

---

## Gate 8: Characterisation Tests Exist (Before Epic 2)

**Check**: T005 characterisation tests exist and pass before any Epic 2 task begins
**Command**: `pytest tests/test_engine_characterisation.py -v`
**Threshold**: All characterisation tests green
**When**: Before T006
**Blocking**: Yes -- refactoring cannot begin without characterisation safety net
