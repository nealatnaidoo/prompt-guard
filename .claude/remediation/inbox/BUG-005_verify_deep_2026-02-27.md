# BUG-005: CI Workflow Coverage Threshold Too Low

**ID**: BUG-005
**Source**: verify_deep (2026-02-27)
**Priority**: HIGH
**Status**: open
**Created**: 2026-02-27

---

## Summary

CI workflow enforces 80% coverage threshold but spec requires 100%. This allows future regressions where code quality can degrade to 80% and still pass CI.

---

## Spec Reference

- NFR-11.1: "Maintain 100% test coverage (currently at 100% with 402 tests per solution envelope)"
- Solution envelope line 29: "Test Coverage: Must maintain 100%"
- Solution envelope line 135: "Coverage >= 100% assertion"

---

## Current Implementation

**File**: `.github/workflows/ci.yml` line 42

```yaml
pytest --cov=src --cov-report=term-missing --cov-fail-under=80 -x -q --tb=short
```

**File**: `.github/workflows/deploy.yml` line 41

```yaml
pytest --cov=src --cov-report=term-missing --cov-fail-under=80 -x -q --tb=short
```

---

## Problem

1. **Spec Deviation**: Spec explicitly requires 100%, CI enforces 80%
2. **Regression Risk**: Future PRs could drop coverage to 80.1% and merge without warning
3. **Inconsistency**: Current actual coverage is 100%, but gate allows 20% regression
4. **Both Workflows Affected**: CI and deploy workflows both have the issue

---

## Impact

- Future developers may unknowingly reduce test coverage
- Maintenance burden increases over time (untested code paths multiply)
- Spec non-compliance visible in every CI run
- Deploy workflow allows unvetted code to reach production

---

## Fix Steps

1. Update `.github/workflows/ci.yml` line 42:
   - Change `--cov-fail-under=80` to `--cov-fail-under=100`

2. Update `.github/workflows/deploy.yml` line 41:
   - Change `--cov-fail-under=80` to `--cov-fail-under=100`

3. Test locally:
   ```bash
   pytest --cov=src --cov-report=term-missing --cov-fail-under=100
   ```
   Should pass with "100% coverage achieved" message.

---

## Code Changes

```yaml
# In ci.yml, line 42:
- name: Tests with coverage (pytest)
  run: pytest --cov=src --cov-report=term-missing --cov-fail-under=100 -x -q --tb=short

# In deploy.yml, line 41:
- name: Tests with coverage (pytest)
  run: pytest --cov=src --cov-report=term-missing --cov-fail-under=100 -x -q --tb=short
```

---

## Validation

After fix:
- CI should continue to pass (current coverage is 100%)
- Next PR with any untested code will fail CI immediately
- Coverage violations visible in PR status checks
- Developers incentivized to maintain test quality

---

## Related Issues

- **BUG-003**: Auth header type; unrelated
- **BUG-004**: Missing /v1/health; unrelated
- **BUG-006**: Request logging threat fields; unrelated

