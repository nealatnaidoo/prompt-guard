# Specification: Prompt Guard Retrofit

**Version**: 1
**Created**: 2026-02-26
**Type**: Retrofit (hexagonal compliance + test coverage + bug fixes)
**Input Artifacts**: `000_user_journeys_v1.md`, `001_solution_envelope_v1.md`

---

## 1. Project Overview

Prompt Guard is an adversarial-grade middleware service (~2,884 LOC, 20 Python files) that scans and sanitises content flowing into LLM-powered applications. It uses a multi-detector pipeline (pattern, heuristic, semantic, entropy, provenance) with weighted score aggregation to classify threats across 11 categories and enforce policy actions.

**This is a retrofit, not greenfield.** The codebase is functional and partially hexagonal. The goal is to:

1. Fix confirmed bugs (3 found)
2. Close hexagonal architecture gaps (7 identified)
3. Establish characterisation tests before refactoring
4. Achieve 80% test coverage with API-level integration tests

### DevOps Approval Status

The solution envelope has DevOps approval as `pending` with the note: "Retrofit documentation. DevOps consultation deferred - no deployment changes proposed in this envelope." Since this retrofit scope is purely code-internal (no Dockerfile changes, no CI/CD changes, no deployment changes), BA proceeds with spec creation. Any future infrastructure tasks (Docker improvements, CI/CD) require DevOps approval before implementation.

---

## 2. Scope

### In Scope

- Fix 3 confirmed bugs (aggregate_scores order, HealthResponse missing, hardcoded test path)
- Create characterisation tests for all existing behaviour
- Extract explicit ports (ClockPort, ConfigPort, AuditPort)
- Remove non-deterministic defaults from domain model (ScanResult)
- Refactor AppState to use dependency injection via composition root
- Move SanitiseResult to domain models
- Decouple engine from concrete detector imports
- Add HTTP API integration tests (FastAPI TestClient)
- Add health/stats endpoint tests

### Out of Scope

- New detectors or threat categories
- Authentication/authorization
- Rate limiting implementation
- Docker improvements (multi-stage build, non-root user)
- CI/CD pipeline
- Kubernetes manifests
- Package naming standardisation (src/ vs prompt_guard/)
- SDK client tests (deferred -- SDK wraps HTTP, test HTTP first)
- CLI tests (deferred -- P3 priority)

---

## 3. Confirmed Bugs

### BUG-001: Unreachable Branch in `_aggregate_scores`

**Location**: `src/detectors/engine.py`, lines 176-179
**Issue**: The boost logic checks `if agreeing_detectors >= 3` before `elif agreeing_detectors >= 4`. Since any value >= 4 also satisfies >= 3, the 1.25x boost for 4+ detectors is unreachable. Only the 1.15x boost ever applies.
**Fix**: Swap the order -- check >= 4 first, then >= 3.

### BUG-002: Missing `HealthResponse` Class

**Location**: `src/middleware/app.py` line 24 imports `HealthResponse` from `src/models/schemas.py`, but this class does not exist in schemas.py.
**Impact**: The `/health` endpoint will raise an `ImportError` at module load time.
**Fix**: Define `HealthResponse` dataclass in `src/models/schemas.py`.

### BUG-003: Hardcoded Path in Test File

**Location**: `tests/test_attack_vectors.py`, line 11
**Issue**: `sys.path.insert(0, "/sessions/admiring-peaceful-gauss/prompt-guard")` -- this path is from a specific development environment and will not work anywhere else.
**Fix**: Remove the hardcoded path. Use proper package configuration or relative imports.

---

## 4. Hexagonal Gaps

Summarised from the solution envelope. Each gap maps to one or more tasks.

| ID | Gap | Severity | Current State | Target State |
|----|-----|----------|---------------|--------------|
| GAP-1 | Non-deterministic defaults in ScanResult | CRITICAL | `uuid.uuid4()` and `time.time()` as default_factory | Inject via ClockPort; no defaults in dataclass |
| GAP-2 | Module-level AppState singleton | HIGH | `state = AppState()` at module level | Composition root in lifespan; DI via app.state |
| GAP-3 | No explicit ports package | MEDIUM | BaseDetector is the only port | `src/ports/` package with all port ABCs |
| GAP-4 | Config loading not behind port | MEDIUM | Free function `load_config()` with direct filesystem access | ConfigPort ABC + YamlFileConfigAdapter |
| GAP-5 | Audit logger not behind port | MEDIUM | Direct file I/O in AuditLogger | AuditPort ABC + JsonlFileAuditAdapter |
| GAP-6 | Engine imports concrete detectors | LOW | Hard imports of 5 detector classes | Detectors injected via constructor/registry |
| GAP-7 | SanitiseResult not a domain dataclass | LOW | Regular class inside sanitizer module | Dataclass in `src/models/schemas.py` |

---

## 5. Functional Requirements

Derived from the 6 user journeys. These document existing behaviour that must be preserved through refactoring.

### FR-1: Content Scanning (J001)

- POST /scan accepts `content`, `source`, optional `metadata`, `detectors`, `policy_override`
- Pre-check: content exceeding 500,000 chars returns threat_level=HIGH, score=0.90, action=REJECT
- Pre-check: empty/whitespace content returns threat_level=CLEAN, summary="Empty content"
- Runs selected detectors (all 5 by default, or filtered by `detectors` field)
- Parallel execution via asyncio.gather (configurable)
- Weighted score aggregation with multi-detector boost and critical finding override
- Threat classification: CLEAN (<0.20), LOW (0.20-0.39), MEDIUM (0.40-0.64), HIGH (0.65-0.84), CRITICAL (>=0.85)
- Critical category override: prompt_injection, jailbreak, data_exfiltration with score >=0.90 force CRITICAL
- Policy action mapping: CLEAN/LOW->PASS, MEDIUM->WARN, HIGH->QUARANTINE, CRITICAL->REJECT
- Policy override respected when provided
- Detector exceptions logged but do not crash pipeline
- Audit log written; stats updated

### FR-2: Content Sanitisation (J002)

- POST /sanitise accepts `content`, `source`, optional `metadata`, `sanitise_level`
- First runs full scan pipeline
- Escalates sanitise level: HIGH/CRITICAL -> strict, MEDIUM -> standard
- Multi-pass sanitisation: (1) strip invisible Unicode, (2) normalise confusables, (3) escape AI tags, (4) neutralise delimiters, (5) wrap in safety delimiters (strict only)
- Code blocks (fenced with backticks) preserved through sanitisation
- Returns scan_result + sanitised_content + changes + was_modified

### FR-3: Health Monitoring (J005)

- GET /health returns status="ok", detectors_loaded count, uptime_seconds
- GET /stats returns uptime, total_scans, threats_detected, threat_rate, by_level, by_action, avg_latency_ms

### FR-4: Custom Detector Registration (J004)

- Subclass BaseDetector with name, version, and async scan method
- Register via `engine.register_detector(detector, weight)`
- Weights re-normalised on registration
- Custom detector participates in scan pipeline
- Custom detector exceptions handled gracefully

---

## 6. Non-Functional Requirements

### NFR-1: Determinism

- Domain models (`src/models/schemas.py`) must not contain calls to `uuid`, `time`, `random`, `datetime.now()`
- All non-deterministic values must be injected through ports
- Tests must be reproducible with fixed clock and ID generators

### NFR-2: Testability

- Target: 80% code coverage
- All public API endpoints must have integration tests (FastAPI TestClient)
- Characterisation tests must capture current detector behaviour before any refactoring
- Test fixtures must provide fake/stub implementations of all ports

### NFR-3: Performance

- Scan latency must not increase measurably from refactoring (no new I/O in hot path)
- Parallel detector execution must remain the default

### NFR-4: Backward Compatibility

- All existing API contracts (request/response shapes) must be preserved
- All existing tests must continue to pass (after fixing BUG-003 path issue)
- Detector scoring behaviour must not change (verified by characterisation tests)

---

## 7. Architecture Target State

### Package Structure (Target)

```
src/
  __init__.py
  client.py                          # Driving adapter (unchanged)
  cli.py                             # Driving adapter (unchanged)
  ports/                             # NEW: Port interfaces
    __init__.py
    clock.py                         # ClockPort ABC (now, generate_id)
    config.py                        # ConfigPort ABC (load)
    audit.py                         # AuditPort ABC (log_scan)
  middleware/
    __init__.py
    app.py                           # Driving adapter (refactored DI)
  detectors/
    __init__.py
    base.py                          # BaseDetector ABC + DetectorRegistry (unchanged)
    engine.py                        # Application service (refactored: injected deps)
    pattern_detector.py              # (unchanged)
    heuristic_detector.py            # (unchanged)
    semantic_detector.py             # (unchanged)
    entropy_detector.py              # (unchanged)
    provenance_detector.py           # (unchanged)
  sanitizers/
    __init__.py
    content_sanitizer.py             # Domain service (SanitiseResult moved out)
  models/
    __init__.py
    schemas.py                       # Domain models (deterministic, + HealthResponse, + SanitiseResult)
  adapters/                          # NEW: Driven adapter implementations
    __init__.py
    clock.py                         # SystemClockAdapter, FixedClockAdapter
    config.py                        # YamlFileConfigAdapter
    audit.py                         # JsonlFileAuditAdapter
  utils/
    __init__.py
    config.py                        # Retained as thin wrapper (delegates to adapter)
    audit.py                         # Retained as thin wrapper (delegates to adapter)
```

### Composition Root

The FastAPI lifespan function in `app.py` becomes the composition root:

1. Load config via ConfigPort adapter
2. Create ClockPort adapter (SystemClockAdapter)
3. Create AuditPort adapter (JsonlFileAuditAdapter)
4. Create detectors and register in DetectorRegistry
5. Create DetectionEngine with injected registry, clock, config
6. Create ContentSanitiser
7. Store all in `app.state` (typed)

### Port Definitions

**ClockPort** (ABC):
- `now() -> float` -- current timestamp
- `generate_id() -> str` -- unique request ID

**ConfigPort** (ABC):
- `load() -> dict[str, Any]` -- load and return configuration dictionary

**AuditPort** (ABC):
- `log_scan(result: ScanResult, source_ip: str | None, extra: dict | None) -> None`

---

## 8. Quality Gates

| Gate | Requirement | Tool |
|------|-------------|------|
| Tests pass | All tests green | `pytest tests/ -v` |
| Coverage | >= 80% | `pytest --cov=src --cov-report=term-missing` |
| Type hints | No mypy errors in modified files | `mypy src/ --ignore-missing-imports` |
| Determinism | No uuid/time/random in domain models | Manual review + hook |
| Import boundary | Domain models do not import from adapters/framework | Manual review |
| Backward compat | Existing test_attack_vectors tests still pass | `pytest tests/test_attack_vectors.py` |

---

## 9. Epics

### Epic 1: Bug Fixes and Test Foundation

Fix confirmed bugs and establish characterisation test suite as safety net before refactoring.

Tasks: T001-T005

### Epic 2: Hexagonal Port Extraction

Create port interfaces, adapter implementations, and refactor domain to use injected dependencies.

Tasks: T006-T012

### Epic 3: Integration Tests

Add HTTP-level API tests to verify end-to-end behaviour through the driving adapter.

Tasks: T013-T014
