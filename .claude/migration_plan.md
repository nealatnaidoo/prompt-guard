# Prompt Guard — CAF Retrofit Migration Plan

**Status**: Assessed (Broken Arrow)
**Date**: 2026-02-26
**Severity**: Full Retrofit (no governance artifacts exist)

---

## Project Assessment

| Attribute | Value |
|-----------|-------|
| **Name** | prompt-guard |
| **Description** | Adversarial-grade prompt injection, sanitisation & poisoning protection middleware |
| **Language** | Python 3.10+ |
| **Framework** | FastAPI + Uvicorn |
| **Container** | Dockerfile (python:3.12-slim, port 8420) |
| **Source files** | 20 Python files |
| **Test files** | 4 (conftest, test_sanitiser, test_attack_vectors, __init__) |
| **Total LOC** | ~2,884 |
| **Dependencies** | 12 runtime, 4 dev |
| **Git state** | 1 commit, clean working tree |

### Architecture Analysis

The project has a **layered architecture** that can be mapped to hexagonal:

```
src/
  middleware/app.py      → Driving adapter (FastAPI HTTP)
  detectors/engine.py    → Application/domain service (orchestrator)
  detectors/*.py         → Domain logic (5 detectors: pattern, heuristic, semantic, entropy, provenance)
  detectors/base.py      → Domain port (BaseDetector ABC + DetectorRegistry)
  models/schemas.py      → Domain models (pure dataclasses)
  sanitizers/            → Domain service (content sanitiser)
  utils/config.py        → Driven adapter (config loading)
  utils/audit.py         → Driven adapter (audit logging)
  client.py              → SDK client (driving adapter)
  cli.py                 → CLI entry point (driving adapter)
```

**Positive findings**:
- Clean domain models using stdlib dataclasses (no framework leakage)
- Detector registry pattern (pluggable via BaseDetector ABC)
- Good separation between HTTP layer and detection logic
- Structured logging with structlog

**Gaps for hexagonal compliance**:
- No explicit `ports/` and `adapters/` package structure
- Config loading is a plain function, not a port/adapter
- `AppState` is a mutable module-level singleton (not injected)
- `ScanResult` uses `uuid.uuid4()` and `time.time()` — non-deterministic defaults in domain model

---

## Migration Steps

### Step 1: Scaffold `.claude/` governance structure (via `init` agent)

Create the full `.claude/` folder tree:
```
.claude/
  manifest.yaml
  org.yaml
  artifacts/
  evolution/
  remediation/
    inbox/
    archive/
    findings.log
  outbox/
    pending/
    active/
    completed/
    rejected/
  evidence/
```

**Effort**: ~5 min (automated by `init` agent)

---

### Step 2: Create project CLAUDE.md

Project-level CLAUDE.md with:
- Project description and purpose
- Tech stack (Python 3.10+, FastAPI, Pydantic, scikit-learn)
- Architecture overview (hexagonal mapping)
- Testing conventions (pytest, pytest-asyncio)
- Key commands (run, test, lint)
- Non-negotiable rules specific to this project

**Effort**: ~10 min

---

### Step 3: Design phase — User journeys (via `design` agent, Phase A)

Define the core user journeys:
1. **UJ-001**: Developer scans content via HTTP API (`POST /scan`)
2. **UJ-002**: Developer sanitises content via HTTP API (`POST /sanitise`)
3. **UJ-003**: Developer integrates via Python SDK client
4. **UJ-004**: Developer extends detectors via plugin registry
5. **UJ-005**: Ops monitors service health and statistics

**Effort**: ~30 min

---

### Step 4: Design phase — Solution design (via `design` agent, Phase B)

Formalise the hexagonal architecture:
- Define explicit ports (DetectorPort, SanitiserPort, ConfigPort, AuditPort)
- Map existing code to adapters
- Document the detection pipeline flow
- DevOps envelope (Docker, CI/CD considerations)

**Effort**: ~30 min

---

### Step 5: BA phase — Spec + Tasklist (via `ba` agent)

Produce governance artifacts from design output:
- `002_spec_v1.md` — Full specification
- `003_tasklist_v1.md` — Sequenced task list
- `004_rules_v1.md` — Project rules and quality gates
- Quality gates definition

Since this is a **retrofit** (code already exists), the spec describes what IS, not what WILL BE. Tasks focus on:
- Hexagonal compliance refactoring (ports/adapters structure)
- Determinism fixes (`uuid.uuid4()` and `time.time()` in domain)
- Test coverage expansion (currently only 2 test files with real tests)
- Missing test areas: engine, individual detectors, config, audit, CLI

**Effort**: ~45 min

---

### Step 6: Build phase — Refactoring tasks (via `back` agent)

Execute tasklist items, likely including:
1. Create `ports/` package with explicit port interfaces
2. Create `adapters/` package, move config + audit
3. Inject dependencies into `DetectionEngine` (replace module singleton)
4. Fix non-deterministic defaults in `ScanResult` (inject clock/id-generator)
5. Expand test suite (target: all detectors, engine, sanitiser, API endpoints)

**Effort**: ~2-3 hours

---

### Step 7: Verify phase (via `verify` agent)

- Quick verify after each task
- Deep verify after full feature completion
- Generate evidence artifacts

**Effort**: ~30 min

---

## Priority Order

| Priority | Step | Reason |
|----------|------|--------|
| P0 | Step 1 (init) | Unblocks all governance workflows |
| P0 | Step 2 (CLAUDE.md) | Establishes project rules |
| P1 | Step 3-4 (design) | Documents what exists before changing |
| P1 | Step 5 (BA) | Creates actionable tasklist |
| P2 | Step 6 (build) | Actual refactoring work |
| P2 | Step 7 (verify) | Validates compliance |

---

## Risk Notes

- **Low risk**: Existing code is well-structured and close to hexagonal already
- **Medium risk**: Test coverage is thin — refactoring without comprehensive tests increases regression risk. Recommend writing characterisation tests BEFORE restructuring.
- **Low risk**: Single commit history means no complex merge concerns
- **Note**: `ScanResult.request_id` uses `uuid.uuid4()` — the determinism hook will flag this. It lives in the domain model but is arguably an adapter concern (ID generation). Design phase should decide the approach.
