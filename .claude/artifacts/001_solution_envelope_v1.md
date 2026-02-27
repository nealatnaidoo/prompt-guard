# prompt-guard -- Solution Envelope

## Metadata
- **Project Slug**: prompt-guard
- **Version**: v1
- **Created**: 2026-02-26
- **Status**: ready_for_ba
- **Type**: Retrofit (documenting existing + identifying gaps)

---

## Problem Statement

Prompt Guard is an adversarial-grade middleware service that scans and sanitises content flowing into LLM-powered applications. It uses a multi-detector pipeline (pattern matching, heuristic analysis, semantic classification, entropy detection, and provenance checking) with weighted score aggregation to classify threats across 11 categories and enforce policy actions. The codebase is functional but was not built with hexagonal architecture principles. This envelope documents the as-is architecture, maps it to hexagonal concepts, and identifies the refactoring path.

---

## Constraints & Inputs

- **Language**: Python 3.10+ (currently targeting 3.12 in Docker)
- **Framework**: FastAPI + Uvicorn
- **Dependencies**: pydantic, structlog, httpx, scikit-learn, numpy, tiktoken, xxhash, aiofiles, regex, PyYAML
- **Container**: Docker (python:3.12-slim), port 8420
- **Existing Tests**: 2 test files (unittest-based attack vectors, pytest-based sanitiser)
- **No Frontend**: Pure API/SDK service
- **Constraint**: This is a retrofit. No new features. Document what exists, then identify gaps.

---

## Personas & Roles

From Phase A journeys:

| Persona | Role | Primary Journeys |
|---------|------|------------------|
| AI Platform Developer | Integrates Prompt Guard into LLM pipelines via HTTP API or SDK | J001, J002, J003 |
| Plugin Developer | Extends detection with custom detectors | J004 |
| Ops Engineer | Monitors service health, configures deployment | J005, J006 |

---

## In Scope / Out of Scope

### In Scope (Retrofit)
- Document existing hexagonal architecture mapping (ports, adapters, domain)
- Identify gaps for hexagonal compliance
- Define refactoring strategy for determinism, dependency injection, port extraction
- Identify missing test coverage
- Document Docker/deployment concerns

### Out of Scope
- New detectors or threat categories
- LLM judge implementation (semantic_detector has config but implementation is pattern-based)
- Rate limiting implementation (configured in YAML but not enforced in code)
- Log retention enforcement (configured but not implemented)
- Frontend/UI
- Authentication/authorization (no auth exists currently)
- Horizontal scaling / load balancing architecture

---

## Core User Flows

### F1: Content Scanning (J001)

```
Developer -> POST /scan -> FastAPI app.py
  -> DetectionEngine.scan()
    -> Pre-checks (length, empty)
    -> [PatternDetector, HeuristicDetector, SemanticDetector, EntropyDetector, ProvenanceDetector]
       (parallel via asyncio.gather)
    -> _aggregate_scores() (weighted combination + boost + critical override)
    -> _classify_threat() (score -> ThreatLevel enum)
    -> _determine_action() (ThreatLevel -> PolicyAction)
    -> _generate_summary()
  -> AuditLogger.log_scan()
  -> Update AppState.stats
  -> Return ScanResult JSON
```

### F2: Content Sanitisation (J002)

```
Developer -> POST /sanitise -> FastAPI app.py
  -> [Run F1 scan pipeline first]
  -> Escalate sanitise level based on threat_level:
     HIGH/CRITICAL -> strict, MEDIUM -> standard, else -> requested level
  -> ContentSanitiser.sanitise(content, level)
    -> Extract code blocks (preserve)
    -> Pass 1: Strip invisible Unicode
    -> Pass 2: Normalise confusable characters
    -> Pass 3: Escape AI-targeted XML tags
    -> Pass 4: Neutralise delimiter injection
    -> Pass 5: Wrap in safety delimiters (strict only)
    -> Restore code blocks
  -> Return SanitiseResponse (scan_result + sanitised_content + changes)
```

### F3: SDK Integration (J003)

```
Developer -> PromptGuardClient(base_url)
  -> async with client:
    -> client.scan(content) -> POST /scan -> ScanResponse wrapper
    -> client.sanitise(content) -> POST /sanitise -> ScanResponse wrapper
    -> client.health() -> GET /health -> dict
    -> client.stats() -> GET /stats -> dict
  -> result.is_safe -> bool gate for pipeline decisions
```

### F4: Custom Detector Extension (J004)

```
Developer -> Subclass BaseDetector
  -> Define name, version class attributes
  -> Implement async scan(content, metadata) -> list[DetectorFinding]
  -> engine.register_detector(detector, weight)
    -> Registry stores detector by name
    -> Weights re-normalised
  -> Detector participates in next scan() call
```

### F5: Health & Stats Monitoring (J005)

```
Ops -> GET /health -> HealthResponse(status, detectors_loaded, uptime_seconds)
Ops -> GET /stats -> StatsResponse(uptime, total_scans, threats_detected, threat_rate, by_level, by_action, avg_latency_ms)
```

---

## Key Domain Objects

| Object | Location | Type | Description |
|--------|----------|------|-------------|
| `ScanRequest` | `src/models/schemas.py` | Dataclass | Input: content, source (ContentSource enum), metadata, optional detector list, policy override |
| `ScanResult` | `src/models/schemas.py` | Dataclass | Output: request_id, timestamp, threat_level, threat_score, action_taken, findings, content_hash, latency_ms, summary |
| `DetectorFinding` | `src/models/schemas.py` | Dataclass | Single finding: detector name, score (0-1), category (ThreatCategory), evidence, location, confidence, details |
| `ContentSource` | `src/models/schemas.py` | Enum | user_input, web_scrape, api_response, file_upload, unknown |
| `ThreatLevel` | `src/models/schemas.py` | Enum | clean, low, medium, high, critical |
| `ThreatCategory` | `src/models/schemas.py` | Enum | 11 categories (prompt_injection, jailbreak, instruction_override, data_exfiltration, privilege_escalation, encoding_attack, confusable_characters, poisoned_context, indirect_injection, social_engineering, resource_abuse) |
| `PolicyAction` | `src/models/schemas.py` | Enum | pass, warn, sanitise, quarantine, reject |
| `SanitiseResult` | `src/sanitizers/content_sanitizer.py` | Class | Output of sanitisation: content, changes, original/sanitised length, was_modified |
| `BaseDetector` | `src/detectors/base.py` | ABC | Abstract: name, version, config, scan() |
| `DetectorRegistry` | `src/detectors/base.py` | Class | Registry: register(), get(), all(), names(), __len__() |

---

## Policy & Rules Candidates

| Rule | Current Implementation | Location |
|------|----------------------|----------|
| Threat classification thresholds | CLEAN <0.20, LOW 0.20-0.39, MEDIUM 0.40-0.64, HIGH 0.65-0.84, CRITICAL >=0.85 | `engine.py:_classify_threat` |
| Critical category override | prompt_injection, jailbreak, data_exfiltration with score >=0.90 force CRITICAL | `engine.py:_classify_threat` |
| Policy action mapping | CLEAN/LOW->PASS, MEDIUM->WARN, HIGH->QUARANTINE, CRITICAL->REJECT | `engine.py:_determine_action` |
| Multi-detector boost | 3+ detectors agreeing (score >0.5) -> 1.15x boost; 4+ -> 1.25x | `engine.py:_aggregate_scores` |
| Critical finding floor | Any finding with effective score >=0.90 forces base_score >= 0.80 | `engine.py:_aggregate_scores` |
| Sanitise level escalation | HIGH/CRITICAL -> strict, MEDIUM -> standard | `app.py:sanitise_content` |
| Detector weights | pattern 0.30, heuristic 0.25, semantic 0.25, entropy 0.10, provenance 0.10 | `engine.py:_DEFAULT_WEIGHTS` |
| Content length limit | 500,000 characters, auto-reject above | `engine.py:scan` pre-check |
| Audit logging filter | Clean results not logged unless log_clean=true | `audit.py:log_scan` |

---

## Architecture Proposal

### Current Architecture (As-Is)

The codebase has a layered structure that is partially hexagonal but lacks explicit port/adapter separation:

```
                    ┌─────────────────────────────────┐
                    │         DRIVING ADAPTERS          │
                    │                                   │
                    │  app.py (FastAPI HTTP)            │
                    │  client.py (Python SDK)           │
                    │  cli.py (CLI/Uvicorn launcher)    │
                    └──────────┬────────────────────────┘
                               │
                    ┌──────────▼────────────────────────┐
                    │    APPLICATION SERVICE             │
                    │                                   │
                    │  engine.py (DetectionEngine)      │
                    │  - orchestrates detectors          │
                    │  - aggregates scores              │
                    │  - classifies threats             │
                    │  - determines actions             │
                    └──────────┬────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                     │
   ┌──────▼──────┐   ┌────────▼───────┐   ┌────────▼───────┐
   │   DOMAIN     │   │   DOMAIN       │   │   DRIVEN       │
   │              │   │   SERVICES     │   │   ADAPTERS     │
   │ schemas.py   │   │                │   │                │
   │ (models,     │   │ base.py (ABC)  │   │ config.py      │
   │  enums)      │   │ 5 detectors   │   │ audit.py       │
   │              │   │ sanitizer.py   │   │                │
   └──────────────┘   └────────────────┘   └────────────────┘
```

### Hexagonal Architecture Mapping

| Hexagonal Concept | Current Location | Compliance |
|-------------------|------------------|------------|
| **Domain Models** | `src/models/schemas.py` | PARTIAL - Pure dataclasses and enums, good. But ScanResult has non-deterministic defaults (uuid.uuid4, time.time). |
| **Domain Port (Inbound)** | `src/detectors/base.py` (BaseDetector ABC) | GOOD - Clean abstract interface. |
| **Application Service** | `src/detectors/engine.py` (DetectionEngine) | PARTIAL - Good orchestration, but directly instantiates concrete detectors in `_register_default_detectors`. |
| **Driving Adapter: HTTP** | `src/middleware/app.py` | PARTIAL - FastAPI endpoint, but module-level AppState singleton not injected. |
| **Driving Adapter: SDK** | `src/client.py` | GOOD - Clean async HTTP client, properly separated. |
| **Driving Adapter: CLI** | `src/cli.py` | GOOD - Thin wrapper around uvicorn. |
| **Driven Adapter: Config** | `src/utils/config.py` | POOR - Direct filesystem access, not behind a port/interface. |
| **Driven Adapter: Audit** | `src/utils/audit.py` | POOR - Direct file I/O, not behind a port/interface. |
| **Domain Service: Sanitiser** | `src/sanitizers/content_sanitizer.py` | GOOD - Pure logic, no I/O dependencies. |
| **Domain Services: Detectors** | `src/detectors/*.py` (5 concrete detectors) | GOOD - All implement BaseDetector port. Pure computation, no I/O. |

### Components

- **C1: Domain Models** (`src/models/schemas.py`) - Pure data structures: ScanRequest, ScanResult, DetectorFinding, enums
- **C2: Detection Port** (`src/detectors/base.py`) - BaseDetector ABC + DetectorRegistry
- **C3: Detection Engine** (`src/detectors/engine.py`) - Application service: orchestration, scoring, classification
- **C4: Pattern Detector** (`src/detectors/pattern_detector.py`) - Regex-based threat pattern matching (20 curated rules)
- **C5: Heuristic Detector** (`src/detectors/heuristic_detector.py`) - Structural/statistical analysis (5 heuristic checks)
- **C6: Semantic Detector** (`src/detectors/semantic_detector.py`) - AI-addressing and context poisoning detection (4 checks)
- **C7: Entropy Detector** (`src/detectors/entropy_detector.py`) - Shannon entropy, base64/hex decoding, nested encoding detection
- **C8: Provenance Detector** (`src/detectors/provenance_detector.py`) - Source reputation, URL analysis, source-content consistency
- **C9: Content Sanitiser** (`src/sanitizers/content_sanitizer.py`) - Multi-pass content cleaning service
- **C10: HTTP Adapter** (`src/middleware/app.py`) - FastAPI driving adapter (4 endpoints)
- **C11: SDK Adapter** (`src/client.py`) - Python async HTTP client
- **C12: CLI Adapter** (`src/cli.py`) - Command-line launcher
- **C13: Config Adapter** (`src/utils/config.py`) - YAML config loading with env var overrides
- **C14: Audit Adapter** (`src/utils/audit.py`) - JSONL audit logging

### Ports (To Be Extracted)

Currently implicit. These should be made explicit:

- **P1: DetectorPort** (exists as BaseDetector ABC) - `scan(content, metadata) -> list[DetectorFinding]`
- **P2: ConfigPort** (missing) - `load() -> dict` - Abstract interface for configuration loading
- **P3: AuditPort** (missing) - `log_scan(result, source_ip, extra) -> None` - Abstract interface for audit logging
- **P4: ClockPort** (missing) - `now() -> float`, `uuid() -> str` - Deterministic time and ID generation
- **P5: ScanServicePort** (missing) - `scan(request) -> ScanResult` - Inbound port for the application service

---

## Adjacent Impact Zones

| Component | Primary Scope | Adjacent Zones | Rationale | Boundary |
|-----------|---------------|----------------|-----------|----------|
| C1: Domain Models | `schemas.py` | C3 (engine), C10 (app), C11 (SDK), C14 (audit) | All components import models. Changing ScanResult defaults affects everything. | include_in_scope |
| C3: Detection Engine | `engine.py` | C10 (app), C4-C8 (all detectors) | Engine is the core hub. Changing its constructor signature affects app.py. | include_in_scope |
| C10: HTTP Adapter | `app.py` | C3 (engine), C9 (sanitiser), C13 (config), C14 (audit) | AppState wires everything. Refactoring DI here is the main integration point. | include_in_scope |
| C13: Config Adapter | `config.py` | C10 (app lifespan), C12 (CLI) | Config is loaded in two places. Extracting a port affects both. | include_in_scope |
| C14: Audit Adapter | `audit.py` | C10 (app endpoints) | Only used in app.py scan/sanitise handlers. | include_in_scope |
| C4-C8: Detectors | 5 detector files | C3 (engine imports and registers them) | Detectors are already behind BaseDetector port. Engine directly imports concrete classes. | separate_task |
| C9: Sanitiser | `content_sanitizer.py` | C10 (app.py sanitise endpoint) | Already pure logic. Only adjacent to app.py. | document_only |

---

## Security & Privacy

### Current Controls

| Control | Implementation | Status |
|---------|---------------|--------|
| Content length limit | 500K char pre-check in engine | Implemented |
| Content hashing | SHA-256 first 32 chars, logged in audit | Implemented |
| Audit trail | JSONL append-only logging | Implemented |
| CORS | Wildcard allow_origins=["*"] | INSECURE - should be restricted |
| Input validation | Pydantic model validation on request bodies | Implemented |
| Error handling | Generic 500 responses, no internal details leaked | Implemented |
| Content not stored | Only hash stored in audit, not raw content | Implemented (content logged only for threats) |

### Threats / Controls Needed

| Threat | Risk | Current Mitigation | Gap |
|--------|------|-------------------|-----|
| Denial of Service via large payloads | Medium | 500K char limit | No rate limiting enforced (configured but not implemented) |
| CORS wildcard allows any origin | Low (backend service) | None | Should restrict to known origins or remove CORS for internal services |
| No authentication on endpoints | High (if exposed) | None | No auth mechanism exists. Assumes network-level protection. |
| Audit log tampering | Medium | Append-only file | No integrity verification (e.g., chained hashes) |
| Content leakage in logs | Medium | Hash-only for clean; full findings for threats | Threat evidence excerpts (300 chars) are logged |
| Regex ReDoS | Low | Compiled patterns with timeouts | No explicit regex timeout; some patterns could be slow on crafted input |

---

## Operational Reality

### Current Deployment

- **Docker**: `python:3.12-slim`, port 8420, single CMD uvicorn
- **Workers**: Configurable (default 4 via config, CLI override)
- **Health check**: GET /health endpoint available for probes
- **Logging**: structlog for application logs, custom JSONL for audit
- **Config**: YAML file + environment variable overrides

### Deployment Gaps

| Gap | Impact | Priority |
|-----|--------|----------|
| No multi-stage Docker build | Image larger than necessary (includes build tools) | P3 |
| No non-root user in Dockerfile | Security concern for production | P2 |
| COPY before pip install | Docker layer cache invalidated on any file change | P3 |
| No .dockerignore | Unnecessary files in image (tests, .git, etc.) | P3 |
| No CI/CD pipeline | No automated testing or deployment | P2 |
| No Kubernetes manifests | Manual deployment only | P3 |
| Audit log volume mount not configured | Logs lost on container restart | P2 |

---

## DevOps Approval

```yaml
devops_approval:
  approved_by: "pending"
  date: "2026-02-26"
  canonical_version: "v1"
  non_negotiables_verified: false
  notes: "Retrofit documentation. DevOps consultation deferred - no deployment changes proposed in this envelope. Approval required before any infrastructure changes are implemented."
```

---

## Gaps for Hexagonal Compliance

### Gap 1: Non-Deterministic Defaults in Domain Model (CRITICAL)

**Location**: `src/models/schemas.py`, lines 82-83
**Issue**: `ScanResult` uses `uuid.uuid4().hex[:16]` and `time.time()` as default_factory values. Domain objects must be deterministic.
**Fix**: Extract a ClockPort interface. Inject a clock/ID generator into DetectionEngine. Engine sets request_id and timestamp, not the dataclass default.

### Gap 2: Module-Level AppState Singleton (HIGH)

**Location**: `src/middleware/app.py`, lines 39-48
**Issue**: `state = AppState()` is a module-level singleton. Engine, sanitiser, audit, config are wired in the lifespan function and stored as attributes. This is not dependency-injected.
**Fix**: Use FastAPI's dependency injection (Depends) or pass dependencies through the app.state mechanism with proper typing. Create a composition root in the lifespan that wires ports to adapters.

### Gap 3: No Explicit Ports Package (MEDIUM)

**Location**: No `src/ports/` directory exists
**Issue**: BaseDetector is the only explicit port. Config loading, audit logging, clock/ID generation have no abstract interfaces.
**Fix**: Create `src/ports/` with: `detector.py` (move BaseDetector here), `config.py` (ConfigPort ABC), `audit.py` (AuditPort ABC), `clock.py` (ClockPort ABC).

### Gap 4: Config Loading Not Behind a Port (MEDIUM)

**Location**: `src/utils/config.py`
**Issue**: `load_config()` is a free function that directly reads filesystem and environment variables. No interface for testing or swapping implementations.
**Fix**: Define ConfigPort ABC with `load() -> dict`. Current implementation becomes `YamlFileConfigAdapter`. Tests can use `InMemoryConfigAdapter`.

### Gap 5: Audit Logger Not Behind a Port (MEDIUM)

**Location**: `src/utils/audit.py`
**Issue**: `AuditLogger` directly opens files and writes. No interface for testing or alternative audit destinations (e.g., database, cloud logging).
**Fix**: Define AuditPort ABC with `log_scan(result, source_ip, extra) -> None`. Current implementation becomes `JsonlFileAuditAdapter`.

### Gap 6: Engine Directly Imports Concrete Detectors (LOW)

**Location**: `src/detectors/engine.py`, lines 12-16
**Issue**: DetectionEngine imports all 5 concrete detector classes and instantiates them in `_register_default_detectors`. This creates a hard dependency.
**Fix**: Move default detector registration to the composition root (lifespan/startup). Engine receives its detectors via constructor or registry injection.

### Gap 7: SanitiseResult Not a Domain Dataclass (LOW)

**Location**: `src/sanitizers/content_sanitizer.py`, lines 217-243
**Issue**: `SanitiseResult` is defined as a regular class alongside the sanitiser, not in the domain models package.
**Fix**: Move to `src/models/schemas.py` as a dataclass for consistency.

---

## Refactoring Strategy

### Phase 1: Determinism (Priority: Critical)
1. Create `src/ports/clock.py` with `ClockPort` ABC (`now() -> float`, `generate_id() -> str`)
2. Create `src/adapters/clock.py` with `SystemClockAdapter` (real implementation) and `FixedClockAdapter` (for tests)
3. Remove `uuid.uuid4` and `time.time` defaults from `ScanResult`
4. Inject clock into `DetectionEngine`; engine sets request_id and timestamp

### Phase 2: Port Extraction (Priority: High)
1. Create `src/ports/` package with `config.py`, `audit.py`, `clock.py`
2. Move `BaseDetector` and `DetectorRegistry` to `src/ports/detector.py`
3. Define abstract interfaces for config and audit
4. Rename current implementations as explicit adapters

### Phase 3: Dependency Injection (Priority: High)
1. Refactor `AppState` to use proper DI in FastAPI lifespan
2. Engine receives detectors, clock, and config through constructor
3. App endpoints receive engine and sanitiser through FastAPI Depends or app.state
4. Create a composition root function that wires everything

### Phase 4: Test Infrastructure (Priority: High)
1. Add HTTP-level integration tests (TestClient for FastAPI)
2. Add SDK client tests (mock server or integration)
3. Add custom detector registration tests
4. Add health/stats endpoint tests
5. Fix test imports (hardcoded path in test_attack_vectors.py line 11)

---

## Testing Strategy

### Current State
- **2 test files**: `test_attack_vectors.py` (unittest, 30 tests across 8 classes), `test_sanitiser.py` (pytest, 7 tests)
- **Coverage**: Detection engine and sanitiser tested at unit level. Zero integration/API tests.
- **Issue**: `test_attack_vectors.py` has hardcoded path (`sys.path.insert(0, "/sessions/admiring-peaceful-gauss/prompt-guard")`) that will not work in any other environment.

### Missing Coverage

| Area | Current | Needed |
|------|---------|--------|
| HTTP API integration (scan) | None | FastAPI TestClient tests for /scan with various payloads |
| HTTP API integration (sanitise) | None | FastAPI TestClient tests for /sanitise flow |
| HTTP API integration (health/stats) | None | FastAPI TestClient tests for /health and /stats |
| SDK client | None | Tests against mock/real server |
| Custom detector registration | None | Unit tests for register_detector and weight normalisation |
| Config loading | None | Unit tests for YAML loading, env overrides, missing file fallback |
| Audit logging | None | Unit tests for log_scan, file writing, clean filtering |
| CLI | None | Subprocess tests for argument parsing |
| Detector isolation | Partial (via engine) | Individual detector unit tests with crafted inputs |
| False positive corpus | Partial (7 clean tests) | Larger corpus of benign content that should not trigger |
| Edge cases | Minimal | Max-length content, Unicode edge cases, concurrent scans |

---

## Gotchas & Ambiguities

| # | Issue | Interpretation | Recommendation |
|---|-------|---------------|----------------|
| 1 | `detector_weights` in config/default.yaml is at top level, but engine reads from `config.get("detection", {})` which does not include it | Weights in config file are ignored; engine uses `_DEFAULT_WEIGHTS` hardcoded constant | Clarify: should weights come from config? If so, fix the config nesting. |
| 2 | `HealthResponse` referenced in app.py imports but not visible in schemas.py read | Likely defined elsewhere or missing | Verify: may need to be added to schemas.py |
| 3 | Rate limiting configured in YAML but not implemented in code | Dead config | Document as out-of-scope or flag for future implementation |
| 4 | `policies.on_threat` and `policies.on_error` configured but not referenced in code | Dead config | Document as out-of-scope |
| 5 | CLI entry point in pyproject.toml references `prompt_guard.cli:main` but code structure is `src/cli.py` | Package naming mismatch | Fix package layout or entry point reference |
| 6 | Dockerfile CMD uses `src.middleware.app:app` but pyproject.toml suggests package name is `prompt_guard` | Inconsistent module paths | Standardise to one package name |
| 7 | `_aggregate_scores` boost logic: `if agreeing >= 3: 1.15x` then `elif agreeing >= 4: 1.25x` -- the elif never triggers because 4 >= 3 is already caught | Bug: 4+ detector agreement uses 1.15x boost instead of 1.25x | Fix: swap order (check >= 4 first, then >= 3) |
| 8 | ScanRequest in schemas.py uses `ContentSource` enum but FastAPI ScanRequest in app.py uses Pydantic BaseModel | Two different ScanRequest classes (dataclass vs Pydantic) | The app.py endpoint receives Pydantic, then engine internally uses dataclass. Need to verify conversion. |

---

## Open Questions (Blocking)

1. **Package naming**: Is the canonical package name `prompt_guard` (pyproject.toml) or `src` (current import paths)? This affects all imports and the Dockerfile CMD.
2. **Authentication requirement**: Is this service intended to be network-internal only, or does it need API key authentication for external exposure?
3. **HealthResponse definition**: Where is `HealthResponse` defined? It is imported in app.py but was not found in the schemas.py read. Is there a missing model?

---

## BA Handoff Instructions

### For the BA Agent

1. **Read the user journeys** at `/Users/naidooone/Developer/projects/prompt-guard/.claude/artifacts/000_user_journeys_v1.md` -- these define the 6 journeys with acceptance criteria and test specs.

2. **Prioritise refactoring tasks** based on the gaps identified above:
   - **Critical**: Gap 1 (non-deterministic defaults), Gap 7 (aggregate_scores bug)
   - **High**: Gap 2 (AppState singleton), Gap 3-5 (port extraction)
   - **Medium**: Gap 6 (engine imports), test infrastructure
   - **Low**: Docker improvements, config cleanup

3. **Task breakdown suggestion**:
   - Task 1: Fix aggregate_scores boost order bug (Gap 7 in Gotchas)
   - Task 2: Fix hardcoded path in test_attack_vectors.py
   - Task 3: Create ports package (ClockPort, ConfigPort, AuditPort)
   - Task 4: Extract deterministic defaults from ScanResult
   - Task 5: Refactor AppState to proper DI
   - Task 6: Add HTTP integration tests (FastAPI TestClient)
   - Task 7: Add SDK client tests
   - Task 8: Add health/stats endpoint tests
   - Task 9: Improve Dockerfile (multi-stage, non-root user)
   - Task 10: Resolve package naming inconsistency

4. **Verify the open questions** before writing specs. The package naming question affects nearly every task.

5. **Adjacent impact warning**: Refactoring domain models (Task 3-4) will ripple through engine, app, audit, and SDK. Plan these as a coordinated set, not independent tasks.
