# Tasklist: Prompt Guard Retrofit

**Version**: 1
**Created**: 2026-02-26
**Spec**: `002_spec_v1.md`
**Agent**: back (all tasks are backend Python)

---

## Dependency Graph

```
Independent: T001, T002, T003, T004       <- can start immediately
After T001:  (none)
After T002:  (none)
After T003:  T005
After T004:  (none)
After T005:  T006
After T006:  T007, T008, T009
After T007:  T010
After T008:  T010
After T009:  T010
After T010:  T011, T012
After T011:  T013
After T012:  T013
After T013:  T014

Parallelism Score: 29% (4/14 independent)
```

NOTE: The low parallelism score is expected for a sequential retrofit. Tasks within
each epic are deliberately ordered to maintain the safety net: characterisation tests
first, then refactoring against those tests, then integration tests last. This is a
single-agent (back) project so cross-agent parallelism does not apply.

---

## Epic 1: Bug Fixes and Test Foundation

---

## T001: Fix BUG-003 -- Remove Hardcoded Path in test_attack_vectors.py

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: (none)
**Estimated**: 15 min

### Description

Remove the hardcoded `sys.path.insert(0, "/sessions/admiring-peaceful-gauss/prompt-guard")` on line 11 of `tests/test_attack_vectors.py`. The test should work with the project's existing package configuration. Also convert the deprecated `asyncio.get_event_loop().run_until_complete()` pattern to use `asyncio.run()` or `@pytest.mark.asyncio` if converting to pytest.

### Acceptance Criteria

- [ ] AC1: The hardcoded path `/sessions/admiring-peaceful-gauss/prompt-guard` is removed from the test file
- [ ] AC2: `pytest tests/test_attack_vectors.py -v` passes (all existing tests green)
- [ ] AC3: No hardcoded absolute paths remain in any test file

### Test Assertions

- TA1: test_ignore_previous_instructions passes without hardcoded path
- TA2: test_clean_content (all 5 subtests) passes without hardcoded path
- TA3: All 30 existing tests in test_attack_vectors.py pass

### Files to Create/Modify

- `tests/test_attack_vectors.py` (modify)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `tests/test_attack_vectors.py`
- **Expected Minor**: `tests/conftest.py` (may need fixture updates if converting to pytest)
- **Out of Scope**: `tests/test_sanitiser.py` (separate test file, already pytest)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## T002: Fix BUG-002 -- Add Missing HealthResponse to Domain Models

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: (none)
**Estimated**: 15 min

### Description

`src/middleware/app.py` imports `HealthResponse` from `src/models/schemas.py` (line 24), but this class does not exist. Define it as a dataclass in schemas.py. Based on usage in app.py lines 196-203, it needs fields: `status: str`, `detectors_loaded: int`, `uptime_seconds: float`.

### Acceptance Criteria

- [ ] AC1: `HealthResponse` dataclass exists in `src/models/schemas.py` with fields status (str), detectors_loaded (int), uptime_seconds (float)
- [ ] AC2: `from src.models.schemas import HealthResponse` succeeds without error
- [ ] AC3: The `/health` endpoint logic in app.py is compatible with the new dataclass

### Test Assertions

- TA1: test_health_response_creation -- `HealthResponse(status="ok", detectors_loaded=5, uptime_seconds=123.4)` creates valid instance
- TA2: test_health_response_import -- import from schemas succeeds

### Files to Create/Modify

- `src/models/schemas.py` (modify -- add HealthResponse dataclass)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/models/schemas.py`
- **Expected Minor**: None (app.py already has the correct import)
- **Out of Scope**: `src/middleware/app.py` (should work as-is once import resolves)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## T003: Fix BUG-001 -- Swap Aggregate Scores Boost Order

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: (none)
**Estimated**: 30 min

### Description

In `src/detectors/engine.py`, the `_aggregate_scores` method (lines 176-179) has unreachable code. The check `if agreeing_detectors >= 3` is evaluated before `elif agreeing_detectors >= 4`, meaning the 1.25x boost for 4+ detectors never fires. Swap the order so >= 4 is checked first. Write a dedicated test that proves the 1.25x boost is now reachable.

### Acceptance Criteria

- [ ] AC1: When 4+ detectors agree (score > 0.5), the base_score is multiplied by 1.25x (capped at 1.0)
- [ ] AC2: When exactly 3 detectors agree, the base_score is multiplied by 1.15x (unchanged)
- [ ] AC3: When fewer than 3 detectors agree, no boost is applied (unchanged)
- [ ] AC4: All existing tests in test_attack_vectors.py still pass (scoring thresholds still met)

### Test Assertions

- TA1: test_four_detector_boost_applies_1_25x -- craft findings from 4 detectors with scores > 0.5, verify boost factor
- TA2: test_three_detector_boost_applies_1_15x -- craft findings from 3 detectors with scores > 0.5, verify boost factor
- TA3: test_two_detector_no_boost -- craft findings from 2 detectors, verify no boost
- TA4: test_existing_attack_vectors_still_pass -- run all existing detection tests

### Files to Create/Modify

- `src/detectors/engine.py` (modify lines 176-179)
- `tests/test_engine_scoring.py` (create -- focused scoring tests)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/detectors/engine.py`, `tests/test_engine_scoring.py`
- **Expected Minor**: None
- **Out of Scope**: Detector files (scoring logic is in engine only)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## T004: Write Characterisation Tests for Sanitiser Edge Cases

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: (none)
**Estimated**: 45 min

### Description

Expand sanitiser test coverage to capture edge cases before any refactoring. The existing `test_sanitiser.py` has 7 tests but misses important scenarios from J002: minimal level only strips invisible chars (no confusables), nested code blocks, multiple pass interactions, empty content, and the `was_modified=false` path for clean content at each level.

### Acceptance Criteria

- [ ] AC1: Test that `minimal` level strips invisible chars but does NOT normalise confusables or escape AI tags
- [ ] AC2: Test that confusable normalisation works for fullwidth ASCII characters (not just Cyrillic)
- [ ] AC3: Test that multiple sanitisation passes compose correctly (content with both invisible chars AND AI tags)
- [ ] AC4: Test that empty string input returns unchanged with was_modified=false
- [ ] AC5: Test that `SanitiseResult.to_dict()` returns correct structure

### Test Assertions

- TA1: test_minimal_does_not_normalise_confusables
- TA2: test_minimal_does_not_escape_ai_tags
- TA3: test_fullwidth_ascii_normalised
- TA4: test_combined_invisible_and_ai_tags
- TA5: test_empty_content_unchanged
- TA6: test_sanitise_result_to_dict

### Files to Create/Modify

- `tests/test_sanitiser.py` (modify -- add new test cases)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `tests/test_sanitiser.py`
- **Expected Minor**: `tests/conftest.py` (may reuse sanitiser fixture)
- **Out of Scope**: `src/sanitizers/content_sanitizer.py` (read only for this task)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## T005: Write Characterisation Tests for DetectionEngine

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T003 (scoring bug must be fixed first to capture correct behaviour)
**Estimated**: 60 min

### Description

Write characterisation tests that capture the full DetectionEngine behaviour as-is, creating a safety net for the upcoming hexagonal refactoring. These tests should cover: score aggregation with known inputs, threat classification at each boundary, policy action mapping, pre-checks (oversized content, empty content), detector selection filtering, policy override, and the summary generation format.

### Acceptance Criteria

- [ ] AC1: Tests verify score aggregation with fixed detector findings (known inputs -> known output)
- [ ] AC2: Tests verify threat classification at each boundary (0.19, 0.20, 0.39, 0.40, 0.64, 0.65, 0.84, 0.85)
- [ ] AC3: Tests verify policy action mapping for each ThreatLevel
- [ ] AC4: Tests verify oversized content pre-check (500K+ chars)
- [ ] AC5: Tests verify empty content pre-check
- [ ] AC6: Tests verify detector selection via `request.detectors` field
- [ ] AC7: Tests verify policy_override bypasses normal action mapping
- [ ] AC8: Tests verify summary generation format

### Test Assertions

- TA1: test_score_aggregation_weighted_combination
- TA2: test_score_aggregation_multi_detector_boost_3
- TA3: test_score_aggregation_multi_detector_boost_4
- TA4: test_score_aggregation_critical_finding_floor
- TA5: test_classify_clean_below_020
- TA6: test_classify_low_020_to_039
- TA7: test_classify_medium_040_to_064
- TA8: test_classify_high_065_to_084
- TA9: test_classify_critical_above_085
- TA10: test_classify_critical_category_override
- TA11: test_action_mapping_all_levels
- TA12: test_oversized_content_rejected
- TA13: test_empty_content_clean
- TA14: test_detector_selection_filtering
- TA15: test_policy_override
- TA16: test_summary_format

### Files to Create/Modify

- `tests/test_engine_characterisation.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `tests/test_engine_characterisation.py`
- **Expected Minor**: `tests/conftest.py` (add engine fixture if needed)
- **Out of Scope**: `src/detectors/engine.py` (read only -- characterising, not changing)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## Epic 2: Hexagonal Port Extraction

---

## T006: Create Port Interfaces (ClockPort, ConfigPort, AuditPort)

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T005 (characterisation tests must exist before refactoring)
**Estimated**: 30 min

### Description

Create the `src/ports/` package with three ABC port interfaces. These are pure abstractions with no implementation. Also create test stubs (FixedClockAdapter, InMemoryConfigAdapter, NullAuditAdapter) in a test helpers module for use in subsequent tasks.

**ClockPort**: `now() -> float`, `generate_id() -> str`
**ConfigPort**: `load() -> dict[str, Any]`
**AuditPort**: `log_scan(result: ScanResult, source_ip: str | None = None, extra: dict[str, Any] | None = None) -> None`

### Acceptance Criteria

- [ ] AC1: `src/ports/__init__.py` exists and exports ClockPort, ConfigPort, AuditPort
- [ ] AC2: Each port is an ABC with `@abstractmethod` decorators on all methods
- [ ] AC3: `tests/helpers/fakes.py` contains FixedClockAdapter, InMemoryConfigAdapter, NullAuditAdapter
- [ ] AC4: All fake adapters implement their respective ports and pass type checking
- [ ] AC5: Existing tests still pass (no existing code modified)

### Test Assertions

- TA1: test_fixed_clock_returns_configured_values
- TA2: test_in_memory_config_returns_configured_dict
- TA3: test_null_audit_does_not_raise

### Files to Create/Modify

- `src/ports/__init__.py` (create)
- `src/ports/clock.py` (create)
- `src/ports/config.py` (create)
- `src/ports/audit.py` (create)
- `tests/helpers/__init__.py` (create)
- `tests/helpers/fakes.py` (create)
- `tests/test_ports.py` (create -- port contract tests)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: All files in `src/ports/` and `tests/helpers/`
- **Expected Minor**: None
- **Out of Scope**: `src/detectors/engine.py`, `src/middleware/app.py` (separate tasks)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## T007: Create Driven Adapter Implementations

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T006 (ports must exist first)
**Estimated**: 45 min

### Description

Create `src/adapters/` package with concrete implementations of the three ports:

- `SystemClockAdapter` (implements ClockPort) -- uses `time.time()` and `uuid.uuid4().hex[:16]`
- `YamlFileConfigAdapter` (implements ConfigPort) -- wraps existing `load_config()` logic from `src/utils/config.py`
- `JsonlFileAuditAdapter` (implements AuditPort) -- wraps existing `AuditLogger` logic from `src/utils/audit.py`

These adapters contain the non-deterministic and I/O code that was previously in the domain.

### Acceptance Criteria

- [ ] AC1: `SystemClockAdapter.now()` returns a float (current time)
- [ ] AC2: `SystemClockAdapter.generate_id()` returns a 16-char hex string
- [ ] AC3: `YamlFileConfigAdapter.load()` returns config dict (same as existing `load_config()`)
- [ ] AC4: `JsonlFileAuditAdapter.log_scan()` writes JSONL to file (same as existing AuditLogger)
- [ ] AC5: All adapters implement their respective port ABCs (isinstance check passes)
- [ ] AC6: Existing tests still pass

### Test Assertions

- TA1: test_system_clock_now_returns_float
- TA2: test_system_clock_generate_id_format
- TA3: test_yaml_config_loads_default
- TA4: test_jsonl_audit_writes_file (using tmp_path)

### Files to Create/Modify

- `src/adapters/__init__.py` (create)
- `src/adapters/clock.py` (create)
- `src/adapters/config.py` (create)
- `src/adapters/audit.py` (create)
- `tests/test_adapters.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: All files in `src/adapters/`
- **Expected Minor**: None
- **Out of Scope**: `src/utils/config.py`, `src/utils/audit.py` (retained for backward compat)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## T008: Make ScanResult Deterministic (Inject Clock)

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T006 (ClockPort must exist)
**Estimated**: 30 min

### Description

Remove the non-deterministic `default_factory` values from `ScanResult` in `src/models/schemas.py`. The `request_id` and `timestamp` fields should have no defaults -- they must be provided explicitly by the caller (the engine, which will use ClockPort). This is the critical determinism fix (GAP-1).

Also move `SanitiseResult` from `src/sanitizers/content_sanitizer.py` to `src/models/schemas.py` as a dataclass (GAP-7).

### Acceptance Criteria

- [ ] AC1: `ScanResult.request_id` has no default_factory (must be provided)
- [ ] AC2: `ScanResult.timestamp` has no default_factory (must be provided)
- [ ] AC3: `import uuid` and `import time` are removed from `src/models/schemas.py`
- [ ] AC4: `SanitiseResult` is a `@dataclass` in `src/models/schemas.py`
- [ ] AC5: `src/sanitizers/content_sanitizer.py` imports `SanitiseResult` from schemas
- [ ] AC6: Characterisation tests in T005 still pass (engine must now provide request_id and timestamp)

### Test Assertions

- TA1: test_scan_result_requires_request_id -- `ScanResult()` without request_id raises TypeError
- TA2: test_scan_result_requires_timestamp -- `ScanResult()` without timestamp raises TypeError
- TA3: test_sanitise_result_is_dataclass
- TA4: test_schemas_no_uuid_import -- verify `uuid` not imported in schemas.py
- TA5: test_schemas_no_time_import -- verify `time` not imported in schemas.py

### Files to Create/Modify

- `src/models/schemas.py` (modify -- remove defaults, add SanitiseResult)
- `src/sanitizers/content_sanitizer.py` (modify -- import SanitiseResult from schemas)
- `tests/test_determinism.py` (create -- determinism verification tests)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/models/schemas.py`, `src/sanitizers/content_sanitizer.py`
- **Expected Minor**: `tests/test_engine_characterisation.py` (may need to provide request_id/timestamp)
- **Out of Scope**: `src/detectors/engine.py` (separate task T009)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## T009: Refactor DetectionEngine to Use Dependency Injection

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T006 (ports must exist), T008 (ScanResult must be deterministic)
**Estimated**: 60 min

### Description

Refactor `DetectionEngine` to accept injected dependencies instead of hardcoding them:

1. Constructor accepts `ClockPort` (for request_id and timestamp generation)
2. Constructor accepts optional `DetectorRegistry` (pre-populated with detectors)
3. Remove `_register_default_detectors()` method -- detector registration moves to composition root
4. Remove concrete detector imports from engine.py
5. Engine uses `clock.now()` and `clock.generate_id()` when creating ScanResult

This addresses GAP-6 (engine imports concrete detectors) and completes GAP-1 (determinism).

### Acceptance Criteria

- [ ] AC1: `DetectionEngine.__init__` accepts `clock: ClockPort` parameter
- [ ] AC2: `DetectionEngine.__init__` accepts optional `registry: DetectorRegistry` parameter
- [ ] AC3: Engine no longer imports PatternDetector, HeuristicDetector, SemanticDetector, EntropyDetector, ProvenanceDetector
- [ ] AC4: Engine uses `self.clock.generate_id()` for ScanResult.request_id
- [ ] AC5: Engine uses `self.clock.now()` for ScanResult.timestamp
- [ ] AC6: All characterisation tests pass when engine is constructed with FixedClockAdapter and manually-registered detectors
- [ ] AC7: All existing attack vector tests pass with updated engine construction

### Test Assertions

- TA1: test_engine_uses_injected_clock_for_id
- TA2: test_engine_uses_injected_clock_for_timestamp
- TA3: test_engine_works_with_injected_registry
- TA4: test_engine_no_concrete_detector_imports (inspect module imports)
- TA5: test_all_characterisation_tests_pass
- TA6: test_all_attack_vector_tests_pass

### Files to Create/Modify

- `src/detectors/engine.py` (modify -- accept clock and registry, remove concrete imports)
- `tests/test_engine_characterisation.py` (modify -- use FixedClockAdapter)
- `tests/test_engine_scoring.py` (modify -- use FixedClockAdapter)
- `tests/conftest.py` (modify -- add engine factory fixture with DI)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/detectors/engine.py`, test files
- **Expected Minor**: `tests/test_attack_vectors.py` (engine construction may need updating)
- **Out of Scope**: `src/middleware/app.py` (separate task T010)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## T010: Refactor AppState to Composition Root with DI

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T007 (adapters), T008 (deterministic models), T009 (DI engine)
**Estimated**: 60 min

### Description

Refactor the module-level `AppState` singleton in `src/middleware/app.py` to use proper dependency injection. The lifespan function becomes the composition root that:

1. Creates `YamlFileConfigAdapter` and loads config via ConfigPort
2. Creates `SystemClockAdapter`
3. Creates `JsonlFileAuditAdapter`
4. Creates and populates `DetectorRegistry` with 5 default detectors
5. Creates `DetectionEngine` with injected clock, registry, and config
6. Creates `ContentSanitiser`
7. Stores all components in `app.state` (FastAPI's built-in state)

Remove the module-level `state = AppState()` singleton. Endpoints access dependencies via `request.app.state`.

### Acceptance Criteria

- [ ] AC1: No module-level `state = AppState()` exists in app.py
- [ ] AC2: Lifespan creates all dependencies and stores in `app.state`
- [ ] AC3: Each endpoint accesses engine/sanitiser/audit via `request.app.state`
- [ ] AC4: `app.state.clock` is a ClockPort instance
- [ ] AC5: `app.state.audit` is an AuditPort instance
- [ ] AC6: All 4 endpoints (/scan, /sanitise, /health, /stats) still function correctly
- [ ] AC7: Existing attack vector tests work (may need updated engine construction in conftest)

### Test Assertions

- TA1: test_app_lifespan_creates_all_dependencies
- TA2: test_scan_endpoint_uses_app_state
- TA3: test_sanitise_endpoint_uses_app_state
- TA4: test_health_endpoint_returns_ok
- TA5: test_stats_endpoint_returns_zeros_on_start

### Files to Create/Modify

- `src/middleware/app.py` (modify -- replace AppState singleton with composition root)
- `tests/conftest.py` (modify -- add FastAPI TestClient fixture with test dependencies)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/middleware/app.py`, `tests/conftest.py`
- **Expected Minor**: `tests/test_attack_vectors.py` (engine fixture may change)
- **Out of Scope**: `src/detectors/engine.py` (already refactored in T009)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## T011: Update Existing Test Suite for Refactored Architecture

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T010 (composition root must be in place)
**Estimated**: 45 min

### Description

Update all existing tests to work with the refactored architecture. The main changes:
1. `tests/conftest.py` -- provide engine fixtures that use DI (FixedClockAdapter + manually registered detectors)
2. `tests/test_attack_vectors.py` -- use pytest fixtures instead of manual setUp, use the DI engine
3. `tests/test_sanitiser.py` -- update import path for SanitiseResult if needed
4. Ensure all 37+ existing tests pass with the refactored code

### Acceptance Criteria

- [ ] AC1: `pytest tests/test_attack_vectors.py -v` -- all tests pass
- [ ] AC2: `pytest tests/test_sanitiser.py -v` -- all tests pass
- [ ] AC3: `pytest tests/test_engine_characterisation.py -v` -- all tests pass
- [ ] AC4: `pytest tests/test_engine_scoring.py -v` -- all tests pass
- [ ] AC5: `pytest tests/ -v` -- full suite green
- [ ] AC6: conftest.py provides reusable fixtures for DI-wired engine

### Test Assertions

- TA1: All 30 tests in test_attack_vectors.py pass
- TA2: All 7 tests in test_sanitiser.py pass
- TA3: All characterisation tests pass
- TA4: All scoring tests pass

### Files to Create/Modify

- `tests/conftest.py` (modify)
- `tests/test_attack_vectors.py` (modify -- use fixtures)
- `tests/test_sanitiser.py` (modify if import paths changed)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: All test files
- **Expected Minor**: None
- **Out of Scope**: Source files (no production code changes in this task)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## T012: Update conftest.py Import Paths for test_sanitiser.py

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T010 (full DI in place)
**Estimated**: 15 min

### Description

The existing `tests/test_sanitiser.py` imports from `prompt_guard.src.sanitizers.content_sanitizer` and `tests/conftest.py` imports from `prompt_guard.src.detectors.engine` and `prompt_guard.src.sanitizers.content_sanitizer`. These import paths use `prompt_guard.src.*` which assumes a specific package layout. Verify and fix import paths so that `pytest tests/ -v` works from the project root with the current `pyproject.toml` configuration.

NOTE: This task may be absorbed into T011 if the import path fixes are trivial. The coding agent should assess and merge if appropriate.

### Acceptance Criteria

- [ ] AC1: `pytest tests/test_sanitiser.py -v` passes from project root
- [ ] AC2: `pytest tests/conftest.py --collect-only` shows no import errors
- [ ] AC3: Import paths are consistent across all test files

### Test Assertions

- TA1: All tests in test_sanitiser.py pass
- TA2: conftest.py imports resolve correctly

### Files to Create/Modify

- `tests/test_sanitiser.py` (modify if needed)
- `tests/conftest.py` (modify if needed)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `tests/test_sanitiser.py`, `tests/conftest.py`
- **Expected Minor**: None
- **Out of Scope**: Production code

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## Epic 3: Integration Tests

---

## T013: Add HTTP API Integration Tests (Scan + Sanitise)

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T011, T012 (all refactoring complete and tests green)
**Estimated**: 90 min

### Description

Add integration tests using FastAPI's `TestClient` (or `httpx.AsyncClient` with `ASGITransport`) that test the /scan and /sanitise endpoints through the HTTP layer. These tests verify the full request/response cycle including Pydantic validation, endpoint routing, scan pipeline execution, and response serialization.

The test app should be constructed with test dependencies (FixedClockAdapter, InMemoryConfigAdapter, NullAuditAdapter) for deterministic output.

### Acceptance Criteria

- [ ] AC1: Test POST /scan with valid injection payload returns 200 with threat_level HIGH or CRITICAL
- [ ] AC2: Test POST /scan with clean content returns 200 with threat_level CLEAN or LOW
- [ ] AC3: Test POST /scan with empty content returns 200 with threat_level CLEAN and summary "Empty content"
- [ ] AC4: Test POST /scan with oversized content returns 200 with threat_level HIGH and action REJECT
- [ ] AC5: Test POST /scan with invalid body returns 422
- [ ] AC6: Test POST /scan with detector selection returns findings only from selected detectors
- [ ] AC7: Test POST /scan with policy_override returns overridden action
- [ ] AC8: Test POST /sanitise with AI tags returns sanitised_content without raw tags
- [ ] AC9: Test POST /sanitise with high-threat content escalates to strict level
- [ ] AC10: Test POST /sanitise with clean content returns was_modified=false

### Test Assertions

- TA1: test_scan_injection_detected
- TA2: test_scan_clean_content
- TA3: test_scan_empty_content
- TA4: test_scan_oversized_content
- TA5: test_scan_invalid_body_422
- TA6: test_scan_detector_selection
- TA7: test_scan_policy_override
- TA8: test_sanitise_escapes_ai_tags
- TA9: test_sanitise_threat_escalation
- TA10: test_sanitise_clean_content

### Files to Create/Modify

- `tests/test_api_integration.py` (create)
- `tests/conftest.py` (modify -- add TestClient fixture with DI wiring)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `tests/test_api_integration.py`, `tests/conftest.py`
- **Expected Minor**: None
- **Out of Scope**: Production code (testing only)

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`

---

## T014: Add Health and Stats Endpoint Tests

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T013 (TestClient fixture must exist)
**Estimated**: 30 min

### Description

Add integration tests for the /health and /stats endpoints. These verify J005 acceptance criteria: health returns status="ok" with detector count and uptime, stats returns zero counters on fresh start and correct counters after scans.

### Acceptance Criteria

- [ ] AC1: GET /health returns 200 with status="ok", detectors_loaded=5, uptime_seconds > 0
- [ ] AC2: GET /stats on fresh app returns total_scans=0, threat_rate=0.0, avg_latency_ms=0.0
- [ ] AC3: GET /stats after one scan returns total_scans=1
- [ ] AC4: GET /stats after a threat scan returns threats_detected=1

### Test Assertions

- TA1: test_health_returns_ok
- TA2: test_health_detectors_count
- TA3: test_stats_fresh_start_zeros
- TA4: test_stats_after_scan_increments
- TA5: test_stats_after_threat_increments_threats

### Files to Create/Modify

- `tests/test_api_health_stats.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `tests/test_api_health_stats.py`
- **Expected Minor**: `tests/conftest.py` (reuse TestClient fixture)
- **Out of Scope**: Production code

### Pattern Compliance

- **Backend**: hexagonal (components/), pattern: `backend-hexagonal`
