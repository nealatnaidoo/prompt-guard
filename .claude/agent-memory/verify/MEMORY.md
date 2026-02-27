# Verify Agent Memory - prompt-guard

## Project State (as of 2026-02-27)
- 14 tasks (T001-T014) all complete, status: done
- 309 tests passing, 83% coverage
- Deep verify result: PASS_WITH_NOTES
- 2 open BUGs (BUG-001 medium, BUG-002 low), 1 IMPROVE (IMPROVE-001 medium)

## Key Architecture
- Ports: `src/ports/` (ClockPort, ConfigPort, AuditPort)
- Adapters: `src/adapters/` (SystemClockAdapter, YamlFileConfigAdapter, JsonlFileAuditAdapter)
- Composition root: `src/middleware/app.py` lifespan function
- Test fakes: `tests/helpers/fakes.py` (FixedClockAdapter, InMemoryConfigAdapter, NullAuditAdapter)

## Known Issues
- engine.py has fallback non-deterministic path when clock=None (BUG-001)
- ScanResult has empty/zero defaults instead of no defaults (IMPROVE-001)
- cli.py and client.py have 0% coverage (deferred, out of scope)

## ID Sequence
- BUG: highest is BUG-002, next is BUG-003
- IMPROVE: highest is IMPROVE-001, next is IMPROVE-002 (but IMPROVE-002/003 have no inbox files)
