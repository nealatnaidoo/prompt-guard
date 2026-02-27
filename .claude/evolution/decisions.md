# Decision Log

Append-only architectural decisions with rationale.

---

## 2026-02-26 — Retrofit to Hexagonal Architecture

**Context**: Existing codebase is well-structured but lacks explicit hexagonal ports/adapters separation. Domain model contains non-deterministic defaults (`uuid.uuid4()`, `time.time()`).

**Decision**: Refactor to explicit ports/adapters, with deterministic dependency injection for clock and ID generation.

**Rationale**:
- Enables testability via fake implementations
- Supports Prime Directive determinism requirement
- Aligns with CAF governance model
- Low-risk refactoring given existing clean structure

**Status**: Pending design phase (Phase A) and BA phase specification

---
