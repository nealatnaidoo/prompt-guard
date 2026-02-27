# Prompt Guard — Project Instructions

**Version**: 1.0
**Project**: prompt-guard (Adversarial-grade prompt injection, sanitisation & poisoning protection middleware)
**Tech Stack**: Python 3.10+, FastAPI, Uvicorn, Pydantic, scikit-learn, numpy, structlog
**Last Updated**: 2026-02-26

## Overview

Prompt Guard is a hardened middleware designed to detect and mitigate prompt injection attacks, sanitise adversarial content, and provide forensic audit trails. It exposes three primary surfaces:

1. **HTTP API** (FastAPI) — `/scan`, `/sanitise`, `/health`, `/stats` endpoints
2. **Python SDK** — Synchronous and asynchronous client for integration
3. **CLI** — Command-line interface for batch processing and configuration

---

## Architecture

### Hexagonal Architecture (Target)

The codebase has a **layered structure approaching hexagonal**, with the following mapping:

```
┌─────────────────────────────────────────────────────────┐
│  DRIVING ADAPTERS (Input)                              │
│  ├── middleware/app.py          (FastAPI HTTP server)   │
│  ├── client.py                  (Python SDK client)      │
│  └── cli.py                     (CLI interface)          │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────┴──────────────────────────────────────┐
│  APPLICATION SERVICES                                   │
│  ├── detectors/engine.py        (Detection orchestrator) │
│  └── sanitizers/                (Sanitisation service)   │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────┴──────────────────────────────────────┐
│  DOMAIN LAYER                                            │
│  ├── detectors/base.py          (BaseDetector ABC)      │
│  ├── detectors/*.py             (5 detector plugins)     │
│  └── models/schemas.py          (Pure dataclasses)      │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────┴──────────────────────────────────────┐
│  DRIVEN ADAPTERS (Output)                               │
│  ├── utils/config.py            (Configuration loading) │
│  └── utils/audit.py             (Audit logging)         │
└─────────────────────────────────────────────────────────┘
```

### Package Structure

```
src/
├── __init__.py
├── client.py                    # SDK client (driving adapter)
├── cli.py                       # CLI entry point (driving adapter)
├── middleware/
│   ├── __init__.py
│   └── app.py                   # FastAPI application + routes
├── detectors/
│   ├── __init__.py
│   ├── base.py                  # BaseDetector ABC + DetectorRegistry
│   ├── engine.py                # DetectionEngine (orchestrator)
│   ├── pattern_detector.py      # Regex-based detection
│   ├── heuristic_detector.py    # Heuristic analysis
│   ├── semantic_detector.py     # Semantic analysis (ML-based)
│   ├── entropy_detector.py      # Entropy analysis
│   └── provenance_detector.py   # Data provenance tracking
├── sanitizers/
│   ├── __init__.py
│   └── content_sanitizer.py     # Content sanitisation service
├── models/
│   ├── __init__.py
│   └── schemas.py               # Domain models (dataclasses)
└── utils/
    ├── __init__.py
    ├── config.py                # Configuration loading (driven adapter)
    └── audit.py                 # Audit logging (driven adapter)

config/
└── default.yaml                 # Default configuration

tests/
├── __init__.py
├── conftest.py                  # Pytest fixtures and configuration
├── test_sanitiser.py            # Sanitiser unit tests
└── test_attack_vectors.py       # Attack vector tests
```

### Detector Registry (Pluggable)

The `BaseDetector` ABC defines the contract for all detectors:

```python
class BaseDetector(ABC):
    """Abstract base for pluggable detectors."""

    @abstractmethod
    async def detect(self, content: str) -> DetectionResult:
        """Detect threats in content."""
```

The `DetectorRegistry` maintains a list of registered detectors, allowing runtime plugin loading.

---

## Non-Negotiable Rules

### 1. Prime Directive (All Projects)

> Every change must be **task-scoped, atomic, deterministic, hexagonal, and evidenced.**

Apply this to all work:

- **Task-scoped**: Work tied to a specific task ID (BA tasklist item)
- **Atomic**: Single coherent change (no scattered edits)
- **Deterministic**: No `uuid.uuid4()`, `datetime.now()`, or `random.choice()` in domain code
  - Use injected ports for time, ID generation, randomness
- **Hexagonal**: Changes respect ports/adapters boundary
- **Evidenced**: Every change has verification output (tests pass, coverage %, type hints)

### 2. Determinism (Python-Specific)

**BLOCKED**: Using non-deterministic functions in domain code:

```python
# ❌ FORBIDDEN in domain models/logic
import uuid, time, random
scan_id = uuid.uuid4()          # Non-deterministic
created_at = time.time()        # Non-deterministic
choice = random.choice(items)   # Non-deterministic
```

**ALLOWED**: Inject via ports:

```python
# ✅ CORRECT in domain
class ScanResult:
    def __init__(self, request_id: str, timestamp: float):
        self.request_id = request_id
        self.timestamp = timestamp

# Adapters generate IDs and timestamps
id_generator: IDPort = SystemUUIDAdapter()
clock: ClockPort = SystemClockAdapter()
result = ScanResult(
    request_id=id_generator.generate_id(),
    timestamp=clock.now()
)
```

See `~/.claude/knowledge/coding_standards.md` (Determinism section) for patterns.

### 3. Hexagonal Architecture

All code lives in one of these zones:

| Zone | Content | Rule |
|------|---------|------|
| **Domain** | Models, business logic, ABCs | No framework imports, pure Python |
| **Driving Adapter** | HTTP, CLI, SDK | Translates external input to domain calls |
| **Driven Adapter** | Config, logging, DB, external APIs | Implements domain ports |

**Rule**: Domain never imports from adapters or frameworks.

```python
# ✅ OK: domain models
from dataclasses import dataclass

@dataclass
class ScanResult:
    request_id: str
    threat_level: str

# ❌ WRONG: domain importing FastAPI
from fastapi import HTTPException
```

### 4. Testing Strategy

- **Unit tests**: Individual detectors, sanitiser, models (pure functions)
- **Integration tests**: DetectionEngine + detector registry (in-process)
- **API tests**: HTTP endpoints (`test_middleware.py` — **missing**, create via BA tasklist)
- **Target coverage**: 80% (per org.yaml)

Mutation testing (via `pytest-mutagen`) is recommended but not required.

### 5. Type Hints (Mandatory)

All public APIs must have type hints:

```python
# ✅ CORRECT
async def scan(content: str, detectors: list[str] | None = None) -> ScanResult:
    ...

# ❌ WRONG
async def scan(content, detectors=None):
    ...
```

### 6. Async/Await (FastAPI Convention)

- HTTP handlers in `middleware/app.py` use `async def`
- Detectors use `async def detect()` for I/O-bound operations
- SDK client supports both sync and async interfaces

---

## Testing

### Run Tests

```bash
# All tests with coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Specific test
pytest tests/test_sanitiser.py::test_remove_command_injection -v

# With asyncio
pytest tests/ -v --asyncio-mode=auto
```

### Test Conventions

- **Naming**: `test_{feature}.py` (e.g., `test_pattern_detector.py`)
- **Fixtures**: `conftest.py` provides common setup (config, detectors, mock data)
- **Parametrization**: Use `@pytest.mark.parametrize` for attack vector libraries
- **Async tests**: Use `@pytest.mark.asyncio` and `async def test_...`

### Coverage Requirements

- Minimum **80%** (per org.yaml `coverage_threshold`)
- All detectors **must** have test coverage
- All API endpoints **must** have integration tests

---

## Configuration

Configuration is loaded from `config/default.yaml` and can be overridden via environment variables.

### Example Config

```yaml
# config/default.yaml
detectors:
  enabled:
    - pattern
    - heuristic
    - semantic
    - entropy
    - provenance

pattern:
  max_line_length: 1000

heuristic:
  suspicious_keywords:
    - "prompt injection"
    - "jailbreak"

semantic:
  model_path: "models/semantic.pkl"

entropy:
  threshold: 4.5

audit:
  enabled: true
  log_file: "logs/audit.log"
```

### Loading Config

```python
from src.utils.config import load_config

config = load_config("config/default.yaml")
print(config.detectors.enabled)  # ['pattern', 'heuristic', ...]
```

---

## Key Commands

### Run the API Server

```bash
# Development (auto-reload)
uvicorn src.middleware.app:app --host 0.0.0.0 --port 8420 --reload

# Production
uvicorn src.middleware.app:app --host 0.0.0.0 --port 8420 --workers 4
```

### CLI

```bash
# Scan a file
prompt-guard scan --input /path/to/file.txt

# Sanitise
prompt-guard sanitise --input "malicious<script>content</script>"

# Show config
prompt-guard config show
```

### Linting & Type Checking

```bash
# Type check
mypy src/ --strict

# Lint
pylint src/

# Format
black src/ tests/
```

---

## Ports (For Future Hexagonal Refactoring)

These ports should be created as part of the retrofit:

```python
# src/domain/ports/

class DetectorPort(ABC):
    """Port for detection logic."""
    async def detect(self, content: str) -> DetectionResult: ...

class SanitiserPort(ABC):
    """Port for sanitisation logic."""
    async def sanitise(self, content: str) -> str: ...

class ConfigPort(ABC):
    """Port for configuration loading."""
    def load_config(self, path: str) -> Config: ...

class AuditPort(ABC):
    """Port for audit logging."""
    def log_scan(self, scan_id: str, result: ScanResult): ...

class ClockPort(ABC):
    """Port for time (determinism)."""
    def now(self) -> float: ...

class IDPort(ABC):
    """Port for ID generation (determinism)."""
    def generate_id(self) -> str: ...
```

Adapters will live in `src/domain/adapters/` and will be injected into domain services.

---

## Debugging

### Enable Debug Logging

```bash
# Set log level
export LOG_LEVEL=DEBUG
uvicorn src.middleware.app:app --log-level debug
```

### Inspect Detector Output

```python
from src.detectors.engine import DetectionEngine
from src.utils.config import load_config

config = load_config("config/default.yaml")
engine = DetectionEngine(config)
result = await engine.scan("malicious content")
print(result)  # Shows all detector outputs
```

---

## Project Phases (CAF Lifecycle)

**Current Phase**: `initialized`

Phases are:

1. **Plan** (design)
   - Phase A: User journeys (via `design` agent)
   - Phase B: Solution envelope (via `design` agent)

2. **Build** (ba → back)
   - BA produces spec, tasklist, rules
   - `back` agent executes tasklist

3. **Verify** (verify)
   - Quick verify per task (5-10 min, haiku)
   - Deep verify per feature (60 min, opus)

See `.claude/manifest.yaml` for current phase. Update via agent transitions only.

---

## Retrofit Status

This project is a **retrofit** — code already exists and is reasonably well-structured. Key gaps:

1. **No explicit ports/adapters** — Package structure is layered but not hexagonal
2. **Non-deterministic domain** — `ScanResult` uses `uuid.uuid4()` and `time.time()`
3. **Thin test coverage** — Only 2 test files with real tests (sanitiser, attack vectors)
4. **Missing API tests** — No endpoint tests for `/scan`, `/sanitise`, `/health`, `/stats`
5. **No CLI tests** — CLI is untested

**Next Step**: Invoke `design` agent to define user journeys (Phase A), then design agent for solution envelope (Phase B). See `.claude/migration_plan.md` for full retrofit roadmap.

---

## Key Files

| File | Purpose |
|------|---------|
| `src/middleware/app.py` | HTTP API (FastAPI routes) |
| `src/detectors/engine.py` | Detection orchestrator |
| `src/detectors/base.py` | BaseDetector ABC + registry |
| `src/models/schemas.py` | Domain models (dataclasses) |
| `src/sanitizers/content_sanitizer.py` | Sanitisation logic |
| `config/default.yaml` | Default configuration |
| `tests/conftest.py` | Pytest fixtures |
| `.claude/manifest.yaml` | CAF governance checkpoint |

---

## References

- **Global instructions**: `~/.claude/CLAUDE.md` (Agent routing, lifecycle, exclusive permissions)
- **Coding standards**: `~/.claude/knowledge/coding_standards.md` (Determinism, type hints, testing)
- **Hexagonal guide**: `~/.claude/docs/agent_operating_model.md` (Architecture patterns)
- **Governance**: `~/.claude/docs/agent_governance.md` (Phase transitions, BA workflows)
- **Retrofit plan**: `./.claude/migration_plan.md` (Step-by-step retrofit roadmap)

---

## Getting Help

| Question | Consult |
|----------|---------|
| "What should I work on next?" | `.claude/manifest.yaml` → `outstanding.tasks` |
| "What's broken?" | `.claude/remediation/remediation_tasks.md` |
| "What decisions have we made?" | `.claude/evolution/decisions.md` |
| "How do ports work?" | `~/.claude/knowledge/coding_standards.md` (Determinism section) |
| "What's the full retrofit plan?" | `./.claude/migration_plan.md` |

---

**Maintainer**: CAF Governance Framework
**Last Sync**: 2026-02-26
