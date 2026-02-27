# prompt-guard -- Solution Envelope

## Metadata
- **Project Slug**: prompt-guard
- **Version**: v2
- **Created**: 2026-02-27
- **Status**: ready_for_ba
- **Type**: Production deployment feature (builds on v1 retrofit)
- **Supersedes**: 001_solution_envelope_v1.md

---

## Problem Statement

Prompt Guard is a fully hexagonal, well-tested adversarial prompt injection detection and content sanitisation service. It currently runs only locally. The business needs it available as an **internal network service** so that AI models and agent pipelines across the portfolio can call it over the network. This envelope defines the middleware, configuration, and CI/CD changes required to deploy prompt-guard to Fly.io as a private, authenticated, auto-scaling service with near-zero idle cost.

---

## Constraints & Inputs

- **Language**: Python 3.12 (existing)
- **Framework**: FastAPI + Uvicorn (existing)
- **Platform**: Fly.io (portfolio standard -- 4/4 projects use it)
- **Region**: jnb (Johannesburg -- portfolio standard)
- **VM**: shared-cpu-1x / 256MB (sufficient for stateless middleware)
- **CI/CD**: GitHub Actions (portfolio standard)
- **Networking**: Fly.io private networking (.flycast WireGuard mesh)
- **Cost Target**: $0 idle, $2-4/mo active
- **Test Coverage**: Must maintain 100% (currently 100% at 402 tests)
- **Architecture**: Must maintain hexagonal -- all new middleware goes in adapters layer
- **No Database**: Stateless service; in-memory stats per machine
- **No Breaking Changes**: Existing unversioned endpoints must continue working

---

## Personas & Roles

From Phase A journeys (v2):

| Persona | Role | Primary Journeys |
|---------|------|------------------|
| Kira Chen | AI Platform Developer -- integrates via SDK and HTTP API | J001-J003, J007, J008 |
| Max Okonkwo | Platform Operator -- deploys, monitors, maintains | J009-J013 |
| Agent Pipeline | Automated AI consumer -- calls /v1/scan programmatically | J007 |

---

## In Scope / Out of Scope

### In Scope

1. **API key authentication middleware** (bearer token, env var, constant-time compare)
2. **Rate limiting middleware** (token bucket, 120 req/min, burst 20, in-memory)
3. **Request ID middleware** (generate/propagate X-Request-ID)
4. **Security headers middleware** (X-Content-Type-Options, X-Frame-Options, CSP)
5. **Request logging middleware** (structured JSON, per-request)
6. **API versioning** (/v1/ prefix; backward-compatible unversioned routes)
7. **CORS lockdown** (remove wildcard, restrict or disable)
8. **SDK update** (api_key parameter, /v1/ prefix auto-selection)
9. **Dockerfile hardening** (non-root user, HEALTHCHECK, .dockerignore, layer optimization)
10. **fly.toml configuration** (internal_port, auto_stop, region, health checks)
11. **GitHub Actions CI workflow** (ruff, mypy, pytest, coverage)
12. **GitHub Actions deploy workflow** (quality gates, fly deploy, smoke test)

### Out of Scope

- Multi-tenant API key support (single key is sufficient for internal service)
- API key storage in database (single env var is sufficient)
- Horizontal auto-scaling beyond Fly.io auto-stop/start
- Custom domain or TLS certificate management (Fly.io handles this)
- Log aggregation service (Fly.io's built-in log tailing is sufficient)
- Metrics export (Prometheus/Grafana) -- future enhancement
- Webhook/callback notifications on threat detection
- Admin UI or dashboard
- Blue/green deployment strategy (Fly.io rolling deploys are sufficient)
- Rate limiting per API key (single key, single rate limit)

---

## Core User Flows

### F7: Authenticated Scan (J007)

```
Agent -> POST /v1/scan + Authorization: Bearer <key>
  -> Request ID middleware: extract or generate X-Request-ID
  -> Security headers middleware: add security headers
  -> Request logging middleware: log request start
  -> API key auth middleware: validate bearer token
    -> Missing/invalid: 401 Unauthorized
  -> Rate limit middleware: check token bucket
    -> Over limit: 429 Too Many Requests + Retry-After
  -> FastAPI route -> scan_content() (existing J001 logic)
  -> Request logging middleware: log response (status, latency, threat_level)
  -> Return ScanResult + X-Request-ID header
```

### F8: SDK Authenticated Scan (J008)

```
Developer -> PromptGuardClient(base_url, api_key="sk-...")
  -> httpx.AsyncClient configured with:
     - base_url = base_url
     - headers = {"Authorization": "Bearer sk-..."}
  -> client.scan(content)
     -> POST /v1/scan (v1 prefix when api_key is set)
     -> Response -> ScanResponse wrapper (same as J003)
```

### F9: First Deployment (J009)

```
Operator -> fly apps create prompt-guard
  -> fly secrets set PROMPT_GUARD_API_KEY=<key>
  -> fly deploy
     -> Docker build (hardened Dockerfile)
     -> Deploy to jnb / shared-cpu-1x / 256MB
     -> Health check: GET /v1/health (unauthenticated)
     -> Machine marked healthy
  -> Service available at prompt-guard.flycast (private)
  -> Auto-stop when idle (0 cost)
  -> Auto-start on first request (~5s cold start)
```

### F10: CI/CD Pipeline (J010)

```
Developer -> push to branch
  -> GitHub Actions CI:
     1. Setup Python 3.12
     2. Install dependencies (cached)
     3. ruff check src/ tests/
     4. mypy src/
     5. pytest --cov --cov-report=term-missing
     6. Coverage >= 100% assertion
  -> PR merge to main
  -> GitHub Actions Deploy:
     1. Run CI gates (same as above)
     2. fly deploy --ha=false
     3. Smoke test: GET /v1/health -> 200
```

---

## Key Domain Objects

No new domain objects. All new components are **adapters** (middleware). Existing domain objects from v1 are unchanged:

| Object | Location | Change |
|--------|----------|--------|
| ScanRequest | src/models/schemas.py | No change |
| ScanResult | src/models/schemas.py | No change (request_id already exists) |
| PromptGuardClient | src/client.py | Add api_key parameter, /v1/ prefix logic |

---

## Policy & Rules Candidates

| Rule | Implementation | Location |
|------|---------------|----------|
| API key required for /v1/* (except /v1/health) | Auth middleware checks Authorization header | New: src/middleware/auth.py |
| Health endpoint unauthenticated | Auth middleware skips /v1/health and /health | New: src/middleware/auth.py |
| Rate limit: 120 req/min, burst 20 | Token bucket algorithm per source IP | New: src/middleware/rate_limit.py |
| Request ID propagation | X-Request-ID header extracted or generated | New: src/middleware/request_id.py |
| Security headers on all responses | Middleware adds standard security headers | New: src/middleware/security_headers.py |
| CORS disabled (internal service) | Remove CORSMiddleware or restrict to empty origin list | Modified: src/middleware/app.py |
| API key from env var only | PROMPT_GUARD_API_KEY environment variable; no config file fallback | New: src/middleware/auth.py |
| Non-root container | Dockerfile creates app user with UID 1000 | Modified: Dockerfile |
| Auto-stop idle machines | fly.toml: auto_stop_machines = "stop" | New: fly.toml |

---

## Architecture Proposal

### New Components (All Adapters)

All new components are **driving adapters** (middleware) or **configuration files**. No domain logic changes.

```
                    ┌─────────────────────────────────────────┐
                    │       NEW MIDDLEWARE STACK (Adapters)     │
                    │                                          │
                    │  request_id.py    -> Generate/propagate  │
                    │  security_headers.py -> Add sec headers  │
                    │  request_logging.py -> Log req/resp      │
                    │  auth.py          -> API key validation  │
                    │  rate_limit.py    -> Token bucket         │
                    └──────────────┬───────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────┐
                    │       EXISTING APP (No Changes to Core)   │
                    │                                          │
                    │  /v1/scan, /v1/sanitise (new routes)     │
                    │  /scan, /sanitise (backward compat)       │
                    │  /v1/health, /v1/stats (new routes)      │
                    │  /health, /stats (backward compat)        │
                    └──────────────┬───────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────┐
                    │   EXISTING DOMAIN (Unchanged)             │
                    │                                          │
                    │  DetectionEngine, ContentSanitiser        │
                    │  5 Detectors, Domain Models               │
                    │  Ports, Adapters (clock, config, audit)   │
                    └──────────────────────────────────────────┘
```

### Components

New (all adapters -- middleware layer):
- **C15: Auth Middleware** (`src/middleware/auth.py`) - Bearer token validation, constant-time compare, env var key source, health endpoint exemption
- **C16: Rate Limit Middleware** (`src/middleware/rate_limit.py`) - Token bucket algorithm, 120 req/min, burst 20, Retry-After header, in-memory state
- **C17: Request ID Middleware** (`src/middleware/request_id.py`) - Extract X-Request-ID from request or generate UUID, set on response, inject into request state
- **C18: Security Headers Middleware** (`src/middleware/security_headers.py`) - X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, referrer-policy
- **C19: Request Logging Middleware** (`src/middleware/request_logging.py`) - Structured JSON log per request with method, path, status, latency, request_id

Modified:
- **C10: HTTP Adapter** (`src/middleware/app.py`) - Add /v1/ prefixed routes; register new middleware; remove CORS wildcard; mount middleware in correct order
- **C11: SDK Adapter** (`src/client.py`) - Add api_key constructor param; auto-prefix /v1/ when api_key is set; add Authorization header to httpx client

New (infrastructure):
- **C20: fly.toml** - Fly.io app configuration
- **C21: Dockerfile** (hardened) - Non-root user, HEALTHCHECK, .dockerignore, layer optimization
- **C22: CI Workflow** (`.github/workflows/ci.yml`) - Lint, type-check, test, coverage
- **C23: Deploy Workflow** (`.github/workflows/deploy.yml`) - Quality gates + fly deploy + smoke test
- **C24: .dockerignore** - Exclude tests, .git, .claude, docs from image

### Ports

No new ports needed. All middleware is in the driving adapter layer and does not touch domain logic.

### Middleware Ordering (Critical)

FastAPI middleware executes in **reverse registration order** (last registered = first to execute). Registration order in app.py must be:

```python
# Registered LAST = executes FIRST
app.add_middleware(RequestLoggingMiddleware)   # 5. Log request/response (outermost)
app.add_middleware(SecurityHeadersMiddleware)  # 4. Add security headers
app.add_middleware(RequestIDMiddleware)        # 3. Generate/propagate request ID
app.add_middleware(RateLimitMiddleware, ...)   # 2. Check rate limits
app.add_middleware(AuthMiddleware, ...)        # 1. Validate API key (innermost before route)
```

Execution order for incoming request:
1. RequestLoggingMiddleware (log start)
2. SecurityHeadersMiddleware (will add headers to response)
3. RequestIDMiddleware (generate/extract request ID)
4. RateLimitMiddleware (check rate limit; 429 if exceeded)
5. AuthMiddleware (validate API key; 401 if invalid)
6. Route handler (scan/sanitise/health/stats)

Response flows back through middleware in reverse.

---

## Adjacent Impact Zones

| Component | Primary Scope | Adjacent Zones | Rationale | Boundary |
|-----------|---------------|----------------|-----------|----------|
| C10: app.py | Route registration, middleware setup, CORS removal | C15-C19 (all new middleware) | App.py is the composition root; it registers middleware and routes | include_in_scope |
| C11: client.py | api_key param, /v1/ prefix | Tests that use PromptGuardClient | Constructor signature changes | include_in_scope |
| C21: Dockerfile | Non-root user, HEALTHCHECK | docker-compose.yml (if exists), CI workflows | Dockerfile changes affect build pipeline | include_in_scope |
| C15: Auth middleware | Auth logic | All /v1/ endpoints | Auth is cross-cutting but only touches request headers | include_in_scope |
| C1-C9: Domain + Detectors | NOT in scope | None | No domain changes required | document_only |
| Existing tests | Test updates for /v1/ routes and auth | All integration tests | Tests may need api_key in requests | separate_task |

---

## Security & Privacy

### New Controls

| Control | Implementation | Component |
|---------|---------------|-----------|
| API key authentication | Bearer token in Authorization header; PROMPT_GUARD_API_KEY env var; hmac.compare_digest | C15: auth.py |
| Rate limiting | Token bucket: 120 req/min, burst 20; per source IP; 429 + Retry-After | C16: rate_limit.py |
| Security headers | X-Content-Type-Options: nosniff, X-Frame-Options: DENY, CSP: default-src 'none' | C18: security_headers.py |
| CORS lockdown | Remove wildcard allow_origins; internal service needs no CORS | C10: app.py |
| Non-root container | Dockerfile creates UID 1000 user; CMD runs as that user | C21: Dockerfile |
| Request ID tracing | X-Request-ID propagated for forensic correlation | C17: request_id.py |
| Health endpoint unauthenticated | /v1/health and /health exempt from auth for LB probes | C15: auth.py |
| Secret management | API key via Fly.io encrypted secrets (fly secrets set) | Fly.io platform |

### Threats / Controls

| Threat | Risk | Mitigation |
|--------|------|------------|
| API key brute force | Low (constant-time compare prevents timing attacks) | Rate limiting + constant-time comparison |
| API key leakage in logs | Medium | Auth middleware MUST NOT log the API key; log "authenticated: true/false" only |
| DDoS via unauthenticated health endpoint | Low | Health endpoint is lightweight; rate limiting still applies |
| Container escape via root user | Medium | Non-root user in Dockerfile |
| Man-in-the-middle on public endpoint | Low | Fly.io enforces HTTPS (force_https=true in fly.toml) |
| Rate limit bypass via IP spoofing | Low | Fly.io proxy provides real client IP via Fly-Client-IP header |
| Cold start timing attack | Very low | Auto-start latency is consistent regardless of request content |

### Security Invariants

1. API key MUST be read from environment variable only -- never from config file, never hardcoded
2. API key MUST be compared using constant-time comparison (hmac.compare_digest)
3. API key MUST NOT appear in any log output, error messages, or response bodies
4. Health endpoint MUST be unauthenticated (required for Fly.io health checks and LB probes)
5. If PROMPT_GUARD_API_KEY is unset or empty, ALL authenticated endpoints MUST return 401 (fail closed)
6. Rate limiter MUST use Fly-Client-IP header (if present) as source identifier, falling back to request.client.host

---

## Operational Reality

### Deployment Architecture

```
                    ┌──────────────────────────────────────┐
                    │           GitHub Actions              │
                    │                                       │
                    │  CI: ruff + mypy + pytest + coverage  │
                    │  Deploy: gates + fly deploy + smoke   │
                    └─────────────────┬────────────────────┘
                                      │ (on merge to main)
                                      ▼
                    ┌──────────────────────────────────────┐
                    │            Fly.io (jnb)               │
                    │                                       │
                    │  prompt-guard                         │
                    │  shared-cpu-1x / 256MB                │
                    │  auto_stop: stop                      │
                    │  min_machines_running: 0              │
                    │                                       │
                    │  Internal: prompt-guard.flycast       │
                    │  Public:   prompt-guard.fly.dev       │
                    └─────────────────┬────────────────────┘
                                      │
                    ┌─────────────────┴────────────────────┐
                    │        WireGuard Mesh (private)       │
                    │                                       │
                    │  Other portfolio services             │
                    │  AI agents / models                   │
                    └──────────────────────────────────────┘
```

### Cost Model

| State | Cost |
|-------|------|
| Idle (auto-stopped) | $0/mo |
| Active (shared-cpu-1x, 256MB) | ~$2-4/mo |
| Cold start latency | ~3-5s (first request after idle) |

### fly.toml Structure

```toml
app = "prompt-guard"
primary_region = "jnb"

[build]

[env]
  PORT = "8420"

[http_service]
  internal_port = 8420
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 0

  [http_service.concurrency]
    type = "requests"
    hard_limit = 250
    soft_limit = 200

[[http_service.checks]]
  grace_period = "10s"
  interval = "30s"
  method = "GET"
  path = "/v1/health"
  timeout = "5s"

[[vm]]
  size = "shared-cpu-1x"
  memory = "256mb"
```

### Hardened Dockerfile Structure

```dockerfile
FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
WORKDIR /app
RUN addgroup --system --gid 1000 appgroup && \
    adduser --system --uid 1000 --ingroup appgroup appuser
COPY --from=builder /install /usr/local
COPY src/ ./src/
COPY config/ ./config/
RUN chown -R appuser:appgroup /app
USER appuser
EXPOSE 8420
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8420/v1/health')"]
CMD ["uvicorn", "src.middleware.app:app", "--host", "0.0.0.0", "--port", "8420"]
```

### GitHub Actions CI Workflow Structure

```yaml
name: CI
on:
  push:
    branches: ["*"]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"
      - run: pip install -e ".[dev]"
      - run: ruff check src/ tests/
      - run: mypy src/
      - run: pytest --cov=src --cov-report=term-missing --cov-fail-under=100
```

### GitHub Actions Deploy Workflow Structure

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  test:
    # Same as CI test job
  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: superfly/flyctl-actions/setup-flyctl@master
      - run: flyctl deploy --ha=false
        env:
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
      - name: Smoke test
        run: |
          sleep 10
          curl -sf https://prompt-guard.fly.dev/v1/health | grep '"status":"ok"'
```

---

## DevOps Approval

```yaml
devops_approval:
  approved_by: "ops"
  date: "2026-02-27"
  canonical_version: "v2"
  non_negotiables_verified: true
  platform: "fly.io"
  region: "jnb"
  vm_size: "shared-cpu-1x"
  memory: "256mb"
  cicd: "github-actions"
  notes: >
    Ops agent reviewed full portfolio and confirmed: Fly.io (jnb),
    GitHub Actions, auto-stop, .flycast private networking. This aligns
    with 4/4 existing portfolio projects. Approved for production deployment.
    Cost estimate: $0 idle, $2-4/mo active.
```

---

## Gotchas & Ambiguities

| # | Issue | Interpretation | Recommendation |
|---|-------|---------------|----------------|
| 1 | Rate limiter state is in-memory per machine | With auto-stop, state resets on cold start; with single machine, no cross-machine coordination needed | Acceptable for internal service with single machine. Document that rate limits reset on cold start. |
| 2 | /v1/ prefix vs unversioned routes | Both must work. /v1/ is the canonical path for authenticated access; unversioned routes are backward-compatible for local dev | Mount routes at both paths. Auth middleware only applies to /v1/* paths. Unversioned routes have no auth (local dev parity). |
| 3 | API key validation when PROMPT_GUARD_API_KEY is unset | Fail closed: all authenticated endpoints return 401 | Default: if env var missing, auth middleware rejects all /v1/* requests except health. Log warning at startup. |
| 4 | Fly-Client-IP header for rate limiting | Fly.io provides this header automatically for requests through its proxy | Use Fly-Client-IP if present, fall back to request.client.host. Document this dependency. |
| 5 | CORS removal may break browser-based testing tools | Internal service should not need CORS | Remove CORSMiddleware entirely. If future browser access needed, add it back with specific origins. |
| 6 | Auto-stop cold start latency | First request after idle takes ~3-5s while machine starts | Document cold start behavior. Consuming agents should set timeout >= 10s. SDK default timeout is 30s (sufficient). |
| 7 | Existing tests assume no auth | Integration tests call endpoints without Authorization header | Tests should use unversioned routes (no auth) for existing test coverage. New tests for J007+ use /v1/ with auth. |
| 8 | pyproject.toml entry point mismatch | `prompt_guard.cli:main` vs `src.cli` import path | Not in scope for this envelope (already tracked in v1 Gotcha #5). Does not affect deployment. |

---

## Open Questions (Blocking)

1. **API key value**: Who generates the initial API key and how is it distributed to consuming agents? **Recommendation**: Operator generates with `openssl rand -hex 32` and distributes via secure channel. Document in README.
2. **Rate limit scope**: Should rate limiting apply to unauthenticated unversioned routes as well? **Recommendation**: Yes, apply rate limiting globally to prevent abuse of backward-compatible routes. Auth middleware is the only one that differentiates /v1/ vs unversioned.

---

## BA Handoff Instructions

### For the BA Agent

1. **Read the v2 user journeys** at `/Users/naidooone/Developer/projects/prompt-guard/.claude/artifacts/000_user_journeys_v2.md` -- these define J007-J013 with full acceptance criteria and test specs.

2. **Task breakdown recommendation** (dependency order):

   **Phase 1: Middleware Stack** (enables J007, J011)
   - T015: Create API key auth middleware (C15: src/middleware/auth.py)
     - Bearer token extraction, hmac.compare_digest, env var source, health exemption
     - Unit tests with valid/invalid/missing keys
   - T016: Create rate limiting middleware (C16: src/middleware/rate_limit.py)
     - Token bucket algorithm, 120 req/min burst 20, Retry-After header, Fly-Client-IP
     - Unit tests for bucket fill/drain, burst, header
   - T017: Create request ID middleware (C17: src/middleware/request_id.py)
     - Extract X-Request-ID or generate UUID, set on response header and request state
     - Unit tests for propagation and generation
   - T018: Create security headers middleware (C18: src/middleware/security_headers.py)
     - X-Content-Type-Options, X-Frame-Options, Content-Security-Policy
     - Unit tests for header presence
   - T019: Create request logging middleware (C19: src/middleware/request_logging.py)
     - Structured JSON log per request: method, path, status, latency, request_id
     - Unit tests for log output
   - T020: Register middleware and add /v1/ routes in app.py (C10)
     - Mount middleware in correct order
     - Add /v1/ prefixed routes alongside existing unversioned routes
     - Remove CORS wildcard
     - Integration tests for full middleware stack

   **Phase 2: SDK Update** (enables J008)
   - T021: Add api_key parameter to PromptGuardClient (C11)
     - api_key constructor param, Authorization header, /v1/ prefix when api_key set
     - Unit tests for header injection and prefix logic
     - Integration test against authenticated service

   **Phase 3: Dockerfile and Fly.io** (enables J009, J013)
   - T022: Harden Dockerfile (C21)
     - Multi-stage build, non-root user, HEALTHCHECK, .dockerignore
     - Structural test validating Dockerfile contents
   - T023: Create fly.toml (C20)
     - internal_port, auto_stop, jnb region, health check config
     - Structural test validating fly.toml contents

   **Phase 4: CI/CD** (enables J010)
   - T024: Create GitHub Actions CI workflow (C22)
     - .github/workflows/ci.yml: ruff, mypy, pytest, coverage
     - Structural test validating workflow YAML
   - T025: Create GitHub Actions deploy workflow (C23)
     - .github/workflows/deploy.yml: gates + fly deploy + smoke test
     - Structural test validating workflow YAML

3. **Acceptance criteria**: Each task must reference the relevant AC-J0XX-YY criteria from the journey file. BA should map ACs to tasks explicitly.

4. **Test strategy**:
   - Middleware unit tests: Each middleware tested in isolation with mock request/response
   - Integration tests: Full stack tested via FastAPI TestClient with auth headers
   - Structural tests: Validate Dockerfile, fly.toml, workflow YAML contents
   - Existing tests: Must continue passing unmodified (unversioned routes, no auth)

5. **Adjacent impact warning**: T020 (app.py changes) touches the composition root and must be done after T015-T019 are complete. SDK update (T021) can proceed in parallel with middleware work.

6. **Hexagonal compliance**: All new middleware files go in `src/middleware/`. They are driving adapters. No domain logic changes. No new ports needed.
