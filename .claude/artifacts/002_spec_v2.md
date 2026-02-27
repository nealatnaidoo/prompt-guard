# Specification: Prompt Guard Production Deployment

**Version**: 2
**Created**: 2026-02-27
**Type**: Feature (production deployment -- middleware, auth, CI/CD, Fly.io)
**Input Artifacts**: `000_user_journeys_v2.md`, `001_solution_envelope_v2.md`
**Supersedes**: `002_spec_v1.md` (retrofit phase -- all 14 tasks completed)

---

## 1. Project Overview

Prompt Guard is a fully hexagonal, adversarial-grade prompt injection detection and content sanitisation service. The v1 retrofit is complete: 309 tests passing, 83% coverage, proper DI via ports/adapters, composition root in place.

**This spec covers production deployment.** The goal is to make prompt-guard available as an internal network service on Fly.io so that AI models and agent pipelines can call it over the network. This requires:

1. Middleware stack (auth, rate limiting, request ID, security headers, request logging)
2. API versioning (/v1/ prefix with backward-compatible unversioned routes)
3. SDK update (api_key parameter, /v1/ prefix auto-selection)
4. Container hardening (Dockerfile non-root, HEALTHCHECK, .dockerignore)
5. Fly.io configuration (fly.toml)
6. CI/CD pipelines (GitHub Actions for CI and deploy)

### DevOps Approval Status

The solution envelope v2 has full DevOps approval:
- Approved by: ops
- Date: 2026-02-27
- Platform: Fly.io (jnb region)
- VM: shared-cpu-1x / 256MB
- CI/CD: GitHub Actions

---

## 2. Scope

### In Scope

1. **API key authentication middleware** -- Bearer token, env var source, constant-time compare, health endpoint exemption
2. **Rate limiting middleware** -- Token bucket, 120 req/min, burst 20, in-memory, Retry-After header
3. **Request ID middleware** -- Generate/propagate X-Request-ID header
4. **Security headers middleware** -- X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Referrer-Policy
5. **Request logging middleware** -- Structured JSON per request to stdout
6. **API versioning** -- /v1/ prefix for all endpoints; unversioned routes retained for backward compat
7. **CORS lockdown** -- Remove wildcard; internal service needs no CORS
8. **SDK update** -- api_key constructor parameter, /v1/ auto-prefix when api_key set
9. **Dockerfile hardening** -- Multi-stage build, non-root user (UID 1000), HEALTHCHECK, .dockerignore
10. **fly.toml** -- internal_port 8420, auto_stop, jnb region, health check config
11. **GitHub Actions CI workflow** -- ruff, mypy, pytest, coverage
12. **GitHub Actions deploy workflow** -- Quality gates, fly deploy, smoke test

### Out of Scope

- Multi-tenant API key support (single key sufficient for internal service)
- API key storage in database (single env var sufficient)
- Horizontal auto-scaling beyond Fly.io auto-stop/start
- Custom domain or TLS certificate management (Fly.io handles this)
- Log aggregation service (Fly.io built-in log tailing sufficient)
- Metrics export (Prometheus/Grafana) -- future enhancement
- Webhook/callback notifications on threat detection
- Admin UI or dashboard
- Blue/green deployment strategy (Fly.io rolling deploys sufficient)
- Rate limiting per API key (single key, single rate limit)
- Changes to domain logic, detectors, or sanitisation rules

---

## 3. Functional Requirements

### FR-5: API Key Authentication (J007)

**Component**: C15 -- `src/middleware/auth.py`

The service must authenticate requests to /v1/* endpoints using a bearer token in the Authorization header.

- **FR-5.1**: Extract bearer token from `Authorization: Bearer <token>` header
- **FR-5.2**: Validate token against `PROMPT_GUARD_API_KEY` environment variable using `hmac.compare_digest` (constant-time comparison)
- **FR-5.3**: Return 401 Unauthorized with `{"detail": "Missing API key"}` when Authorization header is absent
- **FR-5.4**: Return 401 Unauthorized with `{"detail": "Invalid authorization scheme"}` when header is not `Bearer` scheme
- **FR-5.5**: Return 401 Unauthorized with `{"detail": "Invalid API key"}` when token does not match
- **FR-5.6**: Return 401 Unauthorized with `{"detail": "Missing API key"}` when bearer token is empty
- **FR-5.7**: Exempt `/v1/health` and `/health` from authentication (load balancer probes)
- **FR-5.8**: If `PROMPT_GUARD_API_KEY` is unset or empty, all authenticated endpoints return 401 (fail closed)
- **FR-5.9**: API key MUST NOT appear in any log output, error messages, or response bodies
- **FR-5.10**: Auth middleware only applies to `/v1/*` paths; unversioned routes (`/scan`, `/sanitise`, `/stats`) have no auth requirement (backward compat for local dev)

**Acceptance Criteria**: AC-J007-01 through AC-J007-08

### FR-6: Rate Limiting (J007)

**Component**: C16 -- `src/middleware/rate_limit.py`

The service must enforce rate limits to prevent abuse.

- **FR-6.1**: Token bucket algorithm: 120 requests per minute capacity, burst of 20
- **FR-6.2**: Source identifier: `Fly-Client-IP` header if present, else `request.client.host`
- **FR-6.3**: Return 429 Too Many Requests when rate limit exceeded
- **FR-6.4**: Include `Retry-After` header (integer seconds) in 429 responses
- **FR-6.5**: Rate limit state is in-memory per machine (resets on cold start; acceptable for single-machine internal service)
- **FR-6.6**: Rate limiting applies globally to all routes (both /v1/* and unversioned)

**Acceptance Criteria**: AC-J007-06

### FR-7: Request ID Propagation (J007, J011)

**Component**: C17 -- `src/middleware/request_id.py`

Every request must have a traceable request ID for correlation.

- **FR-7.1**: If `X-Request-ID` header is present in the request, use that value
- **FR-7.2**: If `X-Request-ID` header is absent, generate a new UUID4 string
- **FR-7.3**: Set `X-Request-ID` on the response headers
- **FR-7.4**: Make request ID available to downstream handlers via request state
- **FR-7.5**: Scan endpoint must include request_id in ScanResult response body matching the X-Request-ID header value

**Acceptance Criteria**: AC-J007-04, AC-J007-05

### FR-8: Security Headers (J011)

**Component**: C18 -- `src/middleware/security_headers.py`

All responses must include security headers.

- **FR-8.1**: `X-Content-Type-Options: nosniff`
- **FR-8.2**: `X-Frame-Options: DENY`
- **FR-8.3**: `Content-Security-Policy: default-src 'none'`
- **FR-8.4**: `X-Request-ID: <request_id>` (from request ID middleware)

**Acceptance Criteria**: AC-J011-03, AC-J011-05

### FR-9: Request Logging (J011)

**Component**: C19 -- `src/middleware/request_logging.py`

Every request/response must be logged as structured JSON to stdout for observability.

- **FR-9.1**: Log entry fields: `timestamp`, `method`, `path`, `status_code`, `latency_ms`, `request_id`
- **FR-9.2**: For scan requests, additionally log: `threat_level`, `threat_score`, `action_taken`
- **FR-9.3**: Output to stdout as single-line JSON (compatible with Fly.io log tailing)
- **FR-9.4**: API key MUST NOT appear in log output

**Acceptance Criteria**: AC-J011-01, AC-J011-02

### FR-10: API Versioning (J007, J008)

**Component**: C10 -- `src/middleware/app.py`

The service must support versioned and unversioned endpoints.

- **FR-10.1**: Register `/v1/scan`, `/v1/sanitise`, `/v1/health`, `/v1/stats` routes
- **FR-10.2**: Retain existing `/scan`, `/sanitise`, `/health`, `/stats` routes (backward compat)
- **FR-10.3**: Both versioned and unversioned routes execute the same handler logic
- **FR-10.4**: Auth middleware only applies to `/v1/*` (except `/v1/health`)
- **FR-10.5**: Remove CORS wildcard (CORSMiddleware removed or restricted to empty origin list)

**Acceptance Criteria**: AC-J007-01, AC-J007-08, AC-J011-04

### FR-11: SDK Authentication Support (J008)

**Component**: C11 -- `src/client.py`

The Python SDK must support authenticated requests.

- **FR-11.1**: `PromptGuardClient` constructor accepts optional `api_key: str | None = None` parameter
- **FR-11.2**: When `api_key` is provided, all requests include `Authorization: Bearer <api_key>` header
- **FR-11.3**: When `api_key` is provided, SDK targets `/v1/*` endpoints (auto-prefix)
- **FR-11.4**: When `api_key` is None (default), SDK targets unversioned endpoints (backward compat)
- **FR-11.5**: When `api_key` is provided but invalid, server returns 401 and SDK raises `httpx.HTTPStatusError`

**Acceptance Criteria**: AC-J008-01 through AC-J008-05

### FR-12: Container Hardening (J009, J013)

**Component**: C21 -- `Dockerfile`, C24 -- `.dockerignore`

The container must follow security best practices.

- **FR-12.1**: Multi-stage build (builder stage for dependencies, runtime stage for app)
- **FR-12.2**: Non-root user: create `appuser` with UID 1000 in `appgroup` with GID 1000
- **FR-12.3**: `USER appuser` directive before CMD
- **FR-12.4**: `HEALTHCHECK` instruction probing `GET /v1/health` on port 8420
- **FR-12.5**: `.dockerignore` excludes: tests/, .git/, .claude/, docs/, *.pyc, __pycache__/
- **FR-12.6**: `EXPOSE 8420`
- **FR-12.7**: CMD runs uvicorn on 0.0.0.0:8420

**Acceptance Criteria**: AC-J009-05, AC-J009-06, AC-J013-03

### FR-13: Fly.io Configuration (J009)

**Component**: C20 -- `fly.toml`

The service must be configurable for Fly.io deployment.

- **FR-13.1**: `app = "prompt-guard"`, `primary_region = "jnb"`
- **FR-13.2**: `internal_port = 8420`, `force_https = true`
- **FR-13.3**: `auto_stop_machines = "stop"`, `auto_start_machines = true`, `min_machines_running = 0`
- **FR-13.4**: Health check: `GET /v1/health` with 30s interval, 5s timeout, 10s grace period
- **FR-13.5**: VM: `shared-cpu-1x`, `256mb` memory
- **FR-13.6**: Concurrency: `type = "requests"`, `hard_limit = 250`, `soft_limit = 200`

**Acceptance Criteria**: AC-J009-01, AC-J009-04, AC-J009-07

### FR-14: CI/CD Pipelines (J010)

**Components**: C22 -- `.github/workflows/ci.yml`, C23 -- `.github/workflows/deploy.yml`

Automated quality gates and deployment.

- **FR-14.1**: CI workflow triggers on push to any branch and pull_request to main
- **FR-14.2**: CI runs: ruff check, mypy, pytest with coverage, coverage >= 100% assertion
- **FR-14.3**: CI caches pip dependencies for performance
- **FR-14.4**: Deploy workflow triggers on push to main only
- **FR-14.5**: Deploy workflow runs quality gates first, then `fly deploy --ha=false`
- **FR-14.6**: Deploy workflow runs smoke test: `GET /v1/health` returns 200
- **FR-14.7**: Deploy requires `FLY_API_TOKEN` secret in GitHub Actions

**Acceptance Criteria**: AC-J010-01 through AC-J010-06

---

## 4. Non-Functional Requirements

### NFR-5: Performance

- **NFR-5.1**: Middleware stack adds < 5ms p95 overhead per request
- **NFR-5.2**: Scan latency remains < 100ms p95 (excluding cold start)
- **NFR-5.3**: Cold start latency < 5 seconds on Fly.io

### NFR-6: Security

- **NFR-6.1**: API key compared using constant-time comparison (hmac.compare_digest)
- **NFR-6.2**: API key never logged, never in error responses, never in response bodies
- **NFR-6.3**: Container runs as non-root user (UID 1000)
- **NFR-6.4**: Security headers on all responses
- **NFR-6.5**: Fail closed when API key is unset (all /v1/* except health return 401)
- **NFR-6.6**: HTTPS enforced via Fly.io (force_https=true)

### NFR-7: Availability

- **NFR-7.1**: Auto-stop on idle (zero cost when not in use)
- **NFR-7.2**: Auto-start on first request (< 5s cold start)
- **NFR-7.3**: Health endpoint unauthenticated for load balancer probes
- **NFR-7.4**: Rolling deploys via Fly.io (no downtime on deploy)

### NFR-8: Cost

- **NFR-8.1**: $0/month when idle (auto-stop)
- **NFR-8.2**: ~$2-4/month when active (shared-cpu-1x, 256MB)

### NFR-9: Observability

- **NFR-9.1**: Structured JSON logs to stdout (Fly.io compatible)
- **NFR-9.2**: Request ID tracing across request/response
- **NFR-9.3**: Latency tracking per request
- **NFR-9.4**: Threat detection events logged with threat_level and action

### NFR-10: Backward Compatibility

- **NFR-10.1**: All existing unversioned routes continue working without auth
- **NFR-10.2**: All 309 existing tests pass without modification
- **NFR-10.3**: SDK without api_key behaves identically to current behaviour
- **NFR-10.4**: No changes to domain logic, detectors, or sanitisation

### NFR-11: Test Coverage

- **NFR-11.1**: Maintain 100% test coverage (currently at 100% with 402 tests per solution envelope)
- **NFR-11.2**: Each new middleware has dedicated unit tests
- **NFR-11.3**: Integration tests for authenticated API flow
- **NFR-11.4**: Structural tests for Dockerfile, fly.toml, workflow YAML

---

## 5. Architecture

### New Components (All Adapters / Infrastructure)

No domain logic changes. All new components are **driving adapters** (middleware) or **infrastructure configuration files**.

```
                    NEW MIDDLEWARE STACK (Adapters)

  C17: request_id.py         -> Generate/propagate X-Request-ID
  C18: security_headers.py   -> Add security headers to response
  C19: request_logging.py    -> Structured JSON log per request
  C15: auth.py               -> API key validation (Bearer token)
  C16: rate_limit.py         -> Token bucket rate limiting

                    MODIFIED COMPONENTS

  C10: app.py                -> Register middleware, add /v1/ routes, remove CORS
  C11: client.py             -> Add api_key param, /v1/ prefix logic

                    NEW INFRASTRUCTURE

  C20: fly.toml              -> Fly.io app configuration
  C21: Dockerfile            -> Hardened container (non-root, HEALTHCHECK)
  C22: ci.yml                -> GitHub Actions CI workflow
  C23: deploy.yml            -> GitHub Actions deploy workflow
  C24: .dockerignore         -> Exclude non-runtime files from image
```

### Middleware Execution Order

FastAPI middleware executes in reverse registration order. Registration order in app.py:

```python
# Registered LAST = executes FIRST
app.add_middleware(RequestLoggingMiddleware)   # 5. Outermost: log request/response
app.add_middleware(SecurityHeadersMiddleware)  # 4. Add security headers
app.add_middleware(RequestIDMiddleware)        # 3. Generate/propagate request ID
app.add_middleware(RateLimitMiddleware, ...)   # 2. Check rate limits
app.add_middleware(AuthMiddleware, ...)        # 1. Innermost before route: validate API key
```

Execution order for incoming request:
1. RequestLoggingMiddleware (log start, measure latency)
2. SecurityHeadersMiddleware (will add headers to response on the way out)
3. RequestIDMiddleware (generate/extract request ID, set on request state)
4. RateLimitMiddleware (check rate limit; 429 if exceeded)
5. AuthMiddleware (validate API key; 401 if invalid; skip for exempt paths)
6. Route handler (scan/sanitise/health/stats)

### Security Invariants

1. API key read from environment variable only -- never from config file, never hardcoded
2. API key compared using constant-time comparison (`hmac.compare_digest`)
3. API key never in log output, error messages, or response bodies
4. Health endpoint unauthenticated (Fly.io health checks and LB probes)
5. If PROMPT_GUARD_API_KEY unset or empty, all /v1/* except health return 401 (fail closed)
6. Rate limiter uses Fly-Client-IP header (if present) as source identifier, fallback to request.client.host

---

## 6. API Changes

### New Endpoints (Versioned)

All versioned endpoints mirror existing unversioned endpoints but require authentication.

| Method | Path | Auth Required | Description |
|--------|------|---------------|-------------|
| POST | /v1/scan | Yes | Scan content (same as /scan) |
| POST | /v1/sanitise | Yes | Sanitise content (same as /sanitise) |
| GET | /v1/health | No | Health check (same as /health) |
| GET | /v1/stats | Yes | Service stats (same as /stats) |

### Existing Endpoints (Retained)

| Method | Path | Auth Required | Description |
|--------|------|---------------|-------------|
| POST | /scan | No | Scan content (backward compat) |
| POST | /sanitise | No | Sanitise content (backward compat) |
| GET | /health | No | Health check (backward compat) |
| GET | /stats | No | Service stats (backward compat) |

### Response Headers (New, All Responses)

| Header | Value | Source |
|--------|-------|--------|
| X-Request-ID | UUID or propagated value | Request ID middleware |
| X-Content-Type-Options | nosniff | Security headers middleware |
| X-Frame-Options | DENY | Security headers middleware |
| Content-Security-Policy | default-src 'none' | Security headers middleware |

### Error Responses (New)

| Status | Condition | Body |
|--------|-----------|------|
| 401 | Missing Authorization header on /v1/* | `{"detail": "Missing API key"}` |
| 401 | Non-Bearer scheme | `{"detail": "Invalid authorization scheme"}` |
| 401 | Invalid API key | `{"detail": "Invalid API key"}` |
| 401 | Empty bearer token | `{"detail": "Missing API key"}` |
| 429 | Rate limit exceeded | `{"detail": "Rate limit exceeded"}` + `Retry-After` header |

---

## 7. Configuration Changes

### New Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| PROMPT_GUARD_API_KEY | Yes (prod) | None | API key for /v1/* authentication. If unset, all /v1/* (except health) return 401. |
| PORT | No | 8420 | Server listen port |

### New Files

| File | Purpose |
|------|---------|
| `src/middleware/auth.py` | API key authentication middleware |
| `src/middleware/rate_limit.py` | Token bucket rate limiting middleware |
| `src/middleware/request_id.py` | Request ID generation/propagation middleware |
| `src/middleware/security_headers.py` | Security headers middleware |
| `src/middleware/request_logging.py` | Structured JSON request logging middleware |
| `fly.toml` | Fly.io deployment configuration |
| `Dockerfile` | Hardened container image |
| `.dockerignore` | Docker build exclusions |
| `.github/workflows/ci.yml` | CI quality gates workflow |
| `.github/workflows/deploy.yml` | Deploy workflow |

### Modified Files

| File | Changes |
|------|---------|
| `src/middleware/app.py` | Register new middleware, add /v1/ routes, remove CORS wildcard |
| `src/client.py` | Add api_key parameter, /v1/ prefix logic |

---

## 8. Test Requirements

### Unit Tests (Per Middleware)

| Test File | Component | Coverage |
|-----------|-----------|----------|
| `tests/unit/test_auth_middleware.py` | C15: auth.py | Valid key, invalid key, missing key, malformed header, empty bearer, health exemption, fail-closed when unset |
| `tests/unit/test_rate_limit_middleware.py` | C16: rate_limit.py | Under limit, at limit, over limit, burst, Retry-After header, Fly-Client-IP extraction |
| `tests/unit/test_request_id_middleware.py` | C17: request_id.py | Propagate existing ID, generate new ID, set on response header |
| `tests/unit/test_security_headers_middleware.py` | C18: security_headers.py | All four headers present on response |
| `tests/unit/test_request_logging_middleware.py` | C19: request_logging.py | Log fields present, JSON format, no API key in log |

### Integration Tests

| Test File | Coverage |
|-----------|----------|
| `tests/integration/test_authenticated_api.py` | Full auth flow: valid key scan, invalid key 401, missing key 401, health unauthenticated |
| `tests/integration/test_middleware_stack.py` | Full middleware stack: request ID propagation, security headers, rate limit 429, logging output |

### SDK Tests

| Test File | Coverage |
|-----------|----------|
| `tests/unit/test_sdk_auth.py` | api_key param, Authorization header injection, /v1/ prefix, backward compat without api_key |

### Structural Tests

| Test File | Coverage |
|-----------|----------|
| `tests/structural/test_dockerfile.py` | Non-root USER, HEALTHCHECK present, EXPOSE 8420 |
| `tests/structural/test_fly_config.py` | fly.toml: internal_port, auto_stop, region, health check |
| `tests/structural/test_ci_workflows.py` | ci.yml and deploy.yml: required keys, steps |

---

## 9. Epics

### Epic 3: Middleware Stack (Enables J007, J011)

Build the five new middleware components and integrate them into the app. This is the core enabling work for production deployment.

Tasks: T015-T020

### Epic 4: SDK and API Versioning (Enables J008)

Update the Python SDK client to support authenticated requests and /v1/ prefix.

Tasks: T021

### Epic 5: Container and Deployment (Enables J009, J010, J013)

Harden the Dockerfile, create Fly.io config, and set up CI/CD pipelines.

Tasks: T022-T025

---

## 10. Journey-to-Requirement Traceability

| Journey | Requirements | Tasks |
|---------|-------------|-------|
| J007 - Authenticated Scan | FR-5, FR-6, FR-7, FR-10 | T015, T016, T017, T020 |
| J008 - SDK Auth | FR-11 | T021 |
| J009 - Fly.io Deploy | FR-12, FR-13 | T022, T023 |
| J010 - CI/CD | FR-14 | T024, T025 |
| J011 - Monitoring | FR-8, FR-9 | T018, T019 |
| J012 - Key Rotation | FR-5.8 (fail closed), FR-5.10 | Covered by T015 (auth reads env var each request) |
| J013 - Incident Response | FR-12.4 (HEALTHCHECK), FR-9 (logging) | T019, T022 |
