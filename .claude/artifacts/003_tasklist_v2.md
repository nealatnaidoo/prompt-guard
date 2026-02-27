# Tasklist: Prompt Guard Production Deployment

**Version**: 2
**Created**: 2026-02-27
**Spec**: `002_spec_v2.md`
**Continues from**: `003_tasklist_v1.md` (T001-T014 all done)

---

## Dependency Graph

```
Independent: T015, T016, T017, T018, T019    <- can start immediately (all middleware)
After T015 + T016 + T017 + T018 + T019: T020 <- register middleware + /v1/ routes
After T020: T021                              <- SDK needs /v1/ routes available
Independent: T022, T023                       <- Dockerfile + fly.toml (no code deps)
Independent: T024                             <- CI workflow (no code deps)
After T024: T025                              <- deploy workflow reuses CI job structure

Parallelism Score: 73% (8/11 independent)
Estimated parallel time: ~4 hours (vs ~9 hours serial)
```

## Domain Summary

```yaml
domain_summary:
  backend:
    tasks: ["T015", "T016", "T017", "T018", "T019", "T020", "T021"]
    agent: "back"
    pattern: "backend-hexagonal"
  ops:
    tasks: ["T022", "T023", "T024", "T025"]
    agent: "ops"
```

---

## Epic 3: Middleware Stack

---

## T015: Create API Key Authentication Middleware

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: (none)
**Estimated**: 90 min (L)

### Description

Create `src/middleware/auth.py` implementing a Starlette `BaseHTTPMiddleware` that validates bearer token authentication for /v1/* endpoints. The middleware reads `PROMPT_GUARD_API_KEY` from `os.environ` on each request (no caching, enabling key rotation via restart). Uses `hmac.compare_digest` for constant-time comparison. Exempts `/v1/health` and `/health` from auth. Returns 401 for missing, malformed, or invalid tokens. If `PROMPT_GUARD_API_KEY` is unset or empty, all /v1/* endpoints (except health) return 401 (fail closed). Unversioned routes (`/scan`, `/sanitise`, `/stats`) are not subject to auth.

### Acceptance Criteria

- [ ] AC1: POST /v1/scan with valid `Authorization: Bearer <key>` proceeds to handler (AC-J007-01)
- [ ] AC2: Request without Authorization header to /v1/scan returns 401 `{"detail": "Missing API key"}` (AC-J007-02)
- [ ] AC3: Request with invalid bearer token returns 401 `{"detail": "Invalid API key"}` (AC-J007-03)
- [ ] AC4: Request with non-Bearer scheme returns 401 `{"detail": "Invalid authorization scheme"}`
- [ ] AC5: GET /v1/health without auth returns 200 (AC-J007-08)
- [ ] AC6: API key compared using `hmac.compare_digest` (AC-J007-07)
- [ ] AC7: When PROMPT_GUARD_API_KEY is unset, /v1/scan returns 401
- [ ] AC8: Unversioned /scan route is not subject to auth
- [ ] AC9: API key never appears in log output or error response bodies

### Test Assertions

- TA1: test_valid_bearer_token_allows_request
- TA2: test_missing_auth_header_returns_401
- TA3: test_invalid_token_returns_401
- TA4: test_non_bearer_scheme_returns_401
- TA5: test_empty_bearer_token_returns_401
- TA6: test_health_endpoint_exempt_from_auth
- TA7: test_unset_api_key_fails_closed
- TA8: test_unversioned_route_no_auth_required
- TA9: test_constant_time_comparison_used

### Files to Create/Modify

- `src/middleware/auth.py` (create)
- `tests/unit/test_auth_middleware.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/middleware/auth.py`, `tests/unit/test_auth_middleware.py`
- **Expected Minor**: `tests/unit/__init__.py` (create if missing)
- **Out of Scope**: `src/middleware/app.py` (separate task T020)

### Pattern Compliance

- **Backend**: hexagonal (adapters layer), pattern: `backend-hexagonal`

---

## T016: Create Rate Limiting Middleware

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: (none)
**Estimated**: 90 min (L)

### Description

Create `src/middleware/rate_limit.py` implementing a token bucket rate limiter as Starlette `BaseHTTPMiddleware`. Configuration: 120 requests per minute capacity, burst of 20. Source identifier: `Fly-Client-IP` header if present, else `request.client.host`. Returns 429 Too Many Requests with `Retry-After` header (integer seconds until bucket refill) when limit exceeded. Rate limit state is in-memory (resets on process restart, acceptable for single-machine internal service). Applies to all routes globally.

### Acceptance Criteria

- [ ] AC1: Requests under rate limit proceed normally
- [ ] AC2: Request exceeding 120/min returns 429 with `Retry-After` header (AC-J007-06)
- [ ] AC3: Burst of 20 requests within a second is allowed
- [ ] AC4: Token bucket refills at 2 tokens/second (120/60)
- [ ] AC5: Source IP extracted from `Fly-Client-IP` header when present
- [ ] AC6: Source IP falls back to `request.client.host` when `Fly-Client-IP` absent
- [ ] AC7: 429 response body is `{"detail": "Rate limit exceeded"}`

### Test Assertions

- TA1: test_request_under_limit_passes
- TA2: test_request_over_limit_returns_429
- TA3: test_burst_within_limit_passes
- TA4: test_retry_after_header_present
- TA5: test_fly_client_ip_used_when_present
- TA6: test_fallback_to_client_host
- TA7: test_bucket_refills_over_time

### Files to Create/Modify

- `src/middleware/rate_limit.py` (create)
- `tests/unit/test_rate_limit_middleware.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/middleware/rate_limit.py`, `tests/unit/test_rate_limit_middleware.py`
- **Expected Minor**: None
- **Out of Scope**: `src/middleware/app.py` (separate task T020)

### Pattern Compliance

- **Backend**: hexagonal (adapters layer), pattern: `backend-hexagonal`

---

## T017: Create Request ID Middleware

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: (none)
**Estimated**: 45 min (S)

### Description

Create `src/middleware/request_id.py` implementing a Starlette `BaseHTTPMiddleware` that generates or propagates the `X-Request-ID` header. If the incoming request has an `X-Request-ID` header, use that value. Otherwise, generate a new UUID4 string. Set the request ID on the request state (for downstream handlers to access) and on the response `X-Request-ID` header.

### Acceptance Criteria

- [ ] AC1: Incoming request with `X-Request-ID: abc-123` results in response `X-Request-ID: abc-123` (AC-J007-04)
- [ ] AC2: Incoming request without `X-Request-ID` results in a generated UUID in response header (AC-J007-05)
- [ ] AC3: Request ID is available via `request.state.request_id` for downstream handlers
- [ ] AC4: Generated request ID is a valid UUID4 string

### Test Assertions

- TA1: test_propagates_existing_request_id
- TA2: test_generates_new_request_id_when_missing
- TA3: test_sets_request_id_on_response_header
- TA4: test_request_id_available_on_request_state

### Files to Create/Modify

- `src/middleware/request_id.py` (create)
- `tests/unit/test_request_id_middleware.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/middleware/request_id.py`, `tests/unit/test_request_id_middleware.py`
- **Expected Minor**: None
- **Out of Scope**: `src/middleware/app.py` (separate task T020)

### Pattern Compliance

- **Backend**: hexagonal (adapters layer), pattern: `backend-hexagonal`

---

## T018: Create Security Headers Middleware

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: (none)
**Estimated**: 30 min (S)

### Description

Create `src/middleware/security_headers.py` implementing a Starlette `BaseHTTPMiddleware` that adds security headers to all responses: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'`, `Referrer-Policy: strict-origin-when-cross-origin`.

### Acceptance Criteria

- [ ] AC1: Response includes `X-Content-Type-Options: nosniff` (AC-J011-03)
- [ ] AC2: Response includes `X-Frame-Options: DENY` (AC-J011-03)
- [ ] AC3: Response includes `Content-Security-Policy: default-src 'none'` (AC-J011-05)
- [ ] AC4: Response includes `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] AC5: Headers applied to all responses (including error responses)

### Test Assertions

- TA1: test_x_content_type_options_present
- TA2: test_x_frame_options_present
- TA3: test_content_security_policy_present
- TA4: test_referrer_policy_present
- TA5: test_headers_on_error_response

### Files to Create/Modify

- `src/middleware/security_headers.py` (create)
- `tests/unit/test_security_headers_middleware.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/middleware/security_headers.py`, `tests/unit/test_security_headers_middleware.py`
- **Expected Minor**: None
- **Out of Scope**: `src/middleware/app.py` (separate task T020)

### Pattern Compliance

- **Backend**: hexagonal (adapters layer), pattern: `backend-hexagonal`

---

## T019: Create Request Logging Middleware

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: (none)
**Estimated**: 60 min (M)

### Description

Create `src/middleware/request_logging.py` implementing a Starlette `BaseHTTPMiddleware` that emits structured JSON log entries to stdout for every request/response. Each log entry includes: `timestamp` (ISO 8601), `method`, `path`, `status_code`, `latency_ms`, `request_id`. For scan endpoint responses, additionally include: `threat_level`, `threat_score`, `action_taken`. The API key MUST NOT appear in any log output. Use Python's `logging` module or `structlog` configured for JSON output.

### Acceptance Criteria

- [ ] AC1: Every request produces a structured JSON log entry to stdout (AC-J011-01)
- [ ] AC2: Log entry contains: timestamp, method, path, status_code, latency_ms, request_id
- [ ] AC3: Scan request log entries additionally contain: threat_level, threat_score, action_taken (AC-J011-02)
- [ ] AC4: API key never appears in log output
- [ ] AC5: Log entries are single-line JSON (no pretty printing)

### Test Assertions

- TA1: test_log_entry_contains_required_fields
- TA2: test_log_entry_is_valid_json
- TA3: test_scan_log_contains_threat_fields
- TA4: test_api_key_not_in_log_output
- TA5: test_latency_ms_is_positive_number

### Files to Create/Modify

- `src/middleware/request_logging.py` (create)
- `tests/unit/test_request_logging_middleware.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/middleware/request_logging.py`, `tests/unit/test_request_logging_middleware.py`
- **Expected Minor**: None
- **Out of Scope**: `src/middleware/app.py` (separate task T020)

### Pattern Compliance

- **Backend**: hexagonal (adapters layer), pattern: `backend-hexagonal`

---

## T020: Register Middleware Stack and Add /v1/ Routes

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T015, T016, T017, T018, T019
**Estimated**: 90 min (L)

### Description

Modify `src/middleware/app.py` to:

1. **Register all five new middleware** in the correct order (reverse registration = forward execution):
   - Register last (executes first): RequestLoggingMiddleware
   - SecurityHeadersMiddleware
   - RequestIDMiddleware
   - RateLimitMiddleware
   - Register first (executes last): AuthMiddleware

2. **Add /v1/ prefixed routes** alongside existing unversioned routes:
   - POST /v1/scan (same handler as /scan)
   - POST /v1/sanitise (same handler as /sanitise)
   - GET /v1/health (same handler as /health)
   - GET /v1/stats (same handler as /stats)

3. **Remove CORS wildcard**: Remove `CORSMiddleware` entirely or restrict to empty origin list.

4. **Wire request_id into scan response**: Ensure the scan handler reads `request.state.request_id` and passes it to the ScanResult.

5. **Integration tests**: Full middleware stack tested via FastAPI TestClient with auth headers.

### Acceptance Criteria

- [ ] AC1: Middleware registered in correct order (logging outermost, auth innermost)
- [ ] AC2: POST /v1/scan with valid auth returns 200 with ScanResult
- [ ] AC3: POST /v1/scan without auth returns 401
- [ ] AC4: GET /v1/health without auth returns 200
- [ ] AC5: POST /scan (unversioned) without auth returns 200 (backward compat)
- [ ] AC6: Response headers include X-Request-ID, X-Content-Type-Options, X-Frame-Options, CSP
- [ ] AC7: X-Request-ID in response matches ScanResult.request_id (AC-J007-04, AC-J007-05)
- [ ] AC8: CORSMiddleware removed or restricted (AC-J011-04)
- [ ] AC9: All 309+ existing tests still pass
- [ ] AC10: Rate limiter active on all routes

### Test Assertions

- TA1: test_v1_scan_authenticated_returns_200
- TA2: test_v1_scan_unauthenticated_returns_401
- TA3: test_v1_health_unauthenticated_returns_200
- TA4: test_unversioned_scan_no_auth_required
- TA5: test_response_has_security_headers
- TA6: test_response_has_request_id_header
- TA7: test_scan_result_request_id_matches_header
- TA8: test_cors_not_wildcard
- TA9: test_rate_limit_429_on_burst

### Files to Create/Modify

- `src/middleware/app.py` (modify)
- `tests/integration/test_authenticated_api.py` (create)
- `tests/integration/test_middleware_stack.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/middleware/app.py`, integration test files
- **Expected Minor**: `tests/integration/__init__.py` (create if missing), `tests/conftest.py` (may need auth-aware TestClient fixture)
- **Out of Scope**: Individual middleware files (already created in T015-T019)

### Pattern Compliance

- **Backend**: hexagonal (adapters layer -- composition root), pattern: `backend-hexagonal`

---

## Epic 4: SDK and API Versioning

---

## T021: Add api_key Parameter to PromptGuardClient

**Status**: pending
**Domain**: backend
**Agent**: back
**Blocked By**: T020 (v1 routes must exist for integration testing)
**Estimated**: 60 min (M)

### Description

Modify `src/client.py` to add an optional `api_key` parameter to `PromptGuardClient`:

1. Constructor accepts `api_key: str | None = None`
2. When `api_key` is provided, configure httpx.AsyncClient with `Authorization: Bearer <api_key>` default header
3. When `api_key` is provided, use `/v1/` prefix for all endpoint calls (scan -> /v1/scan, sanitise -> /v1/sanitise, health -> /v1/health)
4. When `api_key` is None, use existing unversioned endpoints (backward compat)
5. Include unit tests and integration test against authenticated service

### Acceptance Criteria

- [ ] AC1: `PromptGuardClient(base_url, api_key="sk-test")` sets Authorization header (AC-J008-01)
- [ ] AC2: `PromptGuardClient(base_url)` sends no Authorization header (AC-J008-02)
- [ ] AC3: With api_key, scan() calls /v1/scan (AC-J008-03)
- [ ] AC4: Without api_key, scan() calls /scan (AC-J008-04)
- [ ] AC5: Invalid api_key against authenticated server raises httpx.HTTPStatusError 401 (AC-J008-05)

### Test Assertions

- TA1: test_client_with_api_key_sets_auth_header
- TA2: test_client_without_api_key_no_auth_header
- TA3: test_client_with_api_key_uses_v1_prefix
- TA4: test_client_without_api_key_uses_unversioned
- TA5: test_client_invalid_key_raises_401
- TA6: test_client_scan_authenticated_integration

### Files to Create/Modify

- `src/client.py` (modify)
- `tests/unit/test_sdk_auth.py` (create)
- `tests/integration/test_sdk_auth_integration.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `src/client.py`, SDK test files
- **Expected Minor**: None
- **Out of Scope**: Server middleware (already done in T015-T020)

### Pattern Compliance

- **Backend**: hexagonal (driving adapter), pattern: `backend-hexagonal`

---

## Epic 5: Container and Deployment

---

## T022: Harden Dockerfile and Create .dockerignore

**Status**: pending
**Domain**: ops
**Agent**: ops
**Blocked By**: (none)
**Estimated**: 45 min (S)

### Description

Create or replace the `Dockerfile` with a hardened version:

1. Multi-stage build: builder stage installs dependencies, runtime stage copies only what's needed
2. Non-root user: create `appgroup` (GID 1000) and `appuser` (UID 1000)
3. `USER appuser` directive before CMD
4. `HEALTHCHECK` instruction: `GET /v1/health` on port 8420
5. `EXPOSE 8420`
6. CMD: `uvicorn src.middleware.app:app --host 0.0.0.0 --port 8420`

Create `.dockerignore` excluding: `tests/`, `.git/`, `.claude/`, `docs/`, `*.pyc`, `__pycache__/`, `.github/`, `*.md`, `.env*`.

Include structural tests that validate Dockerfile contents.

### Acceptance Criteria

- [ ] AC1: Dockerfile uses multi-stage build (FROM ... AS builder) (AC-J009-05)
- [ ] AC2: Container runs as non-root user UID 1000 (AC-J009-05)
- [ ] AC3: HEALTHCHECK instruction probes /v1/health on port 8420 (AC-J009-06, AC-J013-03)
- [ ] AC4: EXPOSE 8420
- [ ] AC5: .dockerignore excludes tests, .git, .claude, docs
- [ ] AC6: `docker build .` succeeds (if Docker available)

### Test Assertions

- TA1: test_dockerfile_has_non_root_user
- TA2: test_dockerfile_has_healthcheck
- TA3: test_dockerfile_has_expose_8420
- TA4: test_dockerfile_uses_multistage_build
- TA5: test_dockerignore_excludes_tests

### Files to Create/Modify

- `Dockerfile` (create or replace)
- `.dockerignore` (create)
- `tests/structural/test_dockerfile.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `Dockerfile`, `.dockerignore`, structural tests
- **Expected Minor**: `tests/structural/__init__.py` (create if missing)
- **Out of Scope**: `src/` (no source code changes)

### Pattern Compliance

- **Ops**: infrastructure configuration

---

## T023: Create fly.toml Configuration

**Status**: pending
**Domain**: ops
**Agent**: ops
**Blocked By**: (none)
**Estimated**: 30 min (S)

### Description

Create `fly.toml` in the project root with the Fly.io deployment configuration:

- `app = "prompt-guard"`, `primary_region = "jnb"`
- `env.PORT = "8420"`
- `http_service.internal_port = 8420`, `force_https = true`
- `auto_stop_machines = "stop"`, `auto_start_machines = true`, `min_machines_running = 0`
- Health check: `GET /v1/health`, interval 30s, timeout 5s, grace period 10s
- VM: `shared-cpu-1x`, `256mb`
- Concurrency: requests type, hard 250, soft 200

Include structural test that validates fly.toml contents.

### Acceptance Criteria

- [ ] AC1: fly.toml exists in project root with correct app name and region (AC-J009-04)
- [ ] AC2: internal_port is 8420 and force_https is true (AC-J009-07)
- [ ] AC3: auto_stop_machines is "stop" and min_machines_running is 0 (AC-J009-04)
- [ ] AC4: Health check path is /v1/health (AC-J009-01)
- [ ] AC5: VM size is shared-cpu-1x with 256mb memory

### Test Assertions

- TA1: test_fly_toml_app_name
- TA2: test_fly_toml_region_jnb
- TA3: test_fly_toml_internal_port_8420
- TA4: test_fly_toml_auto_stop_enabled
- TA5: test_fly_toml_health_check_path

### Files to Create/Modify

- `fly.toml` (create)
- `tests/structural/test_fly_config.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `fly.toml`, structural tests
- **Expected Minor**: `tests/structural/__init__.py` (create if missing, may already exist from T022)
- **Out of Scope**: `src/` (no source code changes)

### Pattern Compliance

- **Ops**: infrastructure configuration

---

## T024: Create GitHub Actions CI Workflow

**Status**: pending
**Domain**: ops
**Agent**: ops
**Blocked By**: (none)
**Estimated**: 45 min (S)

### Description

Create `.github/workflows/ci.yml` with the CI quality gates workflow:

- Trigger: push to any branch, pull_request to main
- Python 3.12 setup with pip cache
- Steps: `pip install -e ".[dev]"`, `ruff check src/ tests/`, `mypy src/`, `pytest --cov=src --cov-report=term-missing --cov-fail-under=100`
- Single job `test` on ubuntu-latest

Include structural test that validates workflow YAML.

### Acceptance Criteria

- [ ] AC1: .github/workflows/ci.yml exists and is valid YAML (AC-J010-01)
- [ ] AC2: Triggers on push and pull_request
- [ ] AC3: Runs ruff, mypy, and pytest with coverage
- [ ] AC4: Coverage threshold is 100% (--cov-fail-under=100)
- [ ] AC5: Uses pip cache for dependencies (AC-J010-06)

### Test Assertions

- TA1: test_ci_workflow_exists
- TA2: test_ci_workflow_triggers
- TA3: test_ci_workflow_runs_ruff
- TA4: test_ci_workflow_runs_mypy
- TA5: test_ci_workflow_runs_pytest_with_coverage

### Files to Create/Modify

- `.github/workflows/ci.yml` (create)
- `tests/structural/test_ci_workflows.py` (create)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `.github/workflows/ci.yml`, structural tests
- **Expected Minor**: `.github/workflows/` directory creation
- **Out of Scope**: `src/` (no source code changes)

### Pattern Compliance

- **Ops**: CI/CD configuration

---

## T025: Create GitHub Actions Deploy Workflow

**Status**: pending
**Domain**: ops
**Agent**: ops
**Blocked By**: T024 (deploy reuses CI job structure for quality gates)
**Estimated**: 45 min (S)

### Description

Create `.github/workflows/deploy.yml` with the deploy workflow:

- Trigger: push to main only
- Job 1 `test`: Same quality gates as CI (ruff, mypy, pytest, coverage)
- Job 2 `deploy` (needs: test): setup flyctl, `flyctl deploy --ha=false`, smoke test `GET /v1/health`
- Deploy job uses `FLY_API_TOKEN` secret

Include structural test that validates workflow YAML.

### Acceptance Criteria

- [ ] AC1: .github/workflows/deploy.yml exists and is valid YAML
- [ ] AC2: Triggers on push to main only (AC-J010-02)
- [ ] AC3: Runs quality gates before deploy (AC-J010-02)
- [ ] AC4: Uses flyctl for deployment
- [ ] AC5: Includes smoke test hitting /v1/health (AC-J010-03)
- [ ] AC6: References FLY_API_TOKEN secret (AC-J010-05)

### Test Assertions

- TA1: test_deploy_workflow_exists
- TA2: test_deploy_workflow_triggers_on_main_only
- TA3: test_deploy_workflow_has_test_job
- TA4: test_deploy_workflow_has_deploy_job
- TA5: test_deploy_workflow_has_smoke_test
- TA6: test_deploy_workflow_references_fly_api_token

### Files to Create/Modify

- `.github/workflows/deploy.yml` (create)
- `tests/structural/test_ci_workflows.py` (modify -- add deploy workflow tests)

### Adjacent Scope (Tier 2 Prevention)

- **Included**: `.github/workflows/deploy.yml`, structural tests
- **Expected Minor**: None
- **Out of Scope**: `src/` (no source code changes), fly.toml (separate task T023)

### Pattern Compliance

- **Ops**: CI/CD configuration
