# Verify (Deep) - Production Deployment Feature (T015-T025)

**Date**: 2026-02-27
**Mode**: Deep
**Result**: NEEDS_WORK
**Tasks Reviewed**: T015-T025 (11 tasks across 3 epics)
**Report**: `.claude/remediation/verify_deep_YYYY-MM-DD.md`

---

## Summary

| Metric | Value |
|--------|-------|
| Mode | Deep |
| Result | **NEEDS_WORK** |
| Tasks Reviewed | T015-T025 (11 new production deployment tasks) |
| Tests Created | 475 total (166+ new) |
| Coverage Achieved | 100% |
| Bugs Found | 3 CRITICAL / HIGH |
| Improvements Suggested | 1 |
| Blocking Issues | Yes — 2 critical spec deviations prevent deployment |

---

## Prime Directive Compliance

| Check | Status | Notes |
|-------|--------|-------|
| Task-Scoped | PASS | All 11 tasks isolated to epic scope (T015-T020 middleware, T021 SDK, T022-T025 ops) |
| Atomic | PASS | Each task delivers discrete component with tests |
| Deterministic | PASS | No new datetime.now/uuid4/random in domain; request ID uses uuid in adapter (acceptable) |
| Hexagonal | PASS | All new middleware = adapters; domain model untouched; composition root in lifespan |
| Evidenced | PASS | 475 tests passing; 100% coverage; structured test files for each middleware |

---

## Task Completion Verification

### Epic 3: Middleware Stack (T015-T020)

#### T015: Create API Key Authentication Middleware

**Status**: INCOMPLETE — **CRITICAL SPEC DEVIATION**

**Spec Requirement** (FR-5.1, FR-5.2):
- Extract bearer token from `Authorization: Bearer <token>` header
- Validate against `PROMPT_GUARD_API_KEY` env var using hmac.compare_digest

**Implementation** (src/middleware/auth.py):
- ✓ Uses hmac.compare_digest for constant-time comparison (AC-J007-07)
- ✓ Reads PROMPT_GUARD_API_KEY from environment (AC-J007-08 fail-closed)
- ✓ Exempts /health from auth (line 21)
- ✗ **CRITICAL**: Uses `APIKeyHeader(name="X-API-Key")` instead of Bearer token header
- ✗ **MISSING**: Does not exempt `/v1/health` from auth (only `/health`)

**Impact**:
- Agent pipelines expecting `Authorization: Bearer <key>` per spec will fail
- Fly.io health checks to `/v1/health` will be rejected (no route exists + would need auth)
- Solution envelope F7 flow (line 85) shows Bearer token requirement
- Tests pass because they use X-API-Key, not Bearer — tests do not validate spec

**Acceptance Criteria Coverage**:
- AC-J007-01: FAIL (uses X-API-Key, not Bearer)
- AC-J007-02: FAIL (error messages don't distinguish between auth types)
- AC-J007-07: PASS (constant-time comparison used)
- AC-J007-08: PARTIAL (exempts /health but not /v1/health)

**Recommendation**: Rewrite auth middleware to:
1. Parse `Authorization` header instead of X-API-Key
2. Extract `Bearer <token>` scheme and token
3. Return spec-compliant error messages
4. Exempt **both** `/health` and `/v1/health`

---

#### T016: Create Rate Limiting Middleware

**Status**: PASS ✓

**Spec Verification**:
- ✓ Token bucket algorithm with 120 req/min capacity (FR-6.1)
- ✓ Burst of 20 implemented via capacity parameter (line 87)
- ✓ Retry-After header included in 429 responses (FR-6.4, line 103)
- ✓ Per-source rate limiting (API key or IP) (FR-6.2)
- ✓ Returns 429 Too Many Requests (FR-6.3)
- ✓ Applies to all routes globally (FR-6.6)

**Acceptance Criteria**: AC-J007-06 ✓ PASS

---

#### T017: Create Request ID Middleware

**Status**: PASS ✓

**Spec Verification**:
- ✓ Propagates existing X-Request-ID header (FR-7.1)
- ✓ Generates UUID4 when missing (FR-7.2)
- ✓ Sets on response headers (FR-7.3)
- ✓ Available via request.state.request_id (FR-7.4)

**Gap**: Scan endpoint should inject request_id into ScanResult (FR-7.5). Need to verify in T020.

---

#### T018: Create Security Headers Middleware

**Status**: PASS ✓

**Spec Verification**:
- ✓ X-Content-Type-Options: nosniff (FR-8.1)
- ✓ X-Frame-Options: DENY (FR-8.2)
- ✓ Content-Security-Policy: default-src 'none' (FR-8.3)
- ✓ X-Request-ID on response (FR-8.4, set by request ID middleware)
- ✓ Plus X-XSS-Protection: 0 and Strict-Transport-Security (defense-in-depth)

**Acceptance Criteria**: AC-J011-03, AC-J011-05 ✓ PASS

---

#### T019: Create Request Logging Middleware

**Status**: PASS ✓

**Spec Verification**:
- ✓ Structured JSON log per request (FR-9.1)
- ✓ Fields: timestamp, method, path, status_code, latency_ms, request_id (FR-9.1)
- ✓ Single-line JSON output to stdout (FR-9.3)
- ✓ API key not in logs (FR-9.4)
- ✓ Uses structlog (structured logging library)

**Gap**: Does not log threat_level, threat_score, action_taken for scan requests (FR-9.2). Should be added to request.state by scan handler.

**Acceptance Criteria**: AC-J011-01, AC-J011-02 — PARTIAL (missing threat fields for scan)

---

#### T020: Register Middleware Stack and Add /v1/ Routes

**Status**: INCOMPLETE — **CRITICAL MISSING ROUTE**

**Middleware Registration** (app.py lines 126-129):
- ✓ Registered in correct reverse order (logging outermost, others follow)
- ✓ Rate limit and request ID and security headers present
- ✓ Auth applied per-route via Depends(require_api_key)

**Routes Created** (app.py):
- ✗ **CRITICAL**: `/v1/health` route **DOES NOT EXIST**
- ✓ `/v1/scan` registered (line 304-306)
- ✓ `/v1/sanitise` registered (line 309-311)
- ✓ `/v1/stats` registered (line 314-316)
- ✓ Legacy `/scan`, `/sanitise`, `/health`, `/stats` retained (backward compat)

**Impact**:
- Fly.io healthcheck config points to `/v1/health` (fly.toml line 32) — **will always fail**
- Journey J009 AC-J009-01 expects deployments to succeed — **impossible without this route**
- Spec FR-10.1 explicitly requires `/v1/health`
- v1_router includes all routes under dependency requiring auth; need exemption for health

**Auth on /v1/health**:
- If route were created, Depends(require_api_key) would reject it as non-exempt
- Current auth exempts `/health` only, not `/v1/health` (line 21 auth.py)

**Recommendation**: Add `/v1/health` route:
```python
@v1_router.get("/health", response_model=HealthResponse)
async def v1_health(http_request: Request):
    return await health_check(http_request)
```
And update auth.py to exempt both `/health` and `/v1/health`.

**Acceptance Criteria**: AC-J007-04, AC-J007-08 — FAIL

---

### Epic 4: SDK and API Versioning (T021)

#### T021: Add api_key Parameter to PromptGuardClient

**Status**: INCOMPLETE — **INHERITS AUTH HEADER BUG FROM T015**

**Implementation** (src/client.py line 79):
- ✓ Constructor accepts `api_key: str | None = None` (line 73, AC-J008-01)
- ✓ Sets header when api_key provided (line 79)
- ✓ No header when api_key None (backward compat, AC-J008-02)
- ✗ Uses `headers["X-API-Key"]` instead of `Authorization: Bearer`
- ✓ Routes: `/v1/` prefix when api_key set, unversioned when None (AC-J008-03, AC-J008-04)

**Gap**: Since /v1/ routes don't exist fully (missing health), client tests pass but real integration will fail.

**Acceptance Criteria**: AC-J008-01 — FAIL (wrong header type)

---

### Epic 5: Container and Deployment (T022-T025)

#### T022: Harden Dockerfile and Create .dockerignore

**Status**: PASS ✓

**Dockerfile Verification** (Dockerfile):
- ✓ Multi-stage build (builder -> runtime, lines 7-16)
- ✓ Non-root user: appuser (UID 1000), appgroup (GID 1000) (lines 20-21)
- ✓ USER appuser before CMD (line 42)
- ✓ HEALTHCHECK probes `/v1/health` on port 8420 (line 38-39)
  - **Note**: This endpoint doesn't exist yet (T020 bug)
- ✓ EXPOSE 8420 (line 35)
- ✓ CMD runs uvicorn on 0.0.0.0:8420 (line 44)

**.dockerignore Verification**:
- ✓ Excludes tests/, .git/, .claude/, docs/ (lines 7-18)
- ✓ Excludes .env* (line 27)
- ✓ Excludes .github/, .pytest_cache/ (lines 35, 40)

**Acceptance Criteria**: AC-J009-05, AC-J009-06, AC-J013-03 ✓ PASS

---

#### T023: Create fly.toml Configuration

**Status**: PASS ✓

**Verification** (fly.toml):
- ✓ app = "prompt-guard", primary_region = "jnb" (lines 6-7)
- ✓ internal_port = 8420, force_https = true (lines 17-18)
- ✓ auto_stop_machines = "stop", min_machines_running = 0 (lines 19-21)
- ✓ Health check: `/v1/health`, interval 30s, timeout 5s, grace period 10s (lines 28-34)
  - **Note**: Health check path is correct per spec, but endpoint doesn't exist (T020 bug)
- ✓ VM: shared-cpu-1x with 256mb memory (lines 37-38)
- ✓ Concurrency: requests type, hard 250, soft 200 (lines 23-26)

**Acceptance Criteria**: AC-J009-01, AC-J009-04, AC-J009-07 ✓ PASS (config correct, but deployment will fail)

---

#### T024: Create GitHub Actions CI Workflow

**Status**: INCOMPLETE — **COVERAGE THRESHOLD TOO LOW**

**Verification** (.github/workflows/ci.yml):
- ✓ Triggers on push and pull_request (lines 10-13)
- ✓ Runs ruff check (line 36)
- ✓ Runs mypy (line 39)
- ✓ Runs pytest with coverage (line 42)
- ✗ **HIGH SEVERITY**: Coverage threshold is 80% (line 42)
  - Spec NFR-11.1 and solution envelope state "Must maintain 100%"
  - Allows regression: future code could drop to 80% and still pass CI
- ✓ Uses pip cache (line 30)

**Acceptance Criteria**: AC-J010-01, AC-J010-04, AC-J010-06 — PARTIAL (coverage gate too weak)

---

#### T025: Create GitHub Actions Deploy Workflow

**Status**: PARTIAL

**Verification** (.github/workflows/deploy.yml):
- ✓ Triggers on push to main only (line 11)
- ✓ Runs quality gates first (lines 19-41 "quality-gates" job)
- ✓ Uses flyctl for deployment (line 55)
- ✓ References FLY_API_TOKEN secret (line 57)
- ✓ Smoke test hits `/v1/health` (line 71)
  - **Note**: Health check path is correct, but endpoint doesn't exist (T020 bug)
- ✓ Smoke test expects 200 (line 72)

**Gap**: Smoke test will fail because `/v1/health` doesn't exist.

**Acceptance Criteria**: AC-J010-02, AC-J010-03, AC-J010-05 ✓ PASS (config correct, but deployment will fail)

---

## Journey Coverage Verification

### Journey Dependency Impact

| Journey | Task | Status | Blocker |
|---------|------|--------|---------|
| J007 - Authenticated Scan | T015, T016, T017, T020 | FAIL | Missing /v1/health; wrong auth header |
| J008 - SDK Auth | T021 | FAIL | Inherits T015/T020 bugs |
| J009 - Fly.io Deploy | T022, T023 | FAIL | /v1/health missing; auth header wrong |
| J010 - CI/CD | T024, T025 | PARTIAL | Coverage threshold too low; deployment will fail due to health check |
| J011 - Monitoring | T018, T019 | PASS | Middleware functional (though missing threat fields in logs) |
| J012 - Key Rotation | T015 | FAIL | Auth header wrong |
| J013 - Incident Response | T022, T019 | PARTIAL | Dockerfile correct; logging present but incomplete |

---

## Bugs (Must Fix)

### BUG-003 (CRITICAL): Auth Middleware Uses Wrong Header Type

- **Severity**: CRITICAL — blocks J007, J008, J009, J012
- **Location**: `src/middleware/auth.py` (entire file), `src/client.py:79`
- **Spec Reference**: FR-5.1, FR-5.2; Solution envelope F7 (line 85)
- **Evidence**: 
  - Spec: `Authorization: Bearer <token>`
  - Implementation: `APIKeyHeader(name="X-API-Key")`
  - Tests use X-API-Key, not Bearer; tests do not validate spec compliance
- **Impact**: Service will reject all agent pipelines expecting Bearer tokens; incompatible with industry standard OAuth/JWT flows
- **Recommended Fix**:
```python
# In auth.py:
from fastapi import HTTPException, Request
import hmac

async def require_api_key(request: Request):
    # Extract Authorization header
    auth_header = request.headers.get("Authorization")
    
    # Health endpoints exempt
    if request.url.path in {"/health", "/v1/health"}:
        return None
    
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing API key")
    
    # Parse Bearer token
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization scheme")
    
    token = auth_header[7:]  # Remove "Bearer "
    if not token:
        raise HTTPException(status_code=401, detail="Missing API key")
    
    # Validate against env var
    expected = os.environ.get("PROMPT_GUARD_API_KEY")
    if not expected:
        raise HTTPException(status_code=401, detail="Missing API key")
    
    if not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return token
```

---

### BUG-004 (CRITICAL): Missing /v1/health Endpoint

- **Severity**: CRITICAL — blocks J009, J010, J013 deployment
- **Location**: `src/middleware/app.py` (missing route)
- **Spec Reference**: FR-10.1; Fly.io health check (fly.toml line 32)
- **Evidence**:
  - Spec FR-10.1: "Register `/v1/scan`, `/v1/sanitise`, `/v1/health`, `/v1/stats` routes"
  - app.py routes: /v1/scan ✓, /v1/sanitise ✓, /v1/stats ✓, /v1/health ✗
  - fly.toml health check path: `/v1/health` (will always 404)
  - Dockerfile HEALTHCHECK: probes `/v1/health` (will always fail)
  - Deploy workflow smoke test: hits `/v1/health` (will fail)
- **Impact**: 
  - Fly.io deployment will never mark machine as healthy
  - Rolling restart on deploy will not complete (health check fails)
  - Service cannot be deployed to production
- **Recommended Fix**: Add route to v1_router:
```python
@v1_router.get("/health", response_model=HealthResponse)
async def v1_health(http_request: Request):
    return await health_check(http_request)
```
Also update auth.py exempt paths to include `/v1/health`.

---

### BUG-005 (HIGH): CI Workflow Coverage Threshold Too Low

- **Severity**: HIGH — allows future regressions
- **Location**: `.github/workflows/ci.yml` line 42
- **Spec Reference**: NFR-11.1 "Maintain 100% test coverage"; solution envelope line 29, 135
- **Evidence**:
  - Spec: "Must maintain 100%"
  - CI workflow: `--cov-fail-under=80`
  - Current actual coverage: 100%
  - Future PRs could drop to 80% and still merge
- **Impact**: Coverage regression risk; future maintainers may unknowingly reduce test quality
- **Recommended Fix**:
```yaml
# Line 42 in ci.yml:
run: pytest --cov=src --cov-report=term-missing --cov-fail-under=100 -x -q --tb=short
```
Also update deploy.yml line 41 to match.

---

### BUG-006 (MEDIUM): Request Logging Missing Threat Fields for Scans

- **Severity**: MEDIUM — affects observability
- **Location**: `src/middleware/request_logging.py`
- **Spec Reference**: FR-9.2 "For scan requests, additionally log: threat_level, threat_score, action_taken"
- **Evidence**: 
  - Spec FR-9.2: Scan logs should include threat metadata
  - Implementation logs: method, path, status, latency, request_id, client_ip (no threat fields)
  - AC-J011-02 expects threat fields in logs
- **Impact**: Operators cannot correlate threats in service logs without additional queries to stats endpoint
- **Recommended Fix**: After scan completes, store threat fields in request.state and read in logging middleware:
```python
# In scan_content handler:
http_request.state.threat_level = result.threat_level.value
http_request.state.threat_score = result.threat_score
http_request.state.action_taken = result.action_taken.value

# In logging middleware:
if request.method == "POST" and "/scan" in request.url.path:
    threat_level = getattr(request.state, "threat_level", None)
    if threat_level:
        logger.info("threat_detected", threat_level=threat_level, ...)
```

---

## Improvements (Should Consider)

### IMPROVE-003 (MEDIUM): Unused Imports in Production Code

- **Priority**: MEDIUM — quick fix, improves code cleanliness
- **Locations**:
  - `src/middleware/app.py:16` — unused `import time`
  - `src/sanitizers/content_sanitizer.py:11` — unused `import unicodedata`
  - `src/utils/audit.py:6` — unused `import os`
- **Fix**: Run `ruff check --fix src/` to auto-remove

---

## Quality Gate Output

### Test Execution
```
475 passed in 3.77s
```

### Coverage Report
```
Coverage: 100%
Lines: 1197
Statements: 1197
Missing: 0
```

### Lint (Ruff)
```
Found 3 fixable issues:
- src/middleware/app.py:16: F401 unused import `time`
- src/sanitizers/content_sanitizer.py:11: F401 unused import `unicodedata`
- src/utils/audit.py:6: F401 unused import `os`
```

### Type Check (Mypy)
```
Passed (note-level warnings only, no errors)
```

---

## Required Actions (Blocking Deployment)

1. **[CRITICAL]** Fix auth.py to use `Authorization: Bearer` header instead of `X-API-Key`
   - Rewrite authentication logic per spec FR-5.1, FR-5.2
   - Update tests to validate Bearer token flow
   - Update client.py to use Bearer header
   - Estimated: 2 hours

2. **[CRITICAL]** Add `/v1/health` endpoint to app.py
   - Create GET /v1/health under v1_router
   - Exempt from auth in auth.py (both /health and /v1/health)
   - Verify Dockerfile HEALTHCHECK will pass
   - Estimated: 1 hour

3. **[HIGH]** Fix CI/deploy workflows to enforce 100% coverage threshold
   - Change `--cov-fail-under=80` to `--cov-fail-under=100` in ci.yml and deploy.yml
   - Estimated: 10 minutes

4. **[MEDIUM]** Add threat metadata to request logging for scans
   - Pass threat fields through request.state
   - Log threat_level, threat_score, action_taken for scan requests
   - Update tests to verify logging
   - Estimated: 1 hour

---

## Not Blocking, But Recommended

1. Remove unused imports (ruff --fix)
2. Add integration test for full authenticated scan flow with Bearer tokens
3. Add integration test for health endpoint with and without auth
4. Document Bearer token format in README or API docs

---

## Conclusion

**Result: NEEDS_WORK**

The production deployment feature has solid foundational work:
- ✓ 475 tests passing, 100% coverage achieved
- ✓ All middleware components structurally sound
- ✓ Hexagonal architecture preserved
- ✓ Docker and Fly.io config correct (in isolation)

However, **3 critical spec deviations block deployment**:
1. Auth header type (Bearer vs X-API-Key) — **journeys J007, J008, J012 fail**
2. Missing /v1/health endpoint — **deployment to Fly.io cannot succeed**
3. Coverage threshold too low — **regression risk**

All three are relatively straightforward to fix (estimated 3-4 hours total). Once fixed and re-tested, this feature is ready for production deployment.

**Estimated remediation time: 3-4 hours**
**Recommended next steps: Create BUG-003, BUG-004, BUG-005 inbox items; assign to back agent for fixes; re-run deep verify after fixes**
