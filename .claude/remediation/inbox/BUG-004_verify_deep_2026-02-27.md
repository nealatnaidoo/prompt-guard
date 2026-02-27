# BUG-004: Missing /v1/health Endpoint

**ID**: BUG-004
**Source**: verify_deep (2026-02-27)
**Priority**: CRITICAL
**Status**: open
**Created**: 2026-02-27

---

## Summary

Endpoint `/v1/health` does not exist. This blocks Fly.io deployment because the health check (fly.toml) expects `/v1/health`, the Dockerfile HEALTHCHECK probes it, and the deploy workflow smoke test calls it.

---

## Spec Reference

- FR-10.1: "Register `/v1/scan`, `/v1/sanitise`, `/v1/health`, `/v1/stats` routes"
- Journey J009 AC-J009-01: "fly deploy succeeds and health check passes"
- fly.toml line 32: Health check path is `/v1/health`
- Dockerfile line 39: HEALTHCHECK probes `/v1/health`
- Deploy workflow line 71: Smoke test hits `/v1/health`

---

## Current State

**Routes Currently in app.py**:
- ✓ `/v1/scan` (line 304)
- ✓ `/v1/sanitise` (line 309)
- ✓ `/v1/stats` (line 314)
- ✗ `/v1/health` — **MISSING**

**Legacy Routes** (for backward compat):
- ✓ `/health` (line 286)
- ✓ `/scan` (line 276)
- ✓ `/sanitise` (line 281)
- ✓ `/stats` (line 291)

---

## Problem

1. **Spec Non-Compliance**: FR-10.1 explicitly requires all four /v1/* endpoints
2. **Deployment Failure**: Fly.io health checks will always fail (404)
3. **Rolling Restart Failure**: Deploy cannot complete without passing health checks
4. **Smoke Test Failure**: Deploy workflow cannot verify deployment success

---

## Impact

- **Blocking Journey J009**: Operator cannot deploy to Fly.io (health checks fail)
- **Blocking Journey J010**: Deploy workflow smoke test fails
- **Blocking Journey J013**: Incident response cannot use `/v1/health` to verify recovery
- Service cannot go to production

---

## Fix Steps

1. Add `/v1/health` route under v1_router in `src/middleware/app.py`:
   ```python
   @v1_router.get("/health", response_model=HealthResponse)
   async def v1_health(http_request: Request):
       return await health_check(http_request)
   ```
   Insert after line 310, before line 314.

2. Update auth exemptions in `src/middleware/auth.py`:
   - Current line 21: `frozenset({"/health"})`
   - Change to: `frozenset({"/health", "/v1/health"})`
   - Both health endpoints must be unauthenticated for Fly.io LB probes

3. Verify Dockerfile HEALTHCHECK will pass:
   ```bash
   # After app starts, test:
   curl http://localhost:8420/v1/health
   # Should return 200 with HealthResponse JSON
   ```

4. Add tests in `tests/test_middleware_integration.py`:
   - Test GET /v1/health returns 200 without auth
   - Test GET /v1/health returns correct HealthResponse structure
   - Test X-Request-ID header on health response

---

## Recommended Code

```python
# In app.py, after line 310 (@v1_router.post("/sanitise")):

@v1_router.get("/health", response_model=HealthResponse)
async def v1_health(http_request: Request):
    return await health_check(http_request)
```

---

## Validation

After fix:
- `curl http://localhost:8420/v1/health` returns 200
- `pytest tests/test_middleware_integration.py::TestHealthEndpoint -v`
- `fly deploy --remote-only --ha=false` completes successfully
- Fly.io UI shows machine in "running" state (health check passes)

---

## Related Issues

- **BUG-003**: Auth header type; related because /v1/health exemption needs updating
- **BUG-005**: CI coverage threshold; not directly related

