# BUG-003: Auth Middleware Uses Wrong Header Type (X-API-Key vs Bearer)

**ID**: BUG-003
**Source**: verify_deep (2026-02-27)
**Priority**: CRITICAL
**Status**: open
**Created**: 2026-02-27

---

## Summary

Auth middleware uses `X-API-Key` header instead of `Authorization: Bearer <token>` as required by spec. This is a critical deviation that blocks authenticated journeys J007, J008, J009, J012.

---

## Spec Reference

- FR-5.1: "Extract bearer token from `Authorization: Bearer <token>` header"
- FR-5.2: "Validate token against `PROMPT_GUARD_API_KEY` environment variable"
- Solution envelope F7 (line 85): Shows `POST /v1/scan + Authorization: Bearer <key>`
- AC-J007-01 through AC-J007-03: All expect Bearer token, not X-API-Key

---

## Current Implementation

**File**: `src/middleware/auth.py`

- Uses `APIKeyHeader(name="X-API-Key")` (line 18)
- Tests in `tests/test_auth_middleware.py` use `X-API-Key` header
- Client in `src/client.py` sets `headers["X-API-Key"]` (line 79)

---

## Problem

1. **Spec Deviation**: Bearer token is industry standard for OAuth/JWT flows and API authentication. X-API-Key is non-standard.
2. **Integration Failure**: Agent pipelines expecting Bearer token per spec will fail with 401.
3. **Test Validation Gap**: Tests pass but do not validate spec compliance. Tests should use Bearer tokens.

---

## Impact

- Journey J007 (Authenticated Scan): Agent fails to authenticate
- Journey J008 (SDK Auth): Client sends wrong header format
- Journey J009 (Fly.io Deploy): Service deployed but agents cannot authenticate
- Journey J012 (Key Rotation): Env var changes will not affect X-API-Key auth
- All /v1/* endpoints inaccessible to spec-compliant agents

---

## Fix Steps

1. Rewrite `src/middleware/auth.py`:
   - Change from `APIKeyHeader(name="X-API-Key")` to manual `Authorization` header parsing
   - Extract `Bearer <token>` scheme and validate token part
   - Return spec-compliant error responses (FR-5.3 through FR-5.6)
   - Exempt both `/health` and `/v1/health`

2. Update `src/client.py` line 79:
   - Change from `headers["X-API-Key"] = api_key`
   - To: `headers["Authorization"] = f"Bearer {api_key}"`

3. Update all tests in `tests/test_auth_middleware.py`:
   - Change test headers from `X-API-Key` to `Authorization: Bearer`
   - Verify Bearer token parsing
   - Test invalid schemes (non-Bearer)
   - Test empty bearer tokens

4. Verify Fly.io health check will work once /v1/health route is added (BUG-004)

---

## Recommended Code Changes

See deep verification report section: "BUG-003 Recommended Fix" for implementation details.

---

## Validation

After fix:
- Run: `pytest tests/test_auth_middleware.py -v`
- Run: `pytest tests/test_middleware_integration.py -v`
- Manual: `curl -H "Authorization: Bearer test-key" http://localhost:8420/v1/scan`
- Verify: All acceptance criteria AC-J007-01 through AC-J007-08 pass

