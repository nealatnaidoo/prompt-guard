# Pre-Deploy Verification Checklist

Use this checklist before deploying Prompt Guard to Fly.io.

## First Deploy

- [ ] `fly apps create prompt-guard` completed
- [ ] `fly secrets set PROMPT_GUARD_API_KEY=...` set on Fly.io
- [ ] `FLY_API_TOKEN` secret set in GitHub Actions
- [ ] All quality gates pass locally (`ruff check src/ tests/ && mypy src/ && pytest`)
- [ ] Docker build succeeds locally (`docker build -t prompt-guard:test .`)
- [ ] Container runs and health check passes locally:
  ```bash
  docker run -d -p 8420:8420 -e PROMPT_GUARD_API_KEY=test prompt-guard:test
  curl http://localhost:8420/v1/health
  ```

## Every Deploy

- [ ] All tests pass (`pytest --cov=src --cov-fail-under=100`)
- [ ] No lint errors (`ruff check src/ tests/`)
- [ ] No type errors (`mypy src/`)
- [ ] No secrets in code (no hardcoded API keys, passwords, tokens)
- [ ] `fly.toml` unchanged (or changes reviewed)
- [ ] `Dockerfile` unchanged (or changes reviewed)

## Post-Deploy Verification

- [ ] Health check passes: `curl https://prompt-guard.fly.dev/v1/health`
- [ ] Authenticated scan works:
  ```bash
  curl -H "Authorization: Bearer $API_KEY" \
       -H "Content-Type: application/json" \
       -d '{"content": "test"}' \
       https://prompt-guard.fly.dev/v1/scan
  ```
- [ ] Rate limiting active (429 on burst)
- [ ] Security headers present (`X-Content-Type-Options`, `X-Frame-Options`, `CSP`)
- [ ] Request ID propagated (`X-Request-ID` in response)
- [ ] Logs visible: `fly logs -a prompt-guard`

## Rollback Plan

If deployment fails or introduces issues:

```bash
fly releases rollback -a prompt-guard
```

Verify rollback:
```bash
fly status -a prompt-guard
curl https://prompt-guard.fly.dev/v1/health
```
