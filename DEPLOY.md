# Prompt Guard — Deployment Guide

## Prerequisites

1. **flyctl** installed: `brew install flyctl` or `curl -L https://fly.io/install.sh | sh`
2. **Authenticated**: `fly auth login`
3. **Fly.io app created**: `fly apps create prompt-guard`
4. **GitHub repository**: Push access to the repo with GitHub Actions enabled

## Environment Variables (Secrets)

Set secrets on Fly.io before first deploy:

```bash
fly secrets set PROMPT_GUARD_API_KEY="your-secure-api-key-here" -a prompt-guard
```

Set secrets in GitHub Actions (Settings > Secrets and variables > Actions):

- `FLY_API_TOKEN` -- Generate via `fly tokens create deploy -x 999999h`

## First Deploy (Manual)

```bash
# From project root
fly deploy --ha=false -a prompt-guard
```

This will:
1. Build the Docker image remotely on Fly.io
2. Deploy to a single machine in the `jnb` region
3. Run the HEALTHCHECK to verify the app is healthy

## Verify Deployment

```bash
# Check app status
fly status -a prompt-guard

# Check health endpoint
curl -s https://prompt-guard.fly.dev/v1/health

# Check authenticated endpoint
curl -s -H "Authorization: Bearer YOUR_API_KEY" https://prompt-guard.fly.dev/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello, world!"}'
```

## Subsequent Deploys (Automated)

After the first deploy, pushes to `main` trigger the GitHub Actions deploy workflow:

1. Quality gates run (ruff, mypy, pytest)
2. If gates pass, `flyctl deploy` runs automatically
3. Smoke test verifies `/v1/health` returns 200

## Rollback

```bash
# List recent deployments
fly releases -a prompt-guard

# Rollback to a previous release
fly releases rollback -a prompt-guard

# Or rollback to a specific version
fly releases rollback v3 -a prompt-guard
```

## Monitoring

```bash
# Live logs
fly logs -a prompt-guard

# App status and machine info
fly status -a prompt-guard

# SSH into the machine (debugging only)
fly ssh console -a prompt-guard
```

## Machine Management

The app is configured with `auto_stop_machines = "stop"` and `min_machines_running = 0`.
This means:

- **Idle**: Machine stops automatically (zero cost)
- **First request**: Machine starts automatically (cold start < 5s)
- **Active**: Machine runs on shared-cpu-1x with 256MB RAM

```bash
# Check machine status
fly machine list -a prompt-guard

# Manually start/stop
fly machine start MACHINE_ID -a prompt-guard
fly machine stop MACHINE_ID -a prompt-guard
```

## Troubleshooting

| Symptom | Check |
|---------|-------|
| 401 on all /v1/ endpoints | Verify PROMPT_GUARD_API_KEY is set: `fly secrets list -a prompt-guard` |
| App not starting | Check logs: `fly logs -a prompt-guard` |
| Health check failing | Verify /v1/health endpoint works locally first |
| Deploy failing in CI | Check FLY_API_TOKEN secret is set in GitHub Actions |
| Cold start too slow | Check `fly logs` for startup errors; consider `min_machines_running = 1` |
