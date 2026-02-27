# ---------------------------------------------------------------------------
# Prompt Guard API — Hardened Dockerfile
# Task: T022 | Spec: FR-12
# ---------------------------------------------------------------------------

# ---- Builder stage: install dependencies ----
FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --prefix=/install .

# ---- Runtime stage: minimal image ----
FROM python:3.12-slim

# Create non-root user (UID 1000, GID 1000)
RUN groupadd --gid 1000 appgroup && \
    useradd --uid 1000 --gid appgroup --shell /bin/false --create-home appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source and config
COPY src/ src/
COPY config/ config/

# Set ownership
RUN chown -R appuser:appgroup /app

EXPOSE 8420

# Health check: probe /v1/health every 30s
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8420/v1/health')" || exit 1

# Run as non-root user
USER appuser

CMD ["uvicorn", "src.middleware.app:app", "--host", "0.0.0.0", "--port", "8420"]
