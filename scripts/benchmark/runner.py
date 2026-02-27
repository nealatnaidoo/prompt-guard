"""Benchmark runner — feeds samples through the scan endpoint."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from .datasets.base import DatasetAdapter, ScanOutcome

# Threat levels ordered by severity
_THREAT_LEVELS = ("clean", "low", "medium", "high", "critical")


def _level_at_or_above(level: str, threshold: str) -> bool:
    """Return True if level is at or above the threshold."""
    try:
        return _THREAT_LEVELS.index(level) >= _THREAT_LEVELS.index(threshold)
    except ValueError:
        return False


class BenchmarkRunner:
    """Run benchmark samples through prompt-guard scan endpoint."""

    def __init__(
        self,
        endpoint: str | None = None,
        threshold: str = "medium",
    ):
        self._threshold = threshold
        self._endpoint = endpoint
        self._client = None
        self._test_client = None

    def _get_test_client(self):
        """Lazily build in-process FastAPI TestClient."""
        if self._test_client is not None:
            return self._test_client

        from collections import defaultdict
        from contextlib import asynccontextmanager

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.adapters.clock import SystemClockAdapter
        from src.detectors.engine import DetectionEngine
        from src.middleware.app import (
            health_check,
            scan_content,
            sanitise_content,
            get_stats,
        )
        from src.sanitizers.content_sanitizer import ContentSanitiser
        from tests.helpers.fakes import NullAuditAdapter, build_default_registry

        clock = SystemClockAdapter()
        audit = NullAuditAdapter()
        registry = build_default_registry()
        engine = DetectionEngine(clock=clock, registry=registry)
        sanitiser = ContentSanitiser()

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            app.state.config = {}
            app.state.clock = clock
            app.state.audit = audit
            app.state.engine = engine
            app.state.sanitiser = sanitiser
            app.state.start_time = clock.now()
            app.state.stats = defaultdict(int)
            yield

        app = FastAPI(lifespan=lifespan)
        app.post("/scan")(scan_content)
        app.post("/sanitise")(sanitise_content)
        app.get("/health")(health_check)
        app.get("/stats")(get_stats)

        self._test_client = TestClient(app)
        self._test_client.__enter__()
        return self._test_client

    def _scan(self, text: str) -> dict:
        """Post a scan request and return the response JSON."""
        payload = {"content": text}

        if self._endpoint:
            import httpx

            api_key = os.environ.get("PROMPT_GUARD_API_KEY")
            path = "/v1/scan" if api_key else "/scan"
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            resp = httpx.post(
                f"{self._endpoint}{path}",
                json=payload,
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        else:
            client = self._get_test_client()
            resp = client.post("/scan", json=payload)
            resp.raise_for_status()
            return resp.json()

    def run_dataset(
        self,
        adapter: DatasetAdapter,
        cache_dir: Path,
        limit: int | None = None,
    ) -> list[ScanOutcome]:
        """Run all samples from a dataset and return outcomes."""
        samples = adapter.load_samples(cache_dir)
        if limit:
            samples = samples[:limit]

        total = len(samples)
        outcomes: list[ScanOutcome] = []
        start = time.monotonic()

        for i, sample in enumerate(samples):
            t0 = time.monotonic()
            try:
                result = self._scan(sample.text)
                latency = (time.monotonic() - t0) * 1000

                threat_level = result.get("threat_level", "clean")
                predicted = _level_at_or_above(threat_level, self._threshold)

                outcomes.append(
                    ScanOutcome(
                        sample=sample,
                        predicted_malicious=predicted,
                        threat_level=threat_level,
                        threat_score=result.get("threat_score", 0.0),
                        findings=result.get("findings", []),
                        latency_ms=latency,
                    )
                )
            except Exception as e:
                sys.stderr.write(f"\n  Error on sample {i}: {e}\n")
                outcomes.append(
                    ScanOutcome(
                        sample=sample,
                        predicted_malicious=False,
                        threat_level="error",
                        threat_score=0.0,
                        latency_ms=(time.monotonic() - t0) * 1000,
                    )
                )

            # Progress
            if (i + 1) % 50 == 0 or (i + 1) == total:
                elapsed = time.monotonic() - start
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                sys.stdout.write(
                    f"\r  [{adapter.name}] {i + 1}/{total}"
                    f" ({rate:.0f} samples/sec)"
                )
                sys.stdout.flush()

        sys.stdout.write("\n")
        return outcomes

    def close(self):
        """Clean up resources."""
        if self._test_client is not None:
            self._test_client.__exit__(None, None, None)
            self._test_client = None
