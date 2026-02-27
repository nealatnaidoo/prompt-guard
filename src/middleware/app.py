"""FastAPI middleware service — the main entry point.

Exposes:
  POST /scan       — scan content and return analysis
  POST /sanitise   — scan + sanitise content
  GET  /health     — service health check
  GET  /stats      — runtime statistics
"""

from __future__ import annotations

import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ..adapters.clock import SystemClockAdapter
from ..adapters.config import YamlFileConfigAdapter
from ..adapters.audit import JsonlFileAuditAdapter
from ..detectors.base import DetectorRegistry
from ..detectors.engine import DetectionEngine
from ..detectors.pattern_detector import PatternDetector
from ..detectors.heuristic_detector import HeuristicDetector
from ..detectors.semantic_detector import SemanticDetector
from ..detectors.entropy_detector import EntropyDetector
from ..detectors.provenance_detector import ProvenanceDetector
from ..models.schemas import (
    ContentSource,
    HealthResponse,
    PolicyAction,
    ScanRequest,
    ScanResult,
    ThreatLevel,
)
from ..ports.audit import AuditPort
from ..ports.clock import ClockPort
from ..sanitizers.content_sanitizer import ContentSanitiser

logger = structlog.get_logger(__name__)


# ── Lifespan (Composition Root) ───────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Composition root — creates all dependencies and wires them together."""
    # 1. Load config via ConfigPort adapter
    config_adapter = YamlFileConfigAdapter()
    config = config_adapter.load()

    # 2. Create ClockPort adapter
    clock: ClockPort = SystemClockAdapter()

    # 3. Create AuditPort adapter
    audit: AuditPort = JsonlFileAuditAdapter(config.get("audit", {}))

    # 4. Create and populate DetectorRegistry with default detectors
    detection_config = config.get("detection", {})
    registry = DetectorRegistry()
    registry.register(PatternDetector(detection_config.get("pattern_detector", {})))
    registry.register(HeuristicDetector(detection_config.get("heuristic_detector", {})))
    registry.register(SemanticDetector(detection_config.get("semantic_detector", {})))
    registry.register(EntropyDetector(detection_config.get("entropy_detector", {})))
    registry.register(ProvenanceDetector(detection_config.get("provenance_detector", {})))

    # 5. Create DetectionEngine with injected dependencies
    engine = DetectionEngine(
        config=detection_config,
        clock=clock,
        registry=registry,
    )

    # 6. Create ContentSanitiser
    sanitiser = ContentSanitiser(config.get("sanitiser", {}))

    # 7. Store in app.state
    app.state.config = config
    app.state.clock = clock
    app.state.audit = audit
    app.state.engine = engine
    app.state.sanitiser = sanitiser
    app.state.start_time = clock.now()
    app.state.stats = defaultdict(int)

    logger.info(
        "prompt_guard_started",
        detectors=engine.registry.names(),
        threshold=engine.threat_threshold,
    )
    yield
    # Shutdown
    logger.info("prompt_guard_stopped")


# ── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Prompt Guard",
    description="Adversarial-grade prompt injection & poisoning protection",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ── Request / Response models ───────────────────────────────────────────────

class SanitiseRequest(BaseModel):
    content: str = Field(..., max_length=500_000)
    source: str = "unknown"
    metadata: dict[str, Any] = Field(default_factory=dict)
    sanitise_level: str = "standard"  # minimal | standard | strict


class SanitiseResponse(BaseModel):
    scan_result: ScanResult
    sanitised_content: str
    changes: list[str]
    was_modified: bool


class StatsResponse(BaseModel):
    uptime_seconds: float
    total_scans: int
    threats_detected: int
    threat_rate: float
    by_level: dict[str, int]
    by_action: dict[str, int]
    avg_latency_ms: float


# ── Endpoints ───────────────────────────────────────────────────────────────

@app.post("/scan", response_model=ScanResult)
async def scan_content(request: ScanRequest, http_request: Request):
    """Scan content for injection, poisoning, and other threats."""
    try:
        state = http_request.app.state
        result = await state.engine.scan(request)

        # Audit log
        state.audit.log_scan(
            result,
            source_ip=http_request.client.host if http_request.client else None,
        )

        # Update stats
        state.stats["total_scans"] += 1
        state.stats[f"level_{result.threat_level.value}"] += 1
        state.stats[f"action_{result.action_taken.value}"] += 1
        if result.is_threat:
            state.stats["threats_detected"] += 1
        state.stats["total_latency_ms"] += result.latency_ms

        return result

    except Exception as e:
        logger.error("scan_error", error=str(e))
        raise HTTPException(status_code=500, detail="Internal scan error")


@app.post("/sanitise", response_model=SanitiseResponse)
async def sanitise_content(request: SanitiseRequest, http_request: Request):
    """Scan content and return sanitised version."""
    try:
        state = http_request.app.state

        # First scan
        scan_req = ScanRequest(
            content=request.content,
            source=ContentSource(request.source),
            metadata=request.metadata,
        )
        scan_result = await state.engine.scan(scan_req)

        # Then sanitise based on threat level
        if scan_result.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            level = "strict"
        elif scan_result.threat_level == ThreatLevel.MEDIUM:
            level = "standard"
        else:
            level = request.sanitise_level

        san_result = state.sanitiser.sanitise(request.content, level=level)

        # Update scan result with sanitised content
        scan_result.sanitised_content = san_result.content
        if san_result.was_modified:
            scan_result.action_taken = PolicyAction.SANITISE

        # Audit
        state.audit.log_scan(
            scan_result,
            source_ip=http_request.client.host if http_request.client else None,
            extra={"sanitise_changes": san_result.changes},
        )

        # Stats
        state.stats["total_scans"] += 1
        state.stats["sanitise_requests"] += 1

        return SanitiseResponse(
            scan_result=scan_result,
            sanitised_content=san_result.content,
            changes=san_result.changes,
            was_modified=san_result.was_modified,
        )

    except Exception as e:
        logger.error("sanitise_error", error=str(e))
        raise HTTPException(status_code=500, detail="Internal sanitise error")


@app.get("/health", response_model=HealthResponse)
async def health_check(http_request: Request):
    """Service health check."""
    state = http_request.app.state
    return HealthResponse(
        status="ok",
        detectors_loaded=len(state.engine.registry),
        uptime_seconds=state.clock.now() - state.start_time,
    )


@app.get("/stats", response_model=StatsResponse)
async def get_stats(http_request: Request):
    """Runtime statistics."""
    state = http_request.app.state
    total = state.stats.get("total_scans", 0)
    threats = state.stats.get("threats_detected", 0)
    total_latency = state.stats.get("total_latency_ms", 0)

    return StatsResponse(
        uptime_seconds=state.clock.now() - state.start_time,
        total_scans=total,
        threats_detected=threats,
        threat_rate=threats / total if total > 0 else 0.0,
        by_level={
            level.value: state.stats.get(f"level_{level.value}", 0)
            for level in ThreatLevel
        },
        by_action={
            action.value: state.stats.get(f"action_{action.value}", 0)
            for action in PolicyAction
        },
        avg_latency_ms=total_latency / total if total > 0 else 0.0,
    )
