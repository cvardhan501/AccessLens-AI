"""FastAPI web server and REST API for AccessLens AI dashboard.

Exposes endpoints for triggering real Playwright + axe-core scans,
retrieving scan history, downloading JSON reports, and enforcing strict
server-side URL validation and SSRF defenses.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import time
from typing import Any
from urllib.parse import unquote

logger = logging.getLogger("accesslens.server")

from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import load_config
from .db import clear_history, delete_scan, get_history, get_history_count, get_scan, init_db, save_scan
from .decider import AccessibilityDecider, DeciderError, DecisionResult, get_static_rule_guidance
from .models import WCAG_DISCLAIMER, ScanReport
from .scanner import AccessibilityScanner
from .security import SecurityError, URLValidator
from .workflow import execute_workflow


# Directory constants
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

# Concurrency & Rate Limiting Controls
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "1"))
SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

RATE_LIMIT_WINDOW_SECONDS = 60.0
MAX_REQUESTS_PER_WINDOW = 15
_ip_request_timestamps: dict[str, list[float]] = defaultdict(list)
_rate_limit_lock = asyncio.Lock()


def check_rate_limit(client_ip: str) -> bool:
    """Check sliding window rate limit for client IP. Returns True if permitted."""
    now = time.time()
    timestamps = _ip_request_timestamps[client_ip]
    # Prune expired timestamps
    _ip_request_timestamps[client_ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW_SECONDS]
    if len(_ip_request_timestamps[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        return False
    _ip_request_timestamps[client_ip].append(now)
    return True


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Target public HTTP/HTTPS URL")
    timeout: float = Field(default=25.0, ge=5.0, le=60.0, description="Scan timeout in seconds (5-60s)")
    allow_local: bool = Field(default=False, description="Developer flag to permit local endpoints (defaults False)")


class AnalyzeFindingRequest(BaseModel):
    rule_id: str = Field(..., min_length=1, max_length=100)
    impact: str = Field(default="moderate", max_length=50)
    description: str = Field(default="", max_length=1000)
    target: list[str] | str = Field(default_factory=list)
    html: str = Field(default="", max_length=5000)
    failure_summary: str = Field(default="", max_length=2000)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on server startup."""
    init_db()
    yield


app = FastAPI(
    title="AccessLens AI",
    description="Deterministic accessibility auditing powered by Playwright, axe-core, and Strands Decider 2B (Decider-only configuration).",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static assets
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the primary AccessLens AI single-page dashboard HTML."""
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dashboard frontend assets not found.",
        )
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))


def resolve_secure_fixture_path(fixture_name_or_url: str) -> tuple[Path, str]:
    """Safely resolve a civic fixture candidate path with strict directory containment.

    Enforces that the resolved target:
    1. Resides strictly within FIXTURES_DIR.resolve() using Path.is_relative_to().
    2. Does not follow symlinks outside the fixtures root.
    3. Prohibits directory traversal ('..', backslashes, absolute paths, null bytes).
    4. Is a regular file (not a directory or special device).

    Returns (resolved_file_path, fixture_filename).
    Raises HTTPException(400) on traversal/malformed input, or HTTPException(404) if not found.
    """
    root_dir = FIXTURES_DIR.resolve()

    # Extract raw identifier from fixture: scheme or /fixtures/ URL segment
    raw = fixture_name_or_url.strip()
    if raw.startswith("fixture:"):
        raw = raw[len("fixture:"):].strip()
    elif "/fixtures/" in raw:
        raw = raw.split("/fixtures/")[-1].strip()

    # URL decode to catch encoded traversals like %2e%2e or %2f
    decoded = unquote(raw).strip()

    if "\0" in decoded:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid fixture path: null byte detected.",
        )

    # Reject path traversal tokens and absolute paths explicitly
    if (
        ".." in decoded
        or "/" in decoded
        or "\\" in decoded
        or (len(decoded) >= 2 and decoded[1] == ":")
        or decoded.startswith("/")
        or decoded.startswith("\\")
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid fixture path '{decoded}': directory traversal is prohibited.",
        )

    safe_filename = decoded if decoded.endswith(".html") else f"{decoded}.html"

    # Construct and resolve candidate path to canonical form (resolving symlinks)
    candidate_path = (root_dir / safe_filename).resolve()

    # Strict containment verification using Path.is_relative_to (Python 3.9+)
    try:
        is_contained = candidate_path.is_relative_to(root_dir) and candidate_path != root_dir
    except (ValueError, TypeError):
        is_contained = False

    if not is_contained:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid fixture path: target is outside authorized fixtures root.",
        )

    if not candidate_path.exists() or not candidate_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Local civic fixture '{safe_filename}' not found.",
        )

    return candidate_path, safe_filename


@app.get("/fixtures/{fixture_name}", response_class=HTMLResponse)
async def serve_fixture(fixture_name: str):
    """Serve safe local test fixtures for demonstration and offline auditing."""
    target_path, _ = resolve_secure_fixture_path(fixture_name)
    return HTMLResponse(content=target_path.read_text(encoding="utf-8"))


@app.get("/api/health")
async def health_check():
    """Health check endpoint exposing engine status, Decider status, and disclaimer."""
    cfg = load_config()
    safe_cfg = cfg.to_safe_dict()
    return {
        "status": "healthy",
        "mode": safe_cfg["mode"],
        "engine": "axe-core 4.13.0 via Playwright Chromium",
        "ssrf_protection": "enabled",
        "decider_configured": safe_cfg["decider_configured"],
        "bedrock_configured": safe_cfg["bedrock_configured"],
        "bedrock_enabled": safe_cfg["bedrock_enabled"],
        "disclaimer": WCAG_DISCLAIMER,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }



@app.get("/api/config")
async def get_configuration():
    """Return non-sensitive configuration status (secrets redacted)."""
    cfg = load_config()
    return cfg.to_safe_dict()


@app.post("/api/findings/analyze")
async def analyze_finding(payload: AnalyzeFindingRequest):
    """Execute Strands Decider 2B remediation action classification, followed
    by optional Amazon Bedrock contextual explanation if explicitly enabled.

    1. Strands Decider 2B always executes the core policy decision.
    2. Deterministic static WCAG guidance is always assembled.
    3. If LLM_PROVIDER=bedrock is configured and credentials are present,
       BedrockExplainer generates a contextual explanation conditioned on the
       Decider's decision, with graceful fallback on verification/network failure.
    """
    cfg = load_config()

    # 1. Strands Decider 2B Classification (Policy Gatekeeping Step)
    decider = AccessibilityDecider(config=cfg)
    try:
        dec_result = await asyncio.to_thread(
            decider.decide,
            rule_id=payload.rule_id,
            impact=payload.impact,
            description=payload.description,
            target=payload.target,
            html=payload.html,
            failure_summary=payload.failure_summary,
        )
        decision_data = dec_result.to_dict()
    except DeciderError as dec_err:
        is_missing_key = "not configured" in str(dec_err).lower()
        dec_result = DecisionResult(
            action="HUMAN_REVIEW",
            confidence=0.0,
            probabilities={},
            risk_level="high",
            rationale=f"Decider unavailable ({dec_err}); defaulted safely to HUMAN_REVIEW.",
            raw_choice="HUMAN_REVIEW",
            latency_ms=0.0,
            status="unavailable" if is_missing_key else "error",
            workflow_action="ESCALATE_HUMAN_REVIEW",
            evidence_sufficiency="ambiguous_or_high_risk",
        )
        decision_data = dec_result.to_dict()
        decision_data["error"] = str(dec_err)
    except Exception as exc:
        dec_result = DecisionResult(
            action="HUMAN_REVIEW",
            confidence=0.0,
            probabilities={},
            risk_level="high",
            rationale=f"Decider error ({exc}); defaulted safely to HUMAN_REVIEW.",
            raw_choice="HUMAN_REVIEW",
            latency_ms=0.0,
            status="error",
            workflow_action="ESCALATE_HUMAN_REVIEW",
            evidence_sufficiency="ambiguous_or_high_risk",
        )
        decision_data = dec_result.to_dict()
        decision_data["error"] = str(exc)

    # 2. Deterministic Static WCAG Guidance (Always Available as Foundation)
    static_guidance = get_static_rule_guidance(payload.rule_id, payload.failure_summary)

    # 3. Optional Amazon Bedrock Contextual Explanation
    # Disabled by default; only invoked when explicitly configured and enabled
    bedrock_res: dict[str, Any] | None = None
    explanation_data: dict[str, Any] = {
        "status": "disabled",
        "plain_language_explanation": "Generative LLM explanations are disabled in this Decider-only configuration.",
        "why_it_matters": static_guidance.get("summary", "Assistive technology users may experience navigation barriers."),
        "proposed_remediation": static_guidance.get("standard_fix", ""),
        "validation_steps": [static_guidance.get("verification_step", "Re-run axe-core audit to verify resolution.")],
        "limitations": "Advisory suggestion only. Code was not modified on the live website. axe-core results do not certify full WCAG compliance.",
        "confidence": "deterministic_static",
        "provider": "none",
        "is_llm_generated": False,
    }


    if cfg.llm_provider == "bedrock":
        if not cfg.has_bedrock_creds:
            explanation_data = {
                "status": "unconfigured",
                "plain_language_explanation": "AWS credentials not configured. Showing deterministic static WCAG guidance.",
                "why_it_matters": static_guidance.get("summary", ""),
                "proposed_remediation": static_guidance.get("standard_fix", ""),
                "validation_steps": [static_guidance.get("verification_step", "")],
                "limitations": "Advisory suggestion only. Code was not modified on the live website.",
                "confidence": "deterministic_static",
                "provider": "none",
                "is_llm_generated": False,
                "error": "AWS credentials not configured. Set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or AWS_PROFILE.",
            }
        else:
            # Lazy import keeps module-level server namespace clean and preserves offline tests
            from .bedrock import (
                BedrockExplainer,
                BedrockError,
                BedrockAccessDeniedError,
                BedrockAuthError,
                BedrockInvalidModelError,
                BedrockThrottlingError,
                BedrockTimeoutError,
            )

            explainer = BedrockExplainer(config=cfg)
            try:
                # Note on Thread Cancellation:
                # asyncio.wait_for cancels the waiting coroutine and immediately returns
                # the safe deterministic fallback to the client upon timeout.
                # Because Python cannot forcibly terminate an OS thread running synchronous
                # socket operations, the underlying thread may continue until its socket
                # timeout expires. BedrockExplainer sets finite connect/read timeouts in boto3.
                bedrock_res = await asyncio.wait_for(
                    asyncio.to_thread(
                        explainer.explain_finding,
                        rule_id=payload.rule_id,
                        impact=payload.impact,
                        description=payload.description,
                        target=payload.target,
                        html=payload.html,
                        failure_summary=payload.failure_summary,
                        action_decision=decision_data.get("action", "HUMAN_REVIEW"),
                    ),
                    timeout=25.0,
                )
                explanation_data = {
                    "status": "success",
                    "plain_language_explanation": bedrock_res.get("plain_language_explanation", ""),
                    "why_it_matters": bedrock_res.get("why_it_matters", ""),
                    "proposed_remediation": bedrock_res.get("proposed_remediation", ""),
                    "validation_steps": bedrock_res.get("validation_steps", []),
                    "limitations": bedrock_res.get("limitations", "Advisory suggestion only. Code was not modified on the live website."),
                    "confidence": bedrock_res.get("confidence", "high"),
                    "provider": "bedrock",
                    "model_id": bedrock_res.get("model_id", cfg.bedrock_model_id),
                    "latency_ms": bedrock_res.get("latency_ms", 0.0),
                    "is_llm_generated": True,
                }
            except (asyncio.TimeoutError, BedrockTimeoutError) as b_err:
                logger.warning("Amazon Bedrock explanation timed out: %s", b_err)
                explanation_data = {
                    "status": "fallback",
                    "plain_language_explanation": "Amazon Bedrock explanation timed out; showing deterministic static WCAG guidance.",
                    "why_it_matters": static_guidance.get("summary", ""),
                    "proposed_remediation": static_guidance.get("standard_fix", ""),
                    "validation_steps": [static_guidance.get("verification_step", "")],
                    "limitations": "Advisory suggestion only. Code was not modified on the live website.",
                    "confidence": "deterministic_static",
                    "provider": "static_fallback",
                    "is_llm_generated": False,
                    "fallback_reason": "timeout",
                    "error": "Bedrock request exceeded timeout limit.",
                }
            except BedrockAccessDeniedError as b_err:
                logger.warning("Amazon Bedrock access denied or account verification pending: %s", b_err)
                explanation_data = {
                    "status": "fallback",
                    "plain_language_explanation": "Amazon Bedrock access denied or account verification pending; showing deterministic static WCAG guidance.",
                    "why_it_matters": static_guidance.get("summary", ""),
                    "proposed_remediation": static_guidance.get("standard_fix", ""),
                    "validation_steps": [static_guidance.get("verification_step", "")],
                    "limitations": "Advisory suggestion only. Code was not modified on the live website.",
                    "confidence": "deterministic_static",
                    "provider": "static_fallback",
                    "is_llm_generated": False,
                    "fallback_reason": "access_denied_or_verification_pending",
                    "error": str(b_err),
                }
            except BedrockAuthError as b_err:
                logger.warning("Amazon Bedrock authentication failed (session expired or invalid credentials): %s", b_err)
                explanation_data = {
                    "status": "fallback",
                    "plain_language_explanation": "Amazon Bedrock session expired or credentials invalid; showing deterministic static WCAG guidance.",
                    "why_it_matters": static_guidance.get("summary", ""),
                    "proposed_remediation": static_guidance.get("standard_fix", ""),
                    "validation_steps": [static_guidance.get("verification_step", "")],
                    "limitations": "Advisory suggestion only. Code was not modified on the live website.",
                    "confidence": "deterministic_static",
                    "provider": "static_fallback",
                    "is_llm_generated": False,
                    "fallback_reason": "auth_error",
                    "error": str(b_err),
                }
            except BedrockInvalidModelError as b_err:
                logger.warning("Amazon Bedrock model or region error: %s", b_err)
                explanation_data = {
                    "status": "fallback",
                    "plain_language_explanation": "Configured Amazon Bedrock model or inference profile unavailable; showing deterministic static WCAG guidance.",
                    "why_it_matters": static_guidance.get("summary", ""),
                    "proposed_remediation": static_guidance.get("standard_fix", ""),
                    "validation_steps": [static_guidance.get("verification_step", "")],
                    "limitations": "Advisory suggestion only. Code was not modified on the live website.",
                    "confidence": "deterministic_static",
                    "provider": "static_fallback",
                    "is_llm_generated": False,
                    "fallback_reason": "invalid_model_or_region",
                    "error": str(b_err),
                }
            except BedrockThrottlingError as b_err:
                logger.warning("Amazon Bedrock rate limit exceeded: %s", b_err)
                explanation_data = {
                    "status": "fallback",
                    "plain_language_explanation": "Amazon Bedrock rate limit exceeded; showing deterministic static WCAG guidance.",
                    "why_it_matters": static_guidance.get("summary", ""),
                    "proposed_remediation": static_guidance.get("standard_fix", ""),
                    "validation_steps": [static_guidance.get("verification_step", "")],
                    "limitations": "Advisory suggestion only. Code was not modified on the live website.",
                    "confidence": "deterministic_static",
                    "provider": "static_fallback",
                    "is_llm_generated": False,
                    "fallback_reason": "throttled",
                    "error": str(b_err),
                }
            except (BedrockError, Exception) as b_err:
                logger.warning("Amazon Bedrock explanation service error: %s", b_err)
                explanation_data = {
                    "status": "fallback",
                    "plain_language_explanation": "Amazon Bedrock explanation unavailable; showing deterministic static WCAG guidance.",
                    "why_it_matters": static_guidance.get("summary", ""),
                    "proposed_remediation": static_guidance.get("standard_fix", ""),
                    "validation_steps": [static_guidance.get("verification_step", "")],
                    "limitations": "Advisory suggestion only. Code was not modified on the live website.",
                    "confidence": "deterministic_static",
                    "provider": "static_fallback",
                    "is_llm_generated": False,
                    "fallback_reason": "service_error",
                    "error": str(b_err),
                }

    # 4. Evidence-Gated Downstream Workflow Execution
    workflow_res = execute_workflow(
        decision=dec_result,
        rule_id=payload.rule_id,
        impact=payload.impact,
        description=payload.description,
        target=payload.target,
        html=payload.html,
        failure_summary=payload.failure_summary,
        static_guidance=static_guidance,
        bedrock_res=bedrock_res,
    )

    mode = "decider-with-bedrock" if explanation_data.get("status") == "success" else "decider-only"
    return {
        "status": "completed",
        "mode": mode,
        "rule_id": payload.rule_id,
        "decision": decision_data,
        "workflow": workflow_res.to_dict(),
        "static_guidance": static_guidance,
        "explanation": explanation_data,
        "disclaimer": "No website code has been changed. Suggested remediations are advisory.",
    }



@app.post("/api/scan")
async def run_scan(payload: ScanRequest, request: Request):
    """Execute a real, live axe-core accessibility scan against the target URL."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    async with _rate_limit_lock:
        if not check_rate_limit(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded ({MAX_REQUESTS_PER_WINDOW} scans/minute). Please wait before submitting another scan.",
            )

    # 0. Check for Local Fixture Mode (for reproducible demo & offline verification)
    is_fixture = payload.url.startswith("fixture:") or "/fixtures/" in payload.url
    target_fixture_path = None
    fixture_filename = ""
    if is_fixture:
        target_fixture_path, fixture_filename = resolve_secure_fixture_path(payload.url)

    # 1. Enforce Server-Side URL Validation & SSRF Guard BEFORE touching browser or acquiring semaphore
    allow_local = payload.allow_local or bool(os.environ.get("ACCESSLENS_ALLOW_LOCAL", False))
    validated_url = payload.url
    if not is_fixture:
        try:
            validated_url = URLValidator.validate_url(payload.url, allow_local=allow_local)
        except SecurityError as sec_err:
            # Save security block to history for audit trail
            block_report = ScanReport(
                status="SECURITY_BLOCKED",
                url=payload.url,
                final_url=payload.url,
                timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0.0,
                error=str(sec_err),
                error_category="SECURITY_VIOLATION",
            )
            scan_id = save_scan(block_report)
            block_dict = block_report.to_dict()
            block_dict["id"] = scan_id
            return block_dict

    # 2. Acquire semaphore to cap concurrent Playwright Chromium instances (both live and fixture scans)
    acquired = False
    try:
        try:
            # Wait up to 10 seconds for a scanner slot
            await asyncio.wait_for(SCAN_SEMAPHORE.acquire(), timeout=10.0)
            acquired = True
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="All scanner workers are currently busy. Please retry in a few moments.",
            )

        if is_fixture and target_fixture_path is not None:
            fixture_html = target_fixture_path.read_text(encoding="utf-8")
            scanner = AccessibilityScanner(headless=True)
            report = await asyncio.to_thread(
                scanner.scan_html,
                html_content=fixture_html,
                base_url=f"fixture://{fixture_filename}",
            )
            report.engine = "axe-core 4.13.0 via Playwright (Local Civic Fixture Mode)"
            scan_id = save_scan(report)
            result_dict = report.to_dict()
            result_dict["id"] = scan_id
            result_dict["is_fixture"] = True
            result_dict["fixture_name"] = fixture_filename
            return result_dict

        # 3. Execute real Playwright scan in threadpool to keep FastAPI async loop responsive
        scanner = AccessibilityScanner(
            timeout_seconds=payload.timeout,
            allow_local=allow_local,
            headless=True,
        )

        report = await asyncio.to_thread(scanner.scan_url, validated_url)

        # 4. Save to persistent SQLite database
        scan_id = save_scan(report)

        result_dict = report.to_dict()
        result_dict["id"] = scan_id
        return result_dict

    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise exc

        # Create structured failure report
        err_report = ScanReport(
            status="SCAN_ERROR",
            url=payload.url,
            final_url=payload.url,
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_ms=0.0,
            error=f"Internal scan execution error: {exc}",
            error_category="EXECUTION_ERROR",
        )
        scan_id = save_scan(err_report)
        err_dict = err_report.to_dict()
        err_dict["id"] = scan_id
        return err_dict

    finally:
        if acquired:
            SCAN_SEMAPHORE.release()


@app.get("/api/history")
async def list_history(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
):
    """Retrieve paginated scan history ordered newest first."""
    items = get_history(limit=limit, offset=offset, status_filter=status_filter)
    total = get_history_count(status_filter=status_filter)
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/scans/{scan_id}")
async def get_scan_by_id(scan_id: int):
    """Fetch complete scan report with all violation nodes by record ID."""
    report = get_scan(scan_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan #{scan_id} not found.")
    return report


@app.get("/api/scans/{scan_id}/download")
async def download_scan_report(scan_id: int):
    """Download scan results as a structured JSON file."""
    report = get_scan(scan_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan #{scan_id} not found.")

    json_str = json.dumps(report, indent=2)
    filename = f"accesslens-report-{scan_id}.json"
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.delete("/api/scans/{scan_id}")
async def delete_scan_by_id(scan_id: int):
    """Delete a scan record from local history."""
    success = delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan #{scan_id} not found.")
    return {"status": "deleted", "id": scan_id}


@app.delete("/api/history")
async def clear_all_history():
    """Clear all scan records from history."""
    count = clear_history()
    return {"status": "cleared", "records_removed": count}


def main():
    """Server entrypoint for running via `python -m accesslens.server`."""
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="AccessLens AI Web Dashboard Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--allow-local", action="store_true", default=False, help="Permit scanning local endpoints")
    args = parser.parse_args()

    if args.allow_local:
        os.environ["ACCESSLENS_ALLOW_LOCAL"] = "1"

    print(f"Starting AccessLens AI Dashboard on http://{args.host}:{args.port}")
    uvicorn.run("accesslens.server:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
