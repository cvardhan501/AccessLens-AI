"""Deterministic offline unit and integration tests for Strands Decider 2B and Amazon Bedrock.

All external network and AWS calls are strictly mocked or blocked.
Zero live requests are made during these tests.
"""

import asyncio
from io import BytesIO
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error
import pytest
from fastapi.testclient import TestClient

from accesslens.bedrock import (
    AccessibilityExplanation,
    BedrockAccessDeniedError,
    BedrockAuthError,
    BedrockError,
    BedrockExplainer,
    BedrockInvalidModelError,
    BedrockThrottlingError,
    BedrockTimeoutError,
    BedrockUnavailableError,
)
from accesslens.config import Settings, load_config
from accesslens.decider import (
    AccessibilityDecider,
    DeciderAuthError,
    DeciderError,
    DeciderQuotaError,
    DeciderRateLimitError,
    DeciderUnavailableError,
    DeciderValidationError,
    DecisionResult,
    build_finding_state,
    get_static_rule_guidance,
    sanitize_html_evidence,
)
from accesslens.server import app
from accesslens.workflow import (
    AdvisoryRemediationPatch,
    CivicAuditorEscalationTicket,
    CivicContextEnrichmentReport,
    WorkflowExecutionResult,
    execute_workflow,
)



# ==============================================================================
# Configuration Tests
# ==============================================================================

def test_config_loads_defaults(monkeypatch):
    """Configuration loads standard defaults when no .env exists."""
    monkeypatch.delenv("DECIDER_API_KEY", raising=False)
    monkeypatch.delenv("DECIDER_MODE", raising=False)
    monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)

    cfg = load_config(env_path=Path("nonexistent_env_file.env"))
    assert cfg.decider_mode == "ugmdu"
    assert "da25tnxy06gjk.cloudfront.net" in cfg.decider_url
    assert cfg.decider_api_key == ""
    assert cfg.has_decider_creds is False
    assert cfg.bedrock_model_id == "us.amazon.nova-pro-v1:0"
    assert cfg.aws_region == "us-east-1"
    assert cfg.confidence_threshold == 0.70


def test_config_environment_variable_precedence(monkeypatch, tmp_path):
    """Explicitly set process environment variables take precedence over .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text("DECIDER_MODE=local\nDECIDER_API_KEY=env_file_key\n", encoding="utf-8")

    # Set process env explicitly
    monkeypatch.setenv("DECIDER_MODE", "ugmdu")
    monkeypatch.setenv("DECIDER_API_KEY", "process_key_wins")

    cfg = load_config(env_path=env_file)
    assert cfg.decider_mode == "ugmdu"
    assert cfg.decider_api_key == "process_key_wins"


def test_config_redacts_credentials(monkeypatch):
    """Secrets must be redacted in string representations and safe dictionary exports."""
    secret_key = "super_secret_decider_token_12345"
    monkeypatch.setenv("DECIDER_API_KEY", secret_key)
    cfg = load_config(env_path=Path("nonexistent.env"))

    # __repr__ check
    rep = repr(cfg)
    assert secret_key not in rep
    assert "supe..." in cfg.masked_decider_api_key
    assert "...2345" in cfg.masked_decider_api_key

    # to_safe_dict check
    safe_dict = cfg.to_safe_dict()
    assert secret_key not in str(safe_dict)
    assert safe_dict["decider_api_key"] == cfg.masked_decider_api_key
    assert safe_dict["decider_configured"] is True


# ==============================================================================
# Evidence Sanitization Tests
# ==============================================================================

def test_evidence_sanitization_strips_scripts_and_caps_length():
    """HTML sanitizer removes scripts, strips potential tokens, and truncates length."""
    raw = (
        '<div><script>alert("xss")</script><img src="hero.png?token=SECRET_JWT_TOKEN_12345" '
        'alt="" id="hero"><style>body { color: red; }</style></div>'
    )
    sanitized = sanitize_html_evidence(raw, max_chars=120)
    assert "<script>" not in sanitized
    assert "alert" not in sanitized
    assert "<style>" not in sanitized
    assert "SECRET_JWT_TOKEN_12345" not in sanitized
    assert "token=[REDACTED]" in sanitized
    assert len(sanitized) <= 150  # includes ...[truncated]


def test_build_finding_state_structure():
    """State builder produces structured, bounded text for the Decider."""
    state = build_finding_state(
        rule_id="image-alt",
        impact="critical",
        description="Images must have alternate text",
        target=["#broken-hero", ".hero-img"],
        html='<img id="broken-hero" src="photo.jpg">',
        failure_summary="Fix any of the following: Element does not have an alt attribute",
    )
    assert "ACCESSIBILITY AUDIT FINDING:" in state
    assert "- Rule ID: image-alt" in state
    assert "- Severity Impact: critical" in state
    assert "#broken-hero, .hero-img" in state
    assert "photo.jpg" in state


# ==============================================================================
# Strands Decider 2B Unit Tests (Mocked Transport)
# ==============================================================================

def test_decider_raises_auth_error_when_key_missing():
    """Calling decider in hosted mode without API key raises DeciderAuthError immediately."""
    cfg = Settings(
        decider_mode="ugmdu",
        decider_url="https://test.decider",
        decider_api_key="",
        llm_provider="bedrock",
        aws_region="us-east-1",
        bedrock_model_id="us.amazon.nova-pro-v1:0",
        bedrock_small_model_id="us.amazon.nova-micro-v1:0",
        bedrock_medium_model_id="us.amazon.nova-lite-v1:0",
        bedrock_large_model_id="us.amazon.nova-pro-v1:0",
    )
    decider = AccessibilityDecider(config=cfg)
    with pytest.raises(DeciderAuthError, match="DECIDER_API_KEY is not configured"):
        decider.decide("image-alt", "critical", "desc", "#img", "<img>", "missing alt")


def test_decider_wire_format_and_response_parsing():
    """Decider constructs correct POST /v1/decide request and parses answers."""
    cfg = Settings(
        decider_mode="ugmdu",
        decider_url="https://da25tnxy06gjk.cloudfront.net",
        decider_api_key="ugmdu-test-key-9999",
        llm_provider="bedrock",
        aws_region="us-east-1",
        bedrock_model_id="us.amazon.nova-pro-v1:0",
        bedrock_small_model_id="us.amazon.nova-micro-v1:0",
        bedrock_medium_model_id="us.amazon.nova-lite-v1:0",
        bedrock_large_model_id="us.amazon.nova-pro-v1:0",
        confidence_threshold=0.70,
    )
    decider = AccessibilityDecider(config=cfg)

    mock_response_data = {
        "answers": {
            "action": {
                "type": "choice",
                "choice": "AUTO_FIX_CANDIDATE",
                "confidence": 0.92,
                "probabilities": {
                    "AUTO_FIX_CANDIDATE": 0.92,
                    "EXPLAIN_ONLY": 0.05,
                    "HUMAN_REVIEW": 0.03,
                },
            },
            "risk_level": {
                "type": "score",
                "score": 0.2,
                "label": "low",
                "probabilities": {"low": 0.85, "medium": 0.10, "high": 0.05, "critical": 0.0},
            },
        },
        "latency_ms": 145.2,
    }

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_response_data).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        result = decider.decide(
            rule_id="image-alt",
            impact="minor",  # minor impact allows auto-fix
            description="Images must have alternate text",
            target="#test-img",
            html='<img src="test.png">',
            failure_summary="missing alt",
        )

        assert mock_urlopen.call_count == 1
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://da25tnxy06gjk.cloudfront.net/v1/decide"
        assert req.headers["Authorization"] == "Bearer ugmdu-test-key-9999"
        assert req.headers["Content-type"] == "application/json"

        body = json.loads(req.data.decode("utf-8"))
        assert "ACCESSIBILITY AUDIT FINDING:" in body["state"]
        assert "action" in body["questions"]
        assert "risk_level" in body["questions"]

        # Validate parsed result
        assert result.action == "AUTO_FIX_CANDIDATE"
        assert result.confidence == 0.92
        assert result.risk_level == "low"
        assert "Low-risk deterministic fix candidate" in result.rationale


# ==============================================================================
# Conservative Safety & Threshold Tests
# ==============================================================================

def test_low_confidence_forces_human_review():
    """Decider result with confidence below threshold (0.70) must demote to HUMAN_REVIEW."""
    cfg = Settings(
        decider_mode="ugmdu",
        decider_url="https://decider",
        decider_api_key="test-key",
        llm_provider="bedrock",
        aws_region="us-east-1",
        bedrock_model_id="us.amazon.nova-pro-v1:0",
        bedrock_small_model_id="us.amazon.nova-micro-v1:0",
        bedrock_medium_model_id="us.amazon.nova-lite-v1:0",
        bedrock_large_model_id="us.amazon.nova-pro-v1:0",
        confidence_threshold=0.75,
    )
    decider = AccessibilityDecider(config=cfg)

    mock_resp_data = {
        "answers": {
            "action": {
                "type": "choice",
                "choice": "AUTO_FIX_CANDIDATE",
                "confidence": 0.60,  # below 0.75
                "probabilities": {"AUTO_FIX_CANDIDATE": 0.60, "HUMAN_REVIEW": 0.40},
            },
            "risk_level": {"type": "score", "label": "medium"},
        }
    }
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_resp_data).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = decider.decide("color-contrast", "moderate", "Contrast check", "#text", "<span>", "low contrast")
        assert res.action == "HUMAN_REVIEW"
        assert "below safety threshold" in res.rationale


def test_critical_severity_demotes_auto_fix_below_85_confidence():
    """Critical or serious issues require >= 85% confidence for AUTO_FIX_CANDIDATE."""
    cfg = Settings(
        decider_mode="ugmdu",
        decider_url="https://decider",
        decider_api_key="test-key",
        llm_provider="bedrock",
        aws_region="us-east-1",
        bedrock_model_id="us.amazon.nova-pro-v1:0",
        bedrock_small_model_id="us.amazon.nova-micro-v1:0",
        bedrock_medium_model_id="us.amazon.nova-lite-v1:0",
        bedrock_large_model_id="us.amazon.nova-pro-v1:0",
        confidence_threshold=0.70,
    )
    decider = AccessibilityDecider(config=cfg)

    mock_resp_data = {
        "answers": {
            "action": {
                "type": "choice",
                "choice": "AUTO_FIX_CANDIDATE",
                "confidence": 0.80,  # above 0.70 but below 0.85 for CRITICAL
                "probabilities": {"AUTO_FIX_CANDIDATE": 0.80, "HUMAN_REVIEW": 0.20},
            },
            "risk_level": {"type": "score", "label": "high"},
        }
    }
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_resp_data).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = decider.decide("button-name", "critical", "Button must have name", "button", "<button>", "no name")
        assert res.action == "HUMAN_REVIEW"
        assert "CRITICAL severity; candidate demoted" in res.rationale


# ==============================================================================
# Decider Error Handling Tests
# ==============================================================================

def test_decider_http_error_mappings():
    """HTTP errors are cleanly mapped to typed Decider exceptions."""
    cfg = Settings(
        decider_mode="ugmdu",
        decider_url="https://decider",
        decider_api_key="bad-key",
        llm_provider="bedrock",
        aws_region="us-east-1",
        bedrock_model_id="us.amazon.nova-pro-v1:0",
        bedrock_small_model_id="us.amazon.nova-micro-v1:0",
        bedrock_medium_model_id="us.amazon.nova-lite-v1:0",
        bedrock_large_model_id="us.amazon.nova-pro-v1:0",
    )
    decider = AccessibilityDecider(config=cfg)

    # 401 Auth Error
    err401 = urllib.error.HTTPError("https://decider", 401, "Unauthorized", {}, BytesIO(b"Invalid key"))
    with patch("urllib.request.urlopen", side_effect=err401):
        with pytest.raises(DeciderAuthError):
            decider.decide("rule", "minor", "d", "t", "h", "f")

    # 402 Quota Error
    err402 = urllib.error.HTTPError("https://decider", 402, "Payment Required", {}, BytesIO(b"Monthly quota reached"))
    with patch("urllib.request.urlopen", side_effect=err402):
        with pytest.raises(DeciderQuotaError):
            decider.decide("rule", "minor", "d", "t", "h", "f")

    # 429 Rate Limit
    err429 = urllib.error.HTTPError("https://decider", 429, "Too Many Requests", {}, BytesIO(b"Rate limit exceeded"))
    with patch("urllib.request.urlopen", side_effect=err429):
        with pytest.raises(DeciderRateLimitError):
            decider.decide("rule", "minor", "d", "t", "h", "f")

    # 503 Unavailable
    err503 = urllib.error.HTTPError("https://decider", 503, "Service Unavailable", {}, BytesIO(b"Server overloaded"))
    with patch("urllib.request.urlopen", side_effect=err503):
        with pytest.raises(DeciderUnavailableError):
            decider.decide("rule", "minor", "d", "t", "h", "f")

    # Connection Timeout
    with patch("urllib.request.urlopen", side_effect=TimeoutError("Request timed out")):
        with pytest.raises(DeciderUnavailableError):
            decider.decide("rule", "minor", "d", "t", "h", "f")


# ==============================================================================
# Amazon Bedrock Service Tests (Mocked Strands Agent)
# ==============================================================================

def test_bedrock_raises_auth_error_when_credentials_missing(monkeypatch):
    """Calling Bedrock explainer without AWS credentials raises BedrockAuthError."""
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent_credentials_file")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent_config_file")

    explainer = BedrockExplainer()
    with pytest.raises(BedrockAuthError, match="AWS credentials not configured"):
        explainer.explain_finding("image-alt", "critical", "Missing alt", "#img", "<img>", "missing")


def test_bedrock_structured_explanation_with_mocked_agent(monkeypatch):
    """Bedrock explainer constructs Strands Agent and parses structured output."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_secret")

    explainer = BedrockExplainer()

    mock_explanation = AccessibilityExplanation(
        plain_language_explanation="The <img> element lacks alternate text describing the image.",
        why_it_matters="Screen readers cannot convey the graphic to visually impaired users.",
        proposed_remediation='<img id="hero" src="hero.png" alt="Company logo">',
        validation_steps=["Inspect the DOM to verify alt attribute.", "Run axe-core scan."],
        limitations="Advisory suggestion only. Code was not modified on the live website.",
        confidence="high",
    )

    mock_agent_result = MagicMock()
    mock_agent_result.structured_output = mock_explanation

    mock_agent_instance = MagicMock()
    mock_agent_instance.return_value = mock_agent_result

    with patch("strands.models.BedrockModel") as mock_model_cls, patch("strands.Agent", return_value=mock_agent_instance) as mock_agent_cls:
        res = explainer.explain_finding(
            rule_id="image-alt",
            impact="critical",
            description="Images must have alternate text",
            target="#hero",
            html='<img id="hero" src="hero.png">',
            failure_summary="Element does not have an alt attribute",
            action_decision="HUMAN_REVIEW",
        )

        assert mock_model_cls.call_count == 1
        assert mock_agent_cls.call_count == 1

        prompt_sent = mock_agent_instance.call_args[0][0]
        assert "Rule ID: image-alt" in prompt_sent
        assert "Strands Decider Recommendation: HUMAN_REVIEW" in prompt_sent

        assert res["status"] == "success"
        assert "Screen readers cannot convey" in res["why_it_matters"]
        assert 'alt="Company logo"' in res["proposed_remediation"]
        assert len(res["validation_steps"]) == 2
        assert "not modified on the live website" in res["limitations"]


# ==============================================================================
# REST API Endpoint Tests (/api/findings/analyze, /api/health, /api/config)
# ==============================================================================

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_api_config_endpoint_redacts_keys(client, monkeypatch):
    """GET /api/config returns configuration without raw secrets."""
    monkeypatch.setenv("DECIDER_API_KEY", "secret_decider_key_abc_123")
    resp = client.get("/api/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "secret_decider_key_abc_123" not in str(data)
    assert data["decider_configured"] is True
    assert "..." in data["decider_api_key"]


def test_api_findings_analyze_unconfigured_graceful_handling(client, monkeypatch):
    """When Decider credentials are not set, endpoint returns 200 with typed unavailable status."""
    monkeypatch.setenv("LLM_PROVIDER", "disabled")
    monkeypatch.setenv("DECIDER_API_KEY", "")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    payload = {
        "rule_id": "image-alt",
        "impact": "critical",
        "description": "Images must have alternate text",
        "target": ["#broken"],
        "html": "<img src='test.png'>",
        "failure_summary": "Missing alt attribute",
    }
    resp = client.post("/api/findings/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "completed"
    assert data["mode"] == "decider-only"
    assert data["rule_id"] == "image-alt"
    assert data["decision"]["status"] == "unavailable"
    assert data["decision"]["action"] == "HUMAN_REVIEW"  # Safe conservative default
    assert "DECIDER_API_KEY" in data["decision"]["error"]

    assert data["explanation"]["status"] == "disabled"
    assert "disabled in this Decider-only configuration" in data["explanation"]["plain_language_explanation"]
    assert data["static_guidance"]["rule_id"] == "image-alt"
    assert "1.1.1 Non-text Content" in data["static_guidance"]["wcag_criterion"]
    assert "No website code has been changed" in data["disclaimer"]


def test_api_findings_analyze_with_mocked_services(client, monkeypatch):
    """POST /api/findings/analyze succeeds with Decider 2B decision and static WCAG guidance."""
    monkeypatch.setenv("LLM_PROVIDER", "disabled")
    monkeypatch.setenv("DECIDER_API_KEY", "valid_key")

    mock_decision = DecisionResult(
        action="AUTO_FIX_CANDIDATE",
        confidence=0.91,
        probabilities={"AUTO_FIX_CANDIDATE": 0.91, "HUMAN_REVIEW": 0.09},
        risk_level="low",
        rationale="Deterministic fix candidate identified.",
        raw_choice="AUTO_FIX_CANDIDATE",
        latency_ms=110.0,
    )

    with patch.object(AccessibilityDecider, "decide", return_value=mock_decision):
        payload = {
            "rule_id": "image-alt",
            "impact": "minor",
            "description": "Images must have alternate text",
            "target": ["#hero"],
            "html": "<img src='hero.png'>",
            "failure_summary": "Missing alt",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["mode"] == "decider-only"
        assert data["decision"]["action"] == "AUTO_FIX_CANDIDATE"
        assert data["decision"]["confidence"] == 0.91
        assert data["static_guidance"]["rule_id"] == "image-alt"
        assert data["static_guidance"]["is_llm_generated"] is False
        assert data["explanation"]["status"] == "disabled"
        assert data["disclaimer"] == "No website code has been changed. Suggested remediations are advisory."


# ==============================================================================
# Decider-Only & Bedrock Absence Verification Tests
# ==============================================================================

def test_analyze_endpoint_works_without_aws_credentials(client, monkeypatch):
    """POST /api/findings/analyze operates completely without any AWS credentials."""
    # Completely purge all AWS environment variables
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "AWS_DEFAULT_REGION", "AWS_REGION", "AWS_BEARER_TOKEN_BEDROCK"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent_credentials_file")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent_config_file")

    monkeypatch.setenv("LLM_PROVIDER", "disabled")
    monkeypatch.setenv("DECIDER_API_KEY", "test_hosted_key")

    mock_decision = DecisionResult(
        action="EXPLAIN_ONLY",
        confidence=0.82,
        probabilities={"EXPLAIN_ONLY": 0.82, "HUMAN_REVIEW": 0.18},
        risk_level="medium",
        rationale="Educational explanation recommended.",
        raw_choice="EXPLAIN_ONLY",
        latency_ms=95.0,
    )

    with patch.object(AccessibilityDecider, "decide", return_value=mock_decision):
        payload = {
            "rule_id": "button-name",
            "impact": "serious",
            "description": "Buttons must have discernible text",
            "target": ["button.nav"],
            "html": "<button class='nav'></button>",
            "failure_summary": "No accessible name found",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["status"] == "completed"
        assert data["mode"] == "decider-only"
        assert data["decision"]["action"] == "EXPLAIN_ONLY"
        assert data["static_guidance"]["rule_id"] == "button-name"
        assert "4.1.2 Name, Role, Value" in data["static_guidance"]["wcag_criterion"]
        assert data["explanation"]["status"] == "disabled"


def test_no_bedrock_model_instantiated_during_analyze(client, monkeypatch):
    """Verify that strands.models.BedrockModel is NEVER instantiated during /api/findings/analyze."""
    import accesslens.server as srv

    # Confirm BedrockExplainer is not imported into server module namespace
    assert "BedrockExplainer" not in dir(srv), "BedrockExplainer must not be imported in server.py"

    monkeypatch.setenv("LLM_PROVIDER", "disabled")
    monkeypatch.setenv("DECIDER_API_KEY", "test_key")

    mock_decision = DecisionResult(
        action="HUMAN_REVIEW",
        confidence=0.65,
        probabilities={"HUMAN_REVIEW": 0.65, "EXPLAIN_ONLY": 0.35},
        risk_level="high",
        rationale="Low confidence routed to human review.",
        raw_choice="HUMAN_REVIEW",
        latency_ms=120.0,
    )

    with patch("strands.models.BedrockModel") as mock_bedrock_model, \
         patch.object(AccessibilityDecider, "decide", return_value=mock_decision):

        payload = {
            "rule_id": "color-contrast",
            "impact": "serious",
            "description": "Elements must have sufficient color contrast",
            "target": ["span.sub"],
            "html": "<span class='sub'>Text</span>",
            "failure_summary": "Contrast ratio 2.1:1 is below 4.5:1",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200

        # BedrockModel must NEVER have been called or instantiated
        assert mock_bedrock_model.call_count == 0, "BedrockModel was unexpectedly instantiated during /api/findings/analyze"


def test_rejected_decider_credentials_handled_safely(client, monkeypatch):
    """HTTP 401 Unauthorized from Decider defaults safely to HUMAN_REVIEW with error status."""
    monkeypatch.setenv("DECIDER_API_KEY", "invalid_rejected_token")

    err401 = urllib.error.HTTPError("https://decider", 401, "Unauthorized", {}, BytesIO(b"Invalid API token"))

    with patch("urllib.request.urlopen", side_effect=err401):
        payload = {
            "rule_id": "link-name",
            "impact": "moderate",
            "description": "Links must have discernible text",
            "target": ["a.icon-link"],
            "html": "<a href='#' class='icon-link'></a>",
            "failure_summary": "Element is in tab order and does not have accessible text",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["decision"]["status"] == "error"
        assert data["decision"]["action"] == "HUMAN_REVIEW"
        assert "401" in data["decision"]["error"]
        assert data["static_guidance"]["rule_id"] == "link-name"


def test_decider_quota_exhausted_handled_safely(client, monkeypatch):
    """HTTP 402 Payment Required from Decider defaults safely to HUMAN_REVIEW with error status."""
    monkeypatch.setenv("DECIDER_API_KEY", "quota_exhausted_token")

    err402 = urllib.error.HTTPError("https://decider", 402, "Payment Required", {}, BytesIO(b"Monthly limit exceeded"))

    with patch("urllib.request.urlopen", side_effect=err402):
        payload = {
            "rule_id": "document-title",
            "impact": "serious",
            "description": "Documents must have <title> element",
            "target": ["html"],
            "html": "<html><head></head></html>",
            "failure_summary": "Document does not have a title element",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["decision"]["status"] == "error"
        assert data["decision"]["action"] == "HUMAN_REVIEW"
        assert "402" in data["decision"]["error"]


def test_static_wcag_guidance_for_common_and_fallback_rules():
    """Deterministic static guidance catalog provides grounded WCAG criteria and standard fixes."""
    # Test cataloged rule
    alt_guide = get_static_rule_guidance("image-alt")
    assert alt_guide["rule_id"] == "image-alt"
    assert "1.1.1 Non-text Content" in alt_guide["wcag_criterion"]
    assert 'alt="Concise description' in alt_guide["standard_fix"]
    assert alt_guide["is_llm_generated"] is False
    assert alt_guide["source"] == "static_wcag_knowledge_base"

    # Test cataloged rule: button-name
    btn_guide = get_static_rule_guidance("button-name")
    assert "4.1.2 Name, Role, Value" in btn_guide["wcag_criterion"]
    assert 'aria-label="Descriptive action name"' in btn_guide["standard_fix"]

    # Test uncatalogued rule with fallback
    fallback_guide = get_static_rule_guidance("custom-aria-widget-rule", "Widget must handle arrow keys")
    assert fallback_guide["rule_id"] == "custom-aria-widget-rule"
    assert fallback_guide["is_llm_generated"] is False
    assert fallback_guide["source"] == "static_wcag_fallback"
    assert "Widget must handle arrow keys" in fallback_guide["summary"]


# ==============================================================================
# Offline Mocked Tests: Optional Amazon Bedrock Integration
# ==============================================================================

def test_analyze_endpoint_bedrock_success_mocked(client, monkeypatch):
    """When LLM_PROVIDER=bedrock and credentials exist, BedrockExplainer generates contextual explanation conditioned on Decider."""
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_aws_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_aws_secret")
    monkeypatch.setenv("DECIDER_API_KEY", "mock_decider_key")

    mock_decision = DecisionResult(
        action="AUTO_FIX_CANDIDATE",
        confidence=0.91,
        probabilities={"AUTO_FIX_CANDIDATE": 0.91, "EXPLAIN_ONLY": 0.06, "HUMAN_REVIEW": 0.03},
        risk_level="low",
        rationale="Low-risk deterministic fix candidate identified.",
        raw_choice="AUTO_FIX_CANDIDATE",
        latency_ms=110.0,
    )

    mock_bedrock_output = {
        "plain_language_explanation": "The image element lacks an alternate text attribute.",
        "why_it_matters": "Screen reader users cannot identify the graphic content.",
        "proposed_remediation": '<img id="logo" src="logo.png" alt="Company Logo">',
        "validation_steps": ["Inspect DOM to verify alt attribute is non-empty.", "Re-scan with axe-core."],
        "limitations": "Advisory suggestion only. Code was not modified on the live website.",
        "confidence": "high",
        "model_id": "us.amazon.nova-pro-v1:0",
        "latency_ms": 320.5,
        "status": "success",
    }

    with patch.object(AccessibilityDecider, "decide", return_value=mock_decision), \
         patch("accesslens.bedrock.BedrockExplainer.explain_finding", return_value=mock_bedrock_output) as mock_explain:

        payload = {
            "rule_id": "image-alt",
            "impact": "critical",
            "description": "Images must have alternate text",
            "target": ["img#logo"],
            "html": '<img id="logo" src="logo.png">',
            "failure_summary": "Element does not have an alt attribute",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        # Decider decision is strictly preserved
        assert data["decision"]["action"] == "AUTO_FIX_CANDIDATE"
        assert data["decision"]["confidence"] == 0.91

        # Bedrock output is verified
        assert data["status"] == "completed"
        assert data["mode"] == "decider-with-bedrock"
        assert data["explanation"]["status"] == "success"
        assert data["explanation"]["provider"] == "bedrock"
        assert data["explanation"]["is_llm_generated"] is True
        assert data["explanation"]["proposed_remediation"] == '<img id="logo" src="logo.png" alt="Company Logo">'
        assert len(data["explanation"]["validation_steps"]) == 2

        # Static WCAG guidance is preserved
        assert data["static_guidance"]["rule_id"] == "image-alt"

        # Verify Decider action was passed to Bedrock
        assert mock_explain.call_count == 1
        assert mock_explain.call_args[1]["action_decision"] == "AUTO_FIX_CANDIDATE"


def test_analyze_endpoint_bedrock_disabled_mode(client, monkeypatch):
    """When LLM_PROVIDER is disabled (default), Bedrock is skipped and static guidance is returned."""
    monkeypatch.setenv("LLM_PROVIDER", "disabled")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_aws_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_aws_secret")
    monkeypatch.setenv("DECIDER_API_KEY", "mock_decider_key")

    mock_decision = DecisionResult(
        action="EXPLAIN_ONLY",
        confidence=0.80,
        probabilities={"EXPLAIN_ONLY": 0.80, "HUMAN_REVIEW": 0.20},
        risk_level="medium",
        rationale="Design context required.",
        raw_choice="EXPLAIN_ONLY",
        latency_ms=90.0,
    )

    with patch.object(AccessibilityDecider, "decide", return_value=mock_decision), \
         patch("accesslens.bedrock.BedrockExplainer.explain_finding") as mock_explain:

        payload = {
            "rule_id": "color-contrast",
            "impact": "serious",
            "description": "Text must have sufficient contrast",
            "target": ["p.desc"],
            "html": "<p class='desc'>Low contrast</p>",
            "failure_summary": "Contrast ratio 2.5:1",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["mode"] == "decider-only"
        assert data["decision"]["action"] == "EXPLAIN_ONLY"
        assert data["explanation"]["status"] == "disabled"
        assert data["explanation"]["is_llm_generated"] is False
        assert data["static_guidance"]["rule_id"] == "color-contrast"
        assert mock_explain.call_count == 0


def test_analyze_endpoint_bedrock_missing_credentials_fallback(client, monkeypatch):
    """When LLM_PROVIDER=bedrock but AWS credentials are absent, endpoint safely returns unconfigured status and static guidance."""
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("DECIDER_API_KEY", "mock_decider_key")
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "AWS_BEARER_TOKEN_BEDROCK"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent_credentials_file")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent_config_file")

    mock_decision = DecisionResult(
        action="HUMAN_REVIEW",
        confidence=0.60,
        probabilities={"HUMAN_REVIEW": 0.60},
        risk_level="high",
        rationale="Demoted to human review.",
        raw_choice="HUMAN_REVIEW",
        latency_ms=100.0,
    )

    with patch.object(AccessibilityDecider, "decide", return_value=mock_decision), \
         patch("accesslens.bedrock.BedrockExplainer.explain_finding") as mock_explain:

        payload = {
            "rule_id": "aria-roles",
            "impact": "critical",
            "description": "ARIA roles must be valid",
            "target": ["div.widget"],
            "html": "<div role='invalid'></div>",
            "failure_summary": "Unknown ARIA role",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["mode"] == "decider-only"
        assert data["decision"]["action"] == "HUMAN_REVIEW"
        assert data["explanation"]["status"] == "unconfigured"
        assert data["explanation"]["is_llm_generated"] is False
        assert "AWS credentials not configured" in data["explanation"]["error"]
        assert data["static_guidance"]["rule_id"] == "aria-roles"
        assert mock_explain.call_count == 0


def test_analyze_endpoint_bedrock_verification_access_denied_fallback(client, monkeypatch):
    """When Bedrock raises AccessDenied / account verification hold, endpoint safely falls back to static WCAG guidance without crashing."""
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_aws_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_aws_secret")
    monkeypatch.setenv("DECIDER_API_KEY", "mock_decider_key")

    mock_decision = DecisionResult(
        action="HUMAN_REVIEW",
        confidence=0.75,
        probabilities={"HUMAN_REVIEW": 0.75},
        risk_level="high",
        rationale="Human review required.",
        raw_choice="HUMAN_REVIEW",
        latency_ms=105.0,
    )

    with patch.object(AccessibilityDecider, "decide", return_value=mock_decision), \
         patch("accesslens.bedrock.BedrockExplainer.explain_finding", side_effect=BedrockAccessDeniedError("AccessDeniedException: Account verification pending")):

        payload = {
            "rule_id": "image-alt",
            "impact": "critical",
            "description": "Images must have alternate text",
            "target": ["img"],
            "html": "<img>",
            "failure_summary": "Missing alt",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["mode"] == "decider-only"
        assert data["decision"]["action"] == "HUMAN_REVIEW"
        assert data["explanation"]["status"] == "fallback"
        assert data["explanation"]["is_llm_generated"] is False
        assert data["explanation"]["fallback_reason"] == "access_denied_or_verification_pending"
        assert data["static_guidance"]["rule_id"] == "image-alt"


def test_analyze_endpoint_bedrock_timeout_fallback(client, monkeypatch):
    """When Bedrock call times out, endpoint safely catches TimeoutError and returns static guidance without crashing."""
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_aws_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_aws_secret")
    monkeypatch.setenv("DECIDER_API_KEY", "mock_decider_key")

    mock_decision = DecisionResult(
        action="AUTO_FIX_CANDIDATE",
        confidence=0.89,
        probabilities={"AUTO_FIX_CANDIDATE": 0.89},
        risk_level="low",
        rationale="Safe candidate.",
        raw_choice="AUTO_FIX_CANDIDATE",
        latency_ms=95.0,
    )

    with patch.object(AccessibilityDecider, "decide", return_value=mock_decision), \
         patch("accesslens.bedrock.BedrockExplainer.explain_finding", side_effect=asyncio.TimeoutError()):

        payload = {
            "rule_id": "button-name",
            "impact": "serious",
            "description": "Buttons must have text",
            "target": ["button"],
            "html": "<button></button>",
            "failure_summary": "Empty button",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["mode"] == "decider-only"
        assert data["decision"]["action"] == "AUTO_FIX_CANDIDATE"
        assert data["explanation"]["status"] == "fallback"
        assert data["explanation"]["is_llm_generated"] is False
        assert data["explanation"]["fallback_reason"] == "timeout"
        assert data["static_guidance"]["rule_id"] == "button-name"


def test_analyze_endpoint_bedrock_auth_error_fallback(client, monkeypatch):
    """When AWS credentials or SSO session is expired, endpoint safely returns auth_error fallback."""
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_aws_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_aws_secret")
    monkeypatch.setenv("DECIDER_API_KEY", "mock_decider_key")

    mock_decision = DecisionResult(
        action="HUMAN_REVIEW",
        confidence=0.72,
        probabilities={"HUMAN_REVIEW": 0.72},
        risk_level="high",
        rationale="Human review required.",
        raw_choice="HUMAN_REVIEW",
        latency_ms=105.0,
    )

    with patch.object(AccessibilityDecider, "decide", return_value=mock_decision), \
         patch("accesslens.bedrock.BedrockExplainer.explain_finding", side_effect=BedrockAuthError("Your session has expired. Please reauthenticate using 'aws login'.")):

        payload = {
            "rule_id": "image-alt",
            "impact": "critical",
            "description": "Images must have alternate text",
            "target": ["img"],
            "html": "<img>",
            "failure_summary": "Missing alt",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["mode"] == "decider-only"
        assert data["decision"]["action"] == "HUMAN_REVIEW"
        assert data["explanation"]["status"] == "fallback"
        assert data["explanation"]["fallback_reason"] == "auth_error"
        assert "session has expired" in data["explanation"]["error"]
        assert data["static_guidance"]["rule_id"] == "image-alt"


def test_analyze_endpoint_bedrock_invalid_model_fallback(client, monkeypatch):
    """When Bedrock model ID is invalid or unsupported in region, endpoint safely falls back."""
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_aws_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_aws_secret")
    monkeypatch.setenv("DECIDER_API_KEY", "mock_decider_key")

    mock_decision = DecisionResult(
        action="EXPLAIN_ONLY",
        confidence=0.85,
        probabilities={"EXPLAIN_ONLY": 0.85},
        risk_level="medium",
        rationale="Design explanation required.",
        raw_choice="EXPLAIN_ONLY",
        latency_ms=90.0,
    )

    with patch.object(AccessibilityDecider, "decide", return_value=mock_decision), \
         patch("accesslens.bedrock.BedrockExplainer.explain_finding", side_effect=BedrockInvalidModelError("ResourceNotFoundException: Model not found")):

        payload = {
            "rule_id": "color-contrast",
            "impact": "serious",
            "description": "Text must have contrast",
            "target": ["p"],
            "html": "<p>Low contrast</p>",
            "failure_summary": "Contrast 2.0:1",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["mode"] == "decider-only"
        assert data["decision"]["action"] == "EXPLAIN_ONLY"
        assert data["explanation"]["status"] == "fallback"
        assert data["explanation"]["fallback_reason"] == "invalid_model_or_region"
        assert data["static_guidance"]["rule_id"] == "color-contrast"


def test_analyze_endpoint_bedrock_throttled_fallback(client, monkeypatch):
    """When Bedrock returns ThrottlingException, endpoint safely falls back without crashing."""
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_aws_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_aws_secret")
    monkeypatch.setenv("DECIDER_API_KEY", "mock_decider_key")

    mock_decision = DecisionResult(
        action="HUMAN_REVIEW",
        confidence=0.68,
        probabilities={"HUMAN_REVIEW": 0.68},
        risk_level="high",
        rationale="Human review required.",
        raw_choice="HUMAN_REVIEW",
        latency_ms=85.0,
    )

    with patch.object(AccessibilityDecider, "decide", return_value=mock_decision), \
         patch("accesslens.bedrock.BedrockExplainer.explain_finding", side_effect=BedrockThrottlingError("ThrottlingException: Rate limit exceeded")):

        payload = {
            "rule_id": "link-name",
            "impact": "serious",
            "description": "Links must have discernible text",
            "target": ["a"],
            "html": "<a></a>",
            "failure_summary": "Empty link",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["mode"] == "decider-only"
        assert data["decision"]["action"] == "HUMAN_REVIEW"
        assert data["explanation"]["status"] == "fallback"
        assert data["explanation"]["fallback_reason"] == "throttled"
        assert data["static_guidance"]["rule_id"] == "link-name"


def test_bedrock_explainer_categorizes_session_expired(monkeypatch):
    """BedrockExplainer maps LoginRefreshRequired or session expired to BedrockAuthError."""
    cfg = Settings(
        decider_mode="ugmdu",
        decider_url="https://decider",
        decider_api_key="key",
        llm_provider="bedrock",
        aws_region="us-east-1",
        bedrock_model_id="us.amazon.nova-pro-v1:0",
        bedrock_small_model_id="us.amazon.nova-micro-v1:0",
        bedrock_medium_model_id="us.amazon.nova-lite-v1:0",
        bedrock_large_model_id="us.amazon.nova-pro-v1:0",
    )
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_secret")

    explainer = BedrockExplainer(config=cfg)

    with patch("strands.models.BedrockModel"), \
         patch("strands.Agent", side_effect=RuntimeError("LoginRefreshRequired: Your session has expired. Please reauthenticate using 'aws login'.")):
        with pytest.raises(BedrockAuthError, match="session has expired"):
            explainer.explain_finding(
                rule_id="image-alt",
                impact="critical",
                description="Images must have alternate text",
                target=["img"],
                html="<img>",
                failure_summary="Missing alt",
            )


def test_bedrock_explainer_categorizes_invalid_model(monkeypatch):
    """BedrockExplainer maps ResourceNotFoundException / ValidationException to BedrockInvalidModelError."""
    cfg = Settings(
        decider_mode="ugmdu",
        decider_url="https://decider",
        decider_api_key="key",
        llm_provider="bedrock",
        aws_region="us-east-1",
        bedrock_model_id="us.amazon.nova-pro-v1:0",
        bedrock_small_model_id="us.amazon.nova-micro-v1:0",
        bedrock_medium_model_id="us.amazon.nova-lite-v1:0",
        bedrock_large_model_id="us.amazon.nova-pro-v1:0",
    )
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_secret")

    explainer = BedrockExplainer(config=cfg)

    with patch("strands.models.BedrockModel"), \
         patch("strands.Agent", side_effect=Exception("ValidationException: Model id not supported")):
        with pytest.raises(BedrockInvalidModelError, match="not supported"):
            explainer.explain_finding(
                rule_id="image-alt",
                impact="critical",
                description="Images must have alternate text",
                target=["img"],
                html="<img>",
                failure_summary="Missing alt",
            )


def test_bedrock_explainer_handles_dictionary_or_unstructured_output(monkeypatch):
    """BedrockExplainer handles dict output and unstructured string fallback gracefully."""
    cfg = Settings(
        decider_mode="ugmdu",
        decider_url="https://decider",
        decider_api_key="key",
        llm_provider="bedrock",
        aws_region="us-east-1",
        bedrock_model_id="us.amazon.nova-pro-v1:0",
        bedrock_small_model_id="us.amazon.nova-micro-v1:0",
        bedrock_medium_model_id="us.amazon.nova-lite-v1:0",
        bedrock_large_model_id="us.amazon.nova-pro-v1:0",
    )
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_secret")

    explainer = BedrockExplainer(config=cfg)

    # 1. Test dict output
    mock_agent_dict = MagicMock()
    mock_agent_result_dict = MagicMock()
    mock_agent_result_dict.structured_output = {
        "plain_language_explanation": "Dict explanation",
        "why_it_matters": "Dict impact",
        "proposed_remediation": '<img alt="fixed">',
        "validation_steps": ["Verify in DOM"],
        "confidence": "high",
    }
    mock_agent_dict.return_value = mock_agent_result_dict

    with patch("strands.models.BedrockModel"), patch("strands.Agent", return_value=mock_agent_dict):
        res = explainer.explain_finding(
            rule_id="image-alt",
            impact="critical",
            description="Images must have alternate text",
            target=["img"],
            html="<img>",
            failure_summary="Missing alt",
        )
        assert res["status"] == "success"
        assert res["plain_language_explanation"] == "Dict explanation"
        assert res["proposed_remediation"] == '<img alt="fixed">'

    # 2. Test string fallback output
    mock_agent_str = MagicMock()
    mock_agent_result_str = MagicMock()
    mock_agent_result_str.structured_output = None
    mock_agent_result_str.__str__.return_value = "Unstructured text explanation from model"
    mock_agent_str.return_value = mock_agent_result_str

    with patch("strands.models.BedrockModel"), patch("strands.Agent", return_value=mock_agent_str):
        res2 = explainer.explain_finding(
            rule_id="image-alt",
            impact="critical",
            description="Images must have alternate text",
            target=["img"],
            html="<img>",
            failure_summary="Missing alt",
        )
        assert res2["status"] == "success"
        assert "Unstructured text explanation" in res2["plain_language_explanation"]


# ==============================================================================
# Downstream Workflow Branching & Policy Execution Tests (#policy)
# ==============================================================================

def test_workflow_execution_generate_remediation_branch():
    """Branch 1: When Decider selects GENERATE_REMEDIATION, advisory patch is produced for developer review."""
    decision = DecisionResult(
        action="AUTO_FIX_CANDIDATE",
        confidence=0.93,
        probabilities={"AUTO_FIX_CANDIDATE": 0.93, "HUMAN_REVIEW": 0.07},
        risk_level="low",
        rationale="Unambiguous deterministic fix identified.",
        raw_choice="AUTO_FIX_CANDIDATE",
        latency_ms=115.0,
        workflow_action="GENERATE_REMEDIATION",
        evidence_sufficiency="sufficient",
    )
    static_guide = get_static_rule_guidance("image-alt", "Element missing alt")

    wf_res = execute_workflow(
        decision=decision,
        rule_id="image-alt",
        impact="minor",
        description="Images must have alternate text",
        target=["img.hero"],
        html='<img class="hero" src="civic_banner.jpg">',
        failure_summary="Element does not have an alt attribute",
        static_guidance=static_guide,
    )

    assert wf_res.workflow_action == "GENERATE_REMEDIATION"
    assert "Advisory Remediation Patch" in wf_res.action_title
    assert wf_res.remediation_patch is not None
    assert wf_res.escalation_ticket is None
    assert wf_res.context_enrichment is None

    patch = wf_res.remediation_patch
    assert patch.rule_id == "image-alt"
    assert "PAT-" in patch.patch_id
    assert '<img src="..." alt=' in patch.proposed_remediation
    assert len(patch.verification_checklist) >= 3
    assert "Advisory recommendation only" in patch.advisory_disclaimer
    assert "not modified or verified on the live website" in patch.advisory_disclaimer


def test_workflow_execution_enrich_context_branch():
    """Branch 2: When Decider selects ENRICH_CONTEXT, DOM container analysis and contextual observations are generated."""
    decision = DecisionResult(
        action="EXPLAIN_ONLY",
        confidence=0.84,
        probabilities={"EXPLAIN_ONLY": 0.84, "HUMAN_REVIEW": 0.16},
        risk_level="medium",
        rationale="Design and context judgment required.",
        raw_choice="EXPLAIN_ONLY",
        latency_ms=105.0,
        workflow_action="ENRICH_CONTEXT",
        evidence_sufficiency="context_needed",
    )
    static_guide = get_static_rule_guidance("label", "Form element missing label")

    wf_res = execute_workflow(
        decision=decision,
        rule_id="label",
        impact="moderate",
        description="Form controls must have labels",
        target=["form#scholarship-app input[name='dob']"],
        html='<input type="text" name="dob" aria-label="Date of Birth">',
        failure_summary="Input has no explicit label",
        static_guidance=static_guide,
    )

    assert wf_res.workflow_action == "ENRICH_CONTEXT"
    assert "Structural Context Enriched" in wf_res.action_title
    assert wf_res.context_enrichment is not None
    assert wf_res.remediation_patch is None
    assert wf_res.escalation_ticket is None

    enr = wf_res.context_enrichment
    assert enr.rule_id == "label"
    assert "ENR-" in enr.enrichment_id
    assert enr.detected_container == "form_group"
    assert enr.surrounding_landmark == "form"
    assert any("aria-label" in note for note in enr.contextual_notes)
    assert "civic portals" in enr.investigation_guidance.lower()


def test_workflow_execution_escalate_human_review_branch():
    """Branch 3: When Decider selects ESCALATE_HUMAN_REVIEW, an auditor ticket with manual testing protocols is generated."""
    decision = DecisionResult(
        action="HUMAN_REVIEW",
        confidence=0.88,
        probabilities={"HUMAN_REVIEW": 0.88, "EXPLAIN_ONLY": 0.12},
        risk_level="critical",
        rationale="Complex civic barrier requires human auditor evaluation.",
        raw_choice="HUMAN_REVIEW",
        latency_ms=120.0,
        workflow_action="ESCALATE_HUMAN_REVIEW",
        evidence_sufficiency="ambiguous_or_high_risk",
    )
    static_guide = get_static_rule_guidance("color-contrast", "Contrast 2.1:1")

    wf_res = execute_workflow(
        decision=decision,
        rule_id="color-contrast",
        impact="critical",
        description="Elements must have sufficient color contrast",
        target=["button#submit-pension"],
        html='<button id="submit-pension" class="btn-primary">Apply for Benefits</button>',
        failure_summary="Element has insufficient contrast of 2.1:1",
        static_guidance=static_guide,
    )

    assert wf_res.workflow_action == "ESCALATE_HUMAN_REVIEW"
    assert "Civic Auditor Escalation Required" in wf_res.action_title
    assert wf_res.escalation_ticket is not None
    assert wf_res.remediation_patch is None
    assert wf_res.context_enrichment is None

    ticket = wf_res.escalation_ticket
    assert ticket.rule_id == "color-contrast"
    assert ticket.severity == "CRITICAL"
    assert "ESC-" in ticket.ticket_id
    assert ticket.civic_impact_area == "Citizen Applications & Public Benefit Forms"
    assert len(ticket.manual_testing_checklist) >= 4
    assert any("Screen Reader" in step for step in ticket.manual_testing_checklist)
    assert any("Keyboard-Only" in step for step in ticket.manual_testing_checklist)
    assert "Statutory Notice" in ticket.statutory_compliance_note
    assert "subset of machine-testable WCAG" in ticket.statutory_compliance_note


def test_workflow_low_confidence_forces_escalation_ticket():
    """Decider result with low confidence (<70%) automatically maps to ESCALATE_HUMAN_REVIEW."""
    cfg = Settings(
        decider_mode="ugmdu",
        decider_url="https://decider",
        decider_api_key="mock_key",
        llm_provider="bedrock",
        aws_region="us-east-1",
        bedrock_model_id="us.amazon.nova-pro-v1:0",
        bedrock_small_model_id="us.amazon.nova-micro-v1:0",
        bedrock_medium_model_id="us.amazon.nova-lite-v1:0",
        bedrock_large_model_id="us.amazon.nova-pro-v1:0",
        confidence_threshold=0.70,
    )
    decider = AccessibilityDecider(config=cfg)

    mock_resp_data = {
        "answers": {
            "action": {
                "type": "choice",
                "choice": "AUTO_FIX_CANDIDATE",
                "confidence": 0.52,  # Below threshold
                "probabilities": {"AUTO_FIX_CANDIDATE": 0.52, "HUMAN_REVIEW": 0.48},
            },
            "risk_level": {"type": "score", "score": 1.0, "label": "medium"},
        }
    }
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_resp_data).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        dec_res = decider.decide(
            rule_id="image-alt",
            impact="minor",
            description="Images must have alternate text",
            target=["#icon"],
            html='<img src="icon.png">',
            failure_summary="Missing alt",
        )

        assert dec_res.action == "HUMAN_REVIEW"
        assert dec_res.workflow_action == "ESCALATE_HUMAN_REVIEW"
        assert "below safety threshold" in dec_res.rationale

        wf_res = execute_workflow(
            decision=dec_res,
            rule_id="image-alt",
            impact="minor",
            description="Images must have alternate text",
            target=["#icon"],
            html='<img src="icon.png">',
            failure_summary="Missing alt",
            static_guidance=get_static_rule_guidance("image-alt"),
        )
        assert wf_res.workflow_action == "ESCALATE_HUMAN_REVIEW"
        assert wf_res.escalation_ticket is not None
        assert "below safety threshold" in wf_res.escalation_ticket.escalation_reason


def test_workflow_critical_severity_demotion_forces_escalation():
    """Critical finding candidate with confidence < 85% demotes to HUMAN_REVIEW and escalates ticket."""
    cfg = Settings(
        decider_mode="ugmdu",
        decider_url="https://decider",
        decider_api_key="mock_key",
        llm_provider="bedrock",
        aws_region="us-east-1",
        bedrock_model_id="us.amazon.nova-pro-v1:0",
        bedrock_small_model_id="us.amazon.nova-micro-v1:0",
        bedrock_medium_model_id="us.amazon.nova-lite-v1:0",
        bedrock_large_model_id="us.amazon.nova-pro-v1:0",
        confidence_threshold=0.70,
    )
    decider = AccessibilityDecider(config=cfg)

    mock_resp_data = {
        "answers": {
            "action": {
                "type": "choice",
                "choice": "AUTO_FIX_CANDIDATE",
                "confidence": 0.78,  # >= 0.70 but < 0.85
                "probabilities": {"AUTO_FIX_CANDIDATE": 0.78, "HUMAN_REVIEW": 0.22},
            },
            "risk_level": {"type": "score", "score": 2.5, "label": "high"},
        }
    }
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_resp_data).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        dec_res = decider.decide(
            rule_id="button-name",
            impact="critical",
            description="Buttons must have accessible names",
            target=["button#auth-submit"],
            html='<button id="auth-submit"></button>',
            failure_summary="Element has no text content",
        )

        assert dec_res.action == "HUMAN_REVIEW"
        assert dec_res.workflow_action == "ESCALATE_HUMAN_REVIEW"
        assert "CRITICAL severity" in dec_res.rationale

        wf_res = execute_workflow(
            decision=dec_res,
            rule_id="button-name",
            impact="critical",
            description="Buttons must have accessible names",
            target=["button#auth-submit"],
            html='<button id="auth-submit"></button>',
            failure_summary="Element has no text content",
            static_guidance=get_static_rule_guidance("button-name"),
        )
        assert wf_res.workflow_action == "ESCALATE_HUMAN_REVIEW"
        assert wf_res.escalation_ticket.severity == "CRITICAL"


def test_workflow_missing_evidence_safe_handling():
    """Missing or empty evidence fields are safely sanitized without raising exceptions."""
    decision = DecisionResult(
        action="EXPLAIN_ONLY",
        confidence=0.75,
        probabilities={"EXPLAIN_ONLY": 0.75},
        risk_level="medium",
        rationale="Missing snippet context.",
        raw_choice="EXPLAIN_ONLY",
        latency_ms=80.0,
        workflow_action="ENRICH_CONTEXT",
        evidence_sufficiency="context_needed",
    )

    wf_res = execute_workflow(
        decision=decision,
        rule_id="",
        impact="",
        description="",
        target=[],
        html="",
        failure_summary="",
        static_guidance={},
    )
    assert wf_res.workflow_action == "ENRICH_CONTEXT"
    assert wf_res.context_enrichment is not None
    assert "ENR-" in wf_res.context_enrichment.enrichment_id


def test_workflow_unknown_workflow_action_safe_fallback():
    """Unrecognized or corrupted workflow_action safely defaults to ESCALATE_HUMAN_REVIEW."""
    decision = DecisionResult(
        action="UNKNOWN_OR_MALFORMED",
        confidence=0.50,
        probabilities={},
        risk_level="high",
        rationale="Unexpected decision output.",
        raw_choice="UNKNOWN",
        latency_ms=10.0,
        workflow_action="INVALID_UNSUPPORTED_BRANCH",
        evidence_sufficiency="unknown",
    )

    wf_res = execute_workflow(
        decision=decision,
        rule_id="heading-order",
        impact="moderate",
        description="Heading levels should not be skipped",
        target=["h4.sub"],
        html="<h4>Title</h4>",
        failure_summary="Skipped h3",
        static_guidance={},
    )
    assert wf_res.workflow_action == "ESCALATE_HUMAN_REVIEW"
    assert wf_res.escalation_ticket is not None
    assert "Civic Auditor Escalation Required" in wf_res.action_title


def test_api_findings_analyze_returns_structured_workflow(client, monkeypatch):
    """POST /api/findings/analyze includes the complete structured workflow object in JSON output."""
    monkeypatch.setenv("DECIDER_API_KEY", "valid_key")

    mock_decision = DecisionResult(
        action="AUTO_FIX_CANDIDATE",
        confidence=0.95,
        probabilities={"AUTO_FIX_CANDIDATE": 0.95, "HUMAN_REVIEW": 0.05},
        risk_level="low",
        rationale="Deterministic fix available.",
        raw_choice="AUTO_FIX_CANDIDATE",
        latency_ms=90.0,
        workflow_action="GENERATE_REMEDIATION",
        evidence_sufficiency="sufficient",
    )

    with patch.object(AccessibilityDecider, "decide", return_value=mock_decision):
        payload = {
            "rule_id": "image-alt",
            "impact": "minor",
            "description": "Images must have alt text",
            "target": ["#portal-logo"],
            "html": '<img id="portal-logo" src="logo.svg">',
            "failure_summary": "Missing alt attribute",
        }
        resp = client.post("/api/findings/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert "workflow" in data
        wf = data["workflow"]
        assert wf["workflow_action"] == "GENERATE_REMEDIATION"
        assert "Advisory Remediation Patch" in wf["action_title"]
        assert wf["remediation_patch"] is not None
        assert "PAT-" in wf["remediation_patch"]["patch_id"]
        assert "advisory_disclaimer" in wf["remediation_patch"]


def test_health_check_endpoint_configuration_parity(client, monkeypatch):
    """GET /api/health reliably exposes decider_configured, bedrock_configured, and bedrock_enabled."""
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "disabled")
    monkeypatch.setenv("DECIDER_API_KEY", "")

    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "healthy"
    assert "bedrock_configured" in data
    assert "bedrock_enabled" in data
    assert data["bedrock_enabled"] is False
    assert data["decider_configured"] is False
    assert "Axe-core automated accessibility tests" in data["disclaimer"]


def test_civic_scholarship_findings_drive_distinct_downstream_workflows():
    """Real scanner evidence from civic scholarship fixture drives distinct downstream workflows.

    Demonstrates at least two distinct execution paths:
    Path 1: GENERATE_REMEDIATION -> Synthesizes an advisory remediation patch with checklist.
    Path 2: ESCALATE_HUMAN_REVIEW -> Synthesizes a formal auditor escalation ticket with manual testing protocol.
    Path 3: ENRICH_CONTEXT -> Synthesizes surrounding landmark & container DOM analysis.
    """
    from accesslens.scanner import AccessibilityScanner
    from accesslens.workflow import execute_downstream_workflow
    from accesslens.decider import DecisionResult, get_static_rule_guidance
    from pathlib import Path

    fixture_path = Path(__file__).resolve().parent / "fixtures" / "civic_scholarship_portal.html"
    raw_html = fixture_path.read_text(encoding="utf-8")
    scanner = AccessibilityScanner()
    scan_report = scanner.scan_html(raw_html, base_url="http://scholarship.civic.gov")

    assert scan_report.status == "SUCCESS"
    violations_by_id = {v.rule_id: v for v in scan_report.violations}

    # --- Path 1: Deterministic image-alt finding leads to AdvisoryRemediationPatch ---
    alt_v = violations_by_id["image-alt"]
    alt_node = alt_v.nodes[0]
    static_alt = get_static_rule_guidance("image-alt", alt_node.failure_summary)

    decision_alt = DecisionResult(
        action="AUTO_FIX_CANDIDATE",
        confidence=0.92,
        probabilities={"AUTO_FIX_CANDIDATE": 0.92, "HUMAN_REVIEW": 0.08},
        risk_level="low",
        rationale="State emblem image missing alt attribute; deterministic fix available.",
        raw_choice="AUTO_FIX_CANDIDATE",
        latency_ms=85.0,
        workflow_action="GENERATE_REMEDIATION",
        evidence_sufficiency="sufficient",
    )

    wf_result_1 = execute_downstream_workflow(
        decision=decision_alt,
        rule_id="image-alt",
        impact=alt_v.impact,
        description=alt_v.description,
        target=alt_node.target,
        html=alt_node.html,
        failure_summary=alt_node.failure_summary,
        static_guidance=static_alt,
        bedrock_explanation=None,
    )

    assert wf_result_1.workflow_action == "GENERATE_REMEDIATION"
    assert "Advisory Remediation Patch" in wf_result_1.action_title
    assert wf_result_1.remediation_patch is not None
    assert "civic-seal-graphic" in wf_result_1.remediation_patch.original_snippet
    assert 'alt="' in wf_result_1.remediation_patch.proposed_remediation
    assert len(wf_result_1.remediation_patch.verification_checklist) >= 3
    assert "Advisory recommendation only" in wf_result_1.remediation_patch.advisory_disclaimer

    # --- Path 2: Critical / low-contrast finding leads to CivicAuditorEscalationTicket ---
    contrast_v = violations_by_id["color-contrast"]
    contrast_node = contrast_v.nodes[0]
    static_contrast = get_static_rule_guidance("color-contrast", contrast_node.failure_summary)

    decision_contrast = DecisionResult(
        action="HUMAN_REVIEW",
        confidence=0.96,
        probabilities={"HUMAN_REVIEW": 0.96, "AUTO_FIX_CANDIDATE": 0.04},
        risk_level="high",
        rationale="Color contrast modification impacts civic portal brand styling and requires manual color balancing.",
        raw_choice="HUMAN_REVIEW",
        latency_ms=110.0,
        workflow_action="ESCALATE_HUMAN_REVIEW",
        evidence_sufficiency="sufficient",
    )

    wf_result_2 = execute_downstream_workflow(
        decision=decision_contrast,
        rule_id="color-contrast",
        impact=contrast_v.impact,
        description=contrast_v.description,
        target=contrast_node.target,
        html=contrast_node.html,
        failure_summary=contrast_node.failure_summary,
        static_guidance=static_contrast,
        bedrock_explanation=None,
    )

    assert wf_result_2.workflow_action == "ESCALATE_HUMAN_REVIEW"
    assert "Civic Auditor Escalation" in wf_result_2.action_title
    assert wf_result_2.escalation_ticket is not None
    assert wf_result_2.escalation_ticket.risk_level == "HIGH"
    assert len(wf_result_2.escalation_ticket.manual_testing_checklist) >= 4
    assert any("Screen Reader" in item or "Keyboard-Only" in item for item in wf_result_2.escalation_ticket.manual_testing_checklist)
    assert "Statutory Notice" in wf_result_2.escalation_ticket.statutory_compliance_note

    # --- Path 3: Ambiguous form context leads to CivicContextEnrichmentReport ---
    label_v = violations_by_id["label"]
    label_node = label_v.nodes[0]
    static_label = get_static_rule_guidance("label", label_node.failure_summary)

    decision_label = DecisionResult(
        action="EXPLAIN_ONLY",
        confidence=0.88,
        probabilities={"EXPLAIN_ONLY": 0.88, "HUMAN_REVIEW": 0.12},
        risk_level="medium",
        rationale="Missing label requires context enrichment of parent form and container structure.",
        raw_choice="EXPLAIN_ONLY",
        latency_ms=95.0,
        workflow_action="ENRICH_CONTEXT",
        evidence_sufficiency="insufficient_requires_context",
    )

    wf_result_3 = execute_downstream_workflow(
        decision=decision_label,
        rule_id="label",
        impact=label_v.impact,
        description=label_v.description,
        target=label_node.target,
        html=label_node.html,
        failure_summary=label_node.failure_summary,
        static_guidance=static_label,
        bedrock_explanation=None,
    )

    assert wf_result_3.workflow_action == "ENRICH_CONTEXT"
    assert "Structural Context Enriched" in wf_result_3.action_title
    assert wf_result_3.context_enrichment is not None
    assert "form" in wf_result_3.context_enrichment.detected_container.lower()
    assert len(wf_result_3.context_enrichment.contextual_notes) >= 1



