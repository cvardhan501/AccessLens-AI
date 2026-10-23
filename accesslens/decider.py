"""REUSABLE DECISION PATTERN: #policy
==================================

Pattern Identifier: #policy
Model Target: Strands Decider 2B (Hosted endpoint: POST /v1/decide)
Task: Gatekeeping and triage of automated accessibility remediation actions.

1. State Provided to the Decider
--------------------------------
The state captures a bounded, privacy-sanitized snapshot of an accessibility violation:
- Rule ID: axe-core / WCAG violation identifier (e.g. 'image-alt', 'button-name').
- Severity Impact: Violation severity ('critical', 'serious', 'moderate', 'minor').
- Description: Concise statement of the accessibility barrier.
- CSS Target: Specific DOM selector path identifying the offending element.
- Element Evidence: Raw HTML element snippet sanitized via `sanitize_html_evidence`
  (capped at 300 characters; scripts, styles, and sensitive query tokens redacted).
- Failure Summary: Specific axe-core failure assertion explaining why the node failed.

2. Typed Question and Permitted Options
---------------------------------------
The decider evaluates two structured questions:
- 'action' (type: choice):
  * 'AUTO_FIX_CANDIDATE': Deterministic, low-risk fix with minimal risk of breaking
    page semantics or layout (e.g., missing alt on standalone images, label for input).
  * 'EXPLAIN_ONLY': Clear educational guidance; code modification carries semantic risk
    or involves subjective design decisions.
  * 'HUMAN_REVIEW': Critical barrier, complex ARIA widget roles, color contrast changes
    impacting brand palettes, or ambiguous context requiring manual judgment.
- 'risk_level' (type: score):
  * Discrete score scale: ['low', 'medium', 'high', 'critical'].

3. Wiring into Existing Analysis Flow
-------------------------------------
- Trigger: Auditor selects a finding on the AccessLens dashboard or issues a POST
  request to `/api/findings/analyze`.
- Server Pipeline: `accesslens.server.analyze_finding` invokes `AccessibilityDecider.decide(...)`.
- Decider Client: Serializes state and typed questions into JSON, executes POST to `/v1/decide`
  with Bearer token authentication and timeout guard.
- Static Grounding: Concurrently merges deterministic WCAG 2.1 criteria guidance from
  `get_static_rule_guidance()` into the response.
- Response Dispatch: Returns `DecisionResult` with effective action, probability distribution,
  risk score, rationale, and latency to the client.

4. Confidence Thresholds & Conservative Fallback
------------------------------------------------
- Base Confidence Threshold: Configurable via `DECIDER_CONFIDENCE_THRESHOLD` (default: 0.70).
  Any action with confidence < 0.70 is strictly demoted to 'HUMAN_REVIEW'.
- Severity-Sensitive Guard: Findings with 'critical' or 'serious' severity require
  confidence >= 0.85 to qualify for 'AUTO_FIX_CANDIDATE'. Candidates below 85% are demoted
  to 'HUMAN_REVIEW' with explicit rationale.
- Fault Tolerance: Network timeouts, 401 unauthenticated, 402 quota exhaustion, 429 throttling,
  and 503 unavailability raise typed `DeciderError` subclasses, caught at the API layer to
  return structured fallback status without crashing.

5. How Another Developer Can Reuse This Pattern
-----------------------------------------------
```python
from accesslens.decider import AccessibilityDecider

decider = AccessibilityDecider()
result = decider.decide(
    rule_id="image-alt",
    impact="critical",
    description="Images must have alternate text",
    target=["#hero-banner img"],
    html='<img src="banner.jpg">',
    failure_summary="Element does not have an alt attribute",
)
print(f"Action: {result.action} (Confidence: {result.confidence:.1%})")
if result.action == "AUTO_FIX_CANDIDATE":
    apply_deterministic_patch(...)
else:
    notify_human_reviewer(...)
```
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
import time
from typing import Any, Mapping
import urllib.error
import urllib.request

from .config import Settings, load_config

# Reusable decision pattern tag for hackathon classification
PATTERN_TAG: str = "#policy"



# --- Typed Exceptions ---

class DeciderError(Exception):
    """Base error for Strands Decider operations."""


class DeciderAuthError(DeciderError):
    """Raised on missing or rejected DECIDER_API_KEY (HTTP 401)."""


class DeciderQuotaError(DeciderError):
    """Raised when monthly Decider quota is exhausted (HTTP 402)."""


class DeciderRateLimitError(DeciderError):
    """Raised when Decider requests are throttled (HTTP 429)."""


class DeciderUnavailableError(DeciderError):
    """Raised on network timeout, connection refused, or HTTP 503."""


class DeciderValidationError(DeciderError):
    """Raised on invalid request schema, bad question, or malformed server response."""


# --- Data Models ---

@dataclass(frozen=True)
class DecisionResult:
    action: str  # AUTO_FIX_CANDIDATE | EXPLAIN_ONLY | HUMAN_REVIEW
    confidence: float
    probabilities: dict[str, float]
    risk_level: str
    rationale: str
    raw_choice: str
    latency_ms: float
    status: str = "success"
    workflow_action: str = "ESCALATE_HUMAN_REVIEW"
    evidence_sufficiency: str = "sufficient"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "confidence": round(self.confidence, 4),
            "probabilities": {k: round(v, 4) for k, v in self.probabilities.items()},
            "risk_level": self.risk_level,
            "rationale": self.rationale,
            "raw_choice": self.raw_choice,
            "latency_ms": round(self.latency_ms, 2),
            "status": self.status,
            "workflow_action": self.workflow_action,
            "evidence_sufficiency": self.evidence_sufficiency,
        }



# --- Evidence Sanitizer ---

def sanitize_html_evidence(raw_html: str, max_chars: int = 300) -> str:
    """Sanitize HTML evidence snippet: strip scripts, inline tokens, query params, and cap length."""
    if not raw_html:
        return ""
    # Strip script and style blocks
    cleaned = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", raw_html, flags=re.IGNORECASE | re.DOTALL)
    # Strip potential sensitive url parameters like token=, key=, secret=
    cleaned = re.sub(r"(token|key|secret|password|auth)=[^&\"'>\s]+", r"\1=[REDACTED]", cleaned, flags=re.IGNORECASE)
    # Normalize whitespaces
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars] + "...[truncated]"
    return cleaned


def build_finding_state(
    rule_id: str,
    impact: str,
    description: str,
    target: list[str] | str,
    html: str,
    failure_summary: str,
) -> str:
    """Construct bounded, privacy-safe state representation for the Decider."""
    clean_target = ", ".join(target) if isinstance(target, list) else str(target)
    clean_html = sanitize_html_evidence(html, max_chars=300)
    clean_summary = " ".join((failure_summary or "").split())[:250]

    return (
        f"ACCESSIBILITY AUDIT FINDING:\n"
        f"- Rule ID: {rule_id.strip()}\n"
        f"- Severity Impact: {impact.strip().lower()}\n"
        f"- Description: {description.strip()[:200]}\n"
        f"- CSS Target: {clean_target[:150]}\n"
        f"- Element Evidence: {clean_html}\n"
        f"- Failure Summary: {clean_summary}"
    )


# --- Strands Decider Client ---

class AccessibilityDecider:
    """Client for Strands Decider 2B accessibility classification."""

    def __init__(self, config: Settings | None = None, timeout: float = 15.0):
        self.config = config or load_config()
        self.timeout = timeout

    @staticmethod
    def questions() -> dict[str, dict[str, Any]]:
        """Construct standard typed questions for accessibility action classification."""
        return {
            "action": {
                "type": "choice",
                "instructions": (
                    "Based on the accessibility violation rule, severity, and HTML snippet, "
                    "what is the recommended remediation action?"
                ),
                "criteria": {
                    "AUTO_FIX_CANDIDATE": (
                        "Unambiguous deterministic fix that has minimal risk of breaking page semantics "
                        "or requiring design decisions (such as adding alt attribute to standalone images "
                        "or associating a form label with an id)"
                    ),
                    "EXPLAIN_ONLY": (
                        "Clear context and educational guidance, but automated code generation is risky "
                        "or involves subjective design choices"
                    ),
                    "HUMAN_REVIEW": (
                        "High impact or critical barrier, complex ARIA widget roles, color contrast changes "
                        "involving brand palette, or ambiguous context requiring manual human judgment"
                    ),
                },
            },
            "risk_level": {
                "type": "score",
                "instructions": "Rate the technical and visual risk of modifying this element automatically:",
                "criteria": ["low", "medium", "high", "critical"],
            },
        }

    def decide(
        self,
        rule_id: str,
        impact: str,
        description: str,
        target: list[str] | str,
        html: str,
        failure_summary: str,
    ) -> DecisionResult:
        """Execute decision request against Strands Decider 2B endpoint."""
        # 1. Validation check without making network request
        if self.config.decider_mode != "local" and not self.config.decider_api_key:
            raise DeciderAuthError(
                "DECIDER_API_KEY is not configured. Set DECIDER_API_KEY in .env to enable the hosted Decider."
            )

        state_text = build_finding_state(rule_id, impact, description, target, html, failure_summary)
        body = {
            "state": state_text,
            "questions": self.questions(),
        }

        # 2. Endpoint determination
        is_hosted = self.config.decider_mode == "ugmdu" or bool(self.config.decider_api_key)
        path = "/v1/decide" if is_hosted else "/v1/systemone"
        url = self.config.decider_url.rstrip("/") + path

        headers = {"Content-Type": "application/json"}
        if self.config.decider_api_key:
            headers["Authorization"] = f"Bearer {self.config.decider_api_key}"

        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_payload = resp.read()
                try:
                    payload = json.loads(raw_payload.decode("utf-8"))
                except Exception as json_err:
                    raise DeciderValidationError(f"Invalid JSON returned by Decider: {json_err}") from json_err

        except urllib.error.HTTPError as err:
            err_body = err.read().decode("utf-8", errors="replace")[:250]
            if err.code == 401:
                raise DeciderAuthError(f"Decider authentication failed (401). Check DECIDER_API_KEY: {err_body}") from err
            elif err.code == 402:
                raise DeciderQuotaError(f"Decider quota exhausted (402): {err_body}") from err
            elif err.code == 429:
                raise DeciderRateLimitError(f"Decider rate limited (429): {err_body}") from err
            elif err.code in (500, 502, 503, 504):
                raise DeciderUnavailableError(f"Decider service unavailable ({err.code}): {err_body}") from err
            else:
                raise DeciderValidationError(f"Decider returned HTTP {err.code}: {err_body}") from err

        except (urllib.error.URLError, TimeoutError, ConnectionError) as net_err:
            raise DeciderUnavailableError(f"Could not reach Decider at {url}: {net_err}") from net_err

        elapsed_ms = (time.perf_counter() - t0) * 1000

        # 3. Parse Answers
        answers = payload.get("answers", {})
        if "action" not in answers:
            raise DeciderValidationError(f"Decider response missing required 'action' answer: {payload}")

        action_ans = answers["action"]
        raw_choice = str(action_ans.get("choice") or "HUMAN_REVIEW").strip()
        probabilities = {str(k): float(v) for k, v in action_ans.get("probabilities", {}).items()}
        confidence = float(action_ans.get("confidence", 0.0) or (max(probabilities.values()) if probabilities else 0.0))

        # Score / Risk Level
        risk_ans = answers.get("risk_level", {})
        risk_level = str(risk_ans.get("label") or "high").lower()

        # 4. Conservative Safety Rules & Demotion
        # Critical and serious violations are naturally high risk and favour HUMAN_REVIEW
        clean_impact = impact.strip().lower()
        effective_action = raw_choice
        rationale_parts: list[str] = []

        if confidence < self.config.confidence_threshold:
            effective_action = "HUMAN_REVIEW"
            rationale_parts.append(
                f"Decider confidence ({confidence:.0%}) is below safety threshold ({self.config.confidence_threshold:.0%}); "
                "routed to human review."
            )
        elif clean_impact in ("critical", "serious") and effective_action == "AUTO_FIX_CANDIDATE":
            if confidence < 0.85:
                effective_action = "HUMAN_REVIEW"
                rationale_parts.append(
                    f"Finding has {clean_impact.upper()} severity; candidate demoted to HUMAN_REVIEW "
                    f"because confidence ({confidence:.0%}) < 85%."
                )
            else:
                rationale_parts.append(
                    f"High confidence ({confidence:.0%}) deterministic candidate identified for {rule_id}."
                )
        elif effective_action == "AUTO_FIX_CANDIDATE":
            rationale_parts.append(
                f"Low-risk deterministic fix candidate identified ({confidence:.0%} confidence)."
            )
        elif effective_action == "EXPLAIN_ONLY":
            rationale_parts.append(
                f"Educational explanation recommended ({confidence:.0%} confidence); code change involves design choices."
            )
        else:
            rationale_parts.append(
                f"Complex issue requires human judgment ({confidence:.0%} confidence)."
            )

        rationale = " ".join(rationale_parts)

        # 5. Derive Deterministic Downstream Workflow Action
        if effective_action == "AUTO_FIX_CANDIDATE":
            workflow_action = "GENERATE_REMEDIATION"
            evidence_sufficiency = "sufficient"
        elif effective_action == "EXPLAIN_ONLY":
            workflow_action = "ENRICH_CONTEXT"
            evidence_sufficiency = "context_needed"
        else:
            workflow_action = "ESCALATE_HUMAN_REVIEW"
            evidence_sufficiency = "ambiguous_or_high_risk"

        return DecisionResult(
            action=effective_action,
            confidence=confidence,
            probabilities=probabilities,
            risk_level=risk_level,
            rationale=rationale,
            raw_choice=raw_choice,
            latency_ms=elapsed_ms,
            workflow_action=workflow_action,
            evidence_sufficiency=evidence_sufficiency,
        )



# --- Deterministic Static WCAG Guidance Knowledge Base ---

STATIC_WCAG_GUIDANCE: dict[str, dict[str, str]] = {
    "image-alt": {
        "wcag_criterion": "WCAG 2.1 A - 1.1.1 Non-text Content",
        "summary": "All informative <img> elements must provide alternative text describing the image content. Purely decorative images should use an empty alt attribute (alt=\"\") or role=\"presentation\".",
        "standard_fix": '<img src="..." alt="Concise description of the image or action">',
        "verification_step": "Inspect rendered DOM or re-run axe-core audit to verify the alt attribute is present and accurately describes the image.",
    },
    "button-name": {
        "wcag_criterion": "WCAG 2.1 A - 4.1.2 Name, Role, Value",
        "summary": "Buttons must have discernible, accessible text through visible label text, an aria-label attribute, or aria-labelledby reference.",
        "standard_fix": '<button type="button" aria-label="Descriptive action name">Icon</button>',
        "verification_step": "Test with a screen reader or inspect the accessibility tree to confirm the button\'s computed accessible name is non-empty.",
    },
    "color-contrast": {
        "wcag_criterion": "WCAG 2.1 AA - 1.4.3 Contrast (Minimum)",
        "summary": "Text and images of text must maintain a contrast ratio of at least 4.5:1 against the background (3:1 for large text >= 18pt or bold >= 14pt).",
        "standard_fix": "Update CSS color or background-color properties to ensure computed luminance meets or exceeds the 4.5:1 contrast threshold.",
        "verification_step": "Use browser DevTools color picker or a contrast analyzer tool to confirm contrast ratio meets WCAG AA.",
    },
    "label": {
        "wcag_criterion": "WCAG 2.1 A - 1.3.1 Info and Relationships / 4.1.2 Name, Role, Value",
        "summary": "Every form control must have an associated programmatic label using a <label for=\"id\"> pairing, aria-label, or aria-labelledby.",
        "standard_fix": '<label for="field-id">Field Name</label>\n<input id="field-id" type="text" name="field-name">',
        "verification_step": "Clicking the label must transfer focus to the input element, and screen readers must announce the label text on focus.",
    },
    "link-name": {
        "wcag_criterion": "WCAG 2.1 A - 2.4.4 Link Purpose (In Context)",
        "summary": "Links must have discernible text explaining their destination or purpose. Avoid empty links, unlabeled icon links, or generic text like \'click here\'.",
        "standard_fix": '<a href="/target" aria-label="Descriptive destination">Link content</a>',
        "verification_step": "Verify links list in screen reader announces meaningful destinations for all anchor tags.",
    },
    "document-title": {
        "wcag_criterion": "WCAG 2.1 A - 2.4.2 Page Titled",
        "summary": "Every HTML document must contain a non-empty, descriptive <title> element inside the <head> section to orient users.",
        "standard_fix": "<head>\n  <title>Unique Page Title — Site Name</title>\n</head>",
        "verification_step": "Verify page title in browser tab and ensure screen readers announce title on initial page navigation.",
    },
    "html-has-lang": {
        "wcag_criterion": "WCAG 2.1 A - 3.1.1 Language of Page",
        "summary": "The root <html> element must have a valid language attribute (e.g. lang=\"en\") so speech synthesizers use correct pronunciation rules.",
        "standard_fix": '<html lang="en">',
        "verification_step": "Check the root <html> tag in HTML source to ensure a valid IETF BCP 47 language code is defined.",
    },
    "landmark-one-main": {
        "wcag_criterion": "WCAG 2.1 A - 1.3.1 Info and Relationships",
        "summary": "The document must have exactly one top-level <main> landmark element or role=\"main\" to mark primary content.",
        "standard_fix": "<main>\n  <!-- Primary unique page content -->\n</main>",
        "verification_step": "Check landmark navigation in assistive technology to confirm exactly one main landmark exists.",
    },
    "aria-roles": {
        "wcag_criterion": "WCAG 2.1 A - 4.1.2 Name, Role, Value",
        "summary": "All ARIA role attributes must contain valid, recognized WAI-ARIA role values matching the element\'s actual semantic behavior.",
        "standard_fix": "Verify that role attribute uses standard W3C ARIA values (e.g. role=\"dialog\", role=\"navigation\", role=\"banner\").",
        "verification_step": "Validate ARIA roles using axe-core or W3C HTML/ARIA validator.",
    },
    "heading-order": {
        "wcag_criterion": "WCAG 2.1 Best Practice - 1.3.1 Info and Relationships",
        "summary": "Headings should follow a logical sequence from <h1> through <h6> without skipping levels (e.g., avoid jumping directly from <h2> to <h4>).",
        "standard_fix": "Restructure heading tags to maintain sequential hierarchical order matching content structure.",
        "verification_step": "Inspect heading tree in browser accessibility inspector to confirm no skipped heading levels.",
    },
    "empty-table-header": {
        "wcag_criterion": "WCAG 2.1 A - 1.3.1 Info and Relationships",
        "summary": "Table header elements (<th>) must contain discernible, non-empty text to provide programmatic column or row context for screen reader users.",
        "standard_fix": '<th scope="col">Descriptive Column Header</th>',
        "verification_step": "Ensure all table header cells have non-empty text content or an accessible name, and test table navigation in screen reader.",
    },
}


def get_static_rule_guidance(rule_id: str, failure_summary: str = "") -> dict[str, Any]:
    """Return deterministic static WCAG remediation guidance for a detected rule ID.

    This function never invokes any LLM or external model API. All guidance is
    strictly grounded in published W3C WCAG 2.1 success criteria and axe-core heuristics.
    """
    clean_rule = (rule_id or "").strip().lower()
    if clean_rule in STATIC_WCAG_GUIDANCE:
        item = STATIC_WCAG_GUIDANCE[clean_rule]
        return {
            "rule_id": rule_id,
            "wcag_criterion": item["wcag_criterion"],
            "summary": item["summary"],
            "standard_fix": item["standard_fix"],
            "verification_step": item["verification_step"],
            "source": "static_wcag_knowledge_base",
            "is_llm_generated": False,
        }

    # Deterministic fallback for uncatalogued rules
    summary_hint = (failure_summary or "").strip()
    if summary_hint:
        summary_hint = " ".join(summary_hint.split())[:200]
    else:
        summary_hint = f"Review WCAG documentation for rule '{rule_id}' and verify element semantics meet criteria."

    return {
        "rule_id": rule_id,
        "wcag_criterion": "WCAG 2.1 Accessibility Standard",
        "summary": summary_hint,
        "standard_fix": f"<!-- Ensure compliance with axe-core rule: {rule_id} -->\n<!-- Refer to Deque University documentation for detailed code patterns -->",
        "verification_step": "Re-run axe-core audit to verify resolution of the reported rule violation.",
        "source": "static_wcag_fallback",
        "is_llm_generated": False,
    }

