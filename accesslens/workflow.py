"""Civic Access Auditor workflow execution engine.

Executes genuinely distinct downstream workflows based on Strands Decider 2B
policy triage and evidence sufficiency:
1. ESCALATE_HUMAN_REVIEW: Halts automated patching, emits a structured Civic
   Auditor Escalation Ticket with manual assistive technology verification protocols.
2. GENERATE_REMEDIATION: Synthesizes a safe, evidence-grounded advisory code patch
   for developer review (never mutating live websites).
3. ENRICH_CONTEXT: Performs safe in-memory structural DOM analysis to identify
   surrounding form/container landmarks and educational guidance for civic teams.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .decider import DecisionResult
from .models import (
    AdvisoryRemediationPatch,
    CivicAuditorEscalationTicket,
    CivicContextEnrichmentReport,
    WorkflowExecutionResult,
)


def _hash_id(prefix: str, *parts: str) -> str:
    seed = "|".join(parts).encode("utf-8")
    h = hashlib.sha256(seed).hexdigest()[:8].upper()
    return f"{prefix}-{h}"


def _detect_civic_impact_area(rule_id: str, html: str, target_str: str) -> str:
    combined = (rule_id + " " + html + " " + target_str).lower()
    if any(k in combined for k in ("input", "form", "select", "textarea", "label", "button", "submit")):
        return "Citizen Applications & Public Benefit Forms"
    if any(k in combined for k in ("login", "auth", "password", "signup", "register", "token")):
        return "Citizen Authentication & Identity Verification"
    if any(k in combined for k in ("table", "th", "td", "list", "grid")):
        return "Public Data Tables & Financial / Eligibility Schedules"
    if any(k in combined for k in ("color", "contrast", "font", "zoom")):
        return "Low-Vision Citizen Public Information Access"
    if any(k in combined for k in ("nav", "menu", "header", "footer", "skip")):
        return "Screen Reader Navigation on Civic Portals"
    return "Civic Information & Public Notice Access"


def _detect_structural_container(target_str: str, html: str) -> tuple[str, str]:
    combined = (target_str + " " + html).lower()
    container = "generic_element"
    landmark = "contentinfo"

    if "form" in combined:
        container = "form_group"
        landmark = "form"
    elif any(k in combined for k in ("nav", "menu", "header")):
        container = "navigation_bar"
        landmark = "navigation"
    elif any(k in combined for k in ("main", "article", "section")):
        container = "primary_content_region"
        landmark = "main"
    elif "footer" in combined:
        container = "footer_region"
        landmark = "contentinfo"
    elif any(k in combined for k in ("table", "tbody", "thead")):
        container = "tabular_data_structure"
        landmark = "region"
    elif any(k in combined for k in ("dialog", "modal")):
        container = "dialog_overlay"
        landmark = "dialog"

    return container, landmark


def escalate_human_review(
    rule_id: str,
    impact: str,
    description: str,
    html: str,
    failure_summary: str,
    target_str: str,
    rationale: str,
    risk_level: str,
) -> CivicAuditorEscalationTicket:
    """Construct a formal Civic Auditor Escalation Ticket requiring human sign-off."""
    ticket_id = _hash_id("ESC", rule_id, impact, target_str)
    civic_area = _detect_civic_impact_area(rule_id, html, target_str)

    manual_steps = [
        f"1. Screen Reader Protocol: Verify element announcement with NVDA, JAWS, or VoiceOver (Rule: {rule_id}).",
        "2. Keyboard-Only Navigation: Verify clear focus indicator and ensure element operates without mouse interaction.",
        "3. Cognitive & Civic Clarity: Ensure instructions and error states are plain-language and accessible to all citizens.",
        "4. 200% Zoom / Reflow Verification: Confirm layout reflows without horizontal scroll or truncated text per WCAG 1.4.10.",
    ]

    statutory_note = (
        "Statutory Notice: Automated axe-core evaluation checks only a subset of machine-testable WCAG criteria. "
        "Because this finding involves semantic, brand, or high-severity barriers, automated remediation is blocked. "
        "A qualified human accessibility auditor must verify compliance before production deployment."
    )

    return CivicAuditorEscalationTicket(
        ticket_id=ticket_id,
        rule_id=rule_id,
        severity=impact.upper(),
        civic_impact_area=civic_area,
        risk_level=risk_level.upper(),
        escalation_reason=rationale,
        manual_testing_checklist=manual_steps,
        statutory_compliance_note=statutory_note,
    )


def generate_remediation_patch(
    rule_id: str,
    html: str,
    failure_summary: str,
    target_str: str,
    static_guidance: dict[str, Any],
    bedrock_res: dict[str, Any] | None = None,
) -> AdvisoryRemediationPatch:
    """Synthesize an advisory code patch for developer review without modifying target systems."""
    patch_id = _hash_id("PAT", rule_id, target_str)

    proposed_fix = ""
    patch_explanation = ""

    if bedrock_res and bedrock_res.get("status") == "success" and bedrock_res.get("proposed_remediation"):
        proposed_fix = str(bedrock_res["proposed_remediation"]).strip()
        patch_explanation = str(bedrock_res.get("plain_language_explanation", "")).strip()
    elif static_guidance.get("standard_fix"):
        proposed_fix = str(static_guidance["standard_fix"]).strip()
        patch_explanation = str(static_guidance.get("summary", "Standard deterministic WCAG fix pattern.")).strip()
    else:
        proposed_fix = html
        patch_explanation = "Review element attributes against WCAG 2.1 Level AA specifications."

    verification_steps = [
        f"1. Apply suggested patch to local component template for rule '{rule_id}'.",
        "2. Re-run axe-core automated audit to confirm the rule violation is completely resolved.",
        "3. Test with keyboard navigation to ensure tab order and focusability remain intact.",
        "4. Confirm visual rendering matches design specifications across responsive breakpoints.",
    ]

    return AdvisoryRemediationPatch(
        patch_id=patch_id,
        rule_id=rule_id,
        original_snippet=html,
        proposed_remediation=proposed_fix,
        patch_explanation=patch_explanation,
        verification_checklist=verification_steps,
    )


def enrich_finding_context(
    rule_id: str,
    target: list[str] | str,
    html: str,
    failure_summary: str,
) -> CivicContextEnrichmentReport:
    """Perform safe in-memory structural DOM analysis to enrich contextual evidence."""
    target_str = ", ".join(target) if isinstance(target, list) else str(target)
    enrichment_id = _hash_id("ENR", rule_id, target_str)

    container, landmark = _detect_structural_container(target_str, html)

    notes: list[str] = []
    # Identify landmark context
    notes.append(f"Located inside '{landmark}' landmark within structural container '{container}'.")

    # Analyze HTML attributes safely
    has_aria_label = "aria-label=" in html.lower()
    has_title = "title=" in html.lower()
    has_role = "role=" in html.lower()
    has_id = "id=" in html.lower()

    if has_role:
        notes.append("Element specifies an explicit ARIA 'role'; verify that child/parent role inheritance is valid.")
    if has_aria_label:
        notes.append("Element contains an 'aria-label'; confirm it is not overriding visible label text confusingly.")
    if not has_id and ("input" in html.lower() or "select" in html.lower()):
        notes.append("Form control lacks an explicit 'id'; consider wrapping with an implicit <label> or assigning a unique id.")

    guidance = (
        f"For civic portals, ensure elements in the '{landmark}' landmark provide clear accessible names. "
        "Coordinate with UX/UI design before modifying visual contrast or layout hierarchy."
    )

    return CivicContextEnrichmentReport(
        enrichment_id=enrichment_id,
        rule_id=rule_id,
        context_depth="structural_container_analyzed",
        detected_container=container,
        surrounding_landmark=landmark,
        contextual_notes=notes,
        investigation_guidance=guidance,
    )


def execute_workflow(
    decision: DecisionResult,
    rule_id: str,
    impact: str,
    description: str,
    target: list[str] | str,
    html: str,
    failure_summary: str,
    static_guidance: dict[str, Any],
    bedrock_res: dict[str, Any] | None = None,
    bedrock_explanation: dict[str, Any] | None = None,
) -> WorkflowExecutionResult:
    """Execute the concrete downstream workflow determined by Strands Decider 2B."""
    target_str = ", ".join(target) if isinstance(target, list) else str(target)
    action = decision.workflow_action
    effective_bedrock = bedrock_res or bedrock_explanation

    if action == "GENERATE_REMEDIATION":
        patch = generate_remediation_patch(
            rule_id=rule_id,
            html=html,
            failure_summary=failure_summary,
            target_str=target_str,
            static_guidance=static_guidance,
            bedrock_res=effective_bedrock,
        )
        return WorkflowExecutionResult(
            workflow_action="GENERATE_REMEDIATION",
            action_title="Advisory Remediation Patch Available",
            summary=(
                f"Deterministic remediation patch generated for {rule_id}. "
                f"Low-risk deterministic fix candidate identified ({decision.confidence:.0%} confidence)."
            ),
            remediation_patch=patch,
        )

    elif action == "ENRICH_CONTEXT":
        enrichment = enrich_finding_context(
            rule_id=rule_id,
            target=target,
            html=html,
            failure_summary=failure_summary,
        )
        return WorkflowExecutionResult(
            workflow_action="ENRICH_CONTEXT",
            action_title="Structural Context Enriched",
            summary=(
                f"Structural DOM context enriched for {rule_id}. "
                f"Finding involves contextual design choices ({decision.confidence:.0%} confidence)."
            ),
            context_enrichment=enrichment,
        )

    else:  # ESCALATE_HUMAN_REVIEW or any unknown/unsupported action safely defaults to human audit
        ticket = escalate_human_review(
            rule_id=rule_id,
            impact=impact,
            description=description,
            html=html,
            failure_summary=failure_summary,
            target_str=target_str,
            rationale=decision.rationale or "Action defaulted safely to human accessibility review.",
            risk_level=decision.risk_level or "high",
        )
        return WorkflowExecutionResult(
            workflow_action="ESCALATE_HUMAN_REVIEW",
            action_title="Civic Auditor Escalation Required",
            summary=(
                f"Automated patching locked for {rule_id}. Finding escalated to human accessibility auditor "
                f"due to {decision.risk_level.upper()} risk ({decision.confidence:.0%} confidence)."
            ),
            escalation_ticket=ticket,
        )


execute_downstream_workflow = execute_workflow

