"""Structured data models for AccessLens AI scan reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any


WCAG_DISCLAIMER = (
    "Axe-core automated accessibility tests identify a subset of machine-detectable WCAG "
    "accessibility barriers (such as missing alt text, contrast violations, and missing form labels). "
    "Automated testing cannot evaluate contextual semantics, screen reader navigation, or cognitive usability. "
    "Zero reported violations does not certify complete WCAG compliance. Comprehensive compliance "
    "requires manual verification by qualified accessibility reviewers using assistive technologies."
)


@dataclass
class ElementNode:
    """A specific DOM element affected by an accessibility violation."""

    target: list[str]
    html: str
    failure_summary: str
    suggested_remediation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "html": self.html,
            "failure_summary": self.failure_summary,
            "suggested_remediation": self.suggested_remediation,
        }


@dataclass
class Violation:
    """An accessibility rule violation reported by axe-core."""

    rule_id: str
    impact: str
    description: str
    help: str
    help_url: str
    tags: list[str]
    nodes: list[ElementNode]
    node_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "impact": self.impact,
            "description": self.description,
            "help": self.help,
            "help_url": self.help_url,
            "tags": self.tags,
            "node_count": self.node_count,
            "nodes": [n.to_dict() for n in self.nodes],
        }


@dataclass
class ScanSummary:
    """Aggregated quantitative summary of an accessibility scan."""

    total_violations: int
    critical_count: int
    serious_count: int
    moderate_count: int
    minor_count: int
    passes_count: int
    inapplicable_count: int
    incomplete_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    """Complete, self-contained accessibility scan report."""

    status: str  # SUCCESS | SCAN_ERROR | SECURITY_BLOCKED
    url: str
    timestamp: str
    duration_ms: float
    engine: str = "axe-core 4.13.0 via Playwright Chromium"
    final_url: str | None = None
    summary: ScanSummary | None = None
    violations: list[Violation] = field(default_factory=list)
    incomplete: list[Violation] = field(default_factory=list)
    error: str | None = None
    error_category: str | None = None
    disclaimer: str = WCAG_DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "url": self.url,
            "final_url": self.final_url or self.url,
            "timestamp": self.timestamp,
            "duration_ms": round(self.duration_ms, 2),
            "engine": self.engine,
            "summary": self.summary.to_dict() if self.summary else None,
            "violations": [v.to_dict() for v in self.violations],
            "incomplete": [i.to_dict() for i in self.incomplete],
            "error": self.error,
            "error_category": self.error_category,
            "disclaimer": self.disclaimer,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class CivicAuditorEscalationTicket:
    """Manual audit escalation ticket generated when a finding poses critical civic or design risk."""

    ticket_id: str
    rule_id: str
    severity: str
    civic_impact_area: str
    risk_level: str
    escalation_reason: str
    manual_testing_checklist: list[str]
    statutory_compliance_note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AdvisoryRemediationPatch:
    """Suggested code patch generated when evidence is deterministic and unambiguous."""

    patch_id: str
    rule_id: str
    original_snippet: str
    proposed_remediation: str
    patch_explanation: str
    verification_checklist: list[str]
    advisory_disclaimer: str = (
        "Advisory recommendation only. Code was not modified or verified on the live website. "
        "Automated tools must not mutate production civic systems without developer sign-off."
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CivicContextEnrichmentReport:
    """Enriched structural and DOM context report generated when initial snippet requires surrounding context."""

    enrichment_id: str
    rule_id: str
    context_depth: str
    detected_container: str
    surrounding_landmark: str
    contextual_notes: list[str]
    investigation_guidance: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowExecutionResult:
    """Downstream execution result determined by Strands Decider 2B policy triage."""

    workflow_action: str  # ESCALATE_HUMAN_REVIEW | GENERATE_REMEDIATION | ENRICH_CONTEXT
    action_title: str
    summary: str
    escalation_ticket: CivicAuditorEscalationTicket | None = None
    remediation_patch: AdvisoryRemediationPatch | None = None
    context_enrichment: CivicContextEnrichmentReport | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_action": self.workflow_action,
            "action_title": self.action_title,
            "summary": self.summary,
            "escalation_ticket": self.escalation_ticket.to_dict() if self.escalation_ticket else None,
            "remediation_patch": self.remediation_patch.to_dict() if self.remediation_patch else None,
            "context_enrichment": self.context_enrichment.to_dict() if self.context_enrichment else None,
        }

