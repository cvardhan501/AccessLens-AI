# Intelligent Civic Accessibility Triage with Strands Decider 2B: Safeguarding Public Digital Services

*By the AccessLens AI Team*  
*Tags: `#strands-decider-2b`, `#policy`, `Accessibility`, `CivicTech`, `DevSecOps`, `Playwright`, `FastAPI`*  
*Built with the AWS User Group Madurai Strands Decider hackathon kit*

---

## 1. The Civic Accessibility Problem: When Digital Barriers Lock Out Citizens

Public-service websites—such as state scholarship applications, pension enrollment forms, citizen grievance portals, and public health notice boards—serve as vital digital infrastructure. For elderly citizens, people who are blind, individuals with motor disabilities, or citizens with low vision, an accessible web portal is the only bridge to receiving statutory welfare support.

According to WebAIM's annual analysis of the world's top one million web pages, over **96% of homepages fail automated accessibility audits**. On civic websites, common barriers include:
- Unlabelled citizen identity inputs that screen readers cannot announce.
- Low-contrast submit buttons that wash out on low-cost devices or in outdoor sunlight.
- Empty document download links with no discernible purpose.
- Data tables without header cells, disorienting citizens navigating entitlement schedules.
- Missing alternative text on official seals and security graphics.

### The Danger of Blind Automated Remediation
Modern engineering teams frequently turn to automated testing engines like **axe-core** inside CI/CD pipelines. While automated testing efficiently catches machine-detectable syntax errors, attempting **blind automated code remediation** on public websites introduces severe operational and legal risks:
1. **Misleading Citizens**: If an automated tool encounters an empty alt attribute on a state welfare seal and inserts generic placeholder text like `alt="image"`, screen reader users miss crucial validation context.
2. **Brand & Statutory Violations**: Automatically altering CSS colors to satisfy contrast ratios can violate strict departmental visual identity guidelines or clash with emergency notice palettes.
3. **Semantic Rupture**: Modifying complex form inputs or ARIA widget roles without human verification can render a citizen's application completely un-submittable.

Public digital systems cannot tolerate blind AI code mutation. What civic engineering teams need is an **evidence-gated policy decider** that determines whether a violation can be safely repaired through advisory code suggestions, enriched with DOM container context, or escalated to human accessibility auditors.

---

## 2. Enter AccessLens AI: Civic Access Auditor

**AccessLens AI** is an open-source (Apache-2.0) accessibility auditing and decision agent designed specifically for public-service and civic portals.

```
+-----------------------------------------------------------------------------------------------+
|                            AccessLens AI: Civic Access Auditor                                |
|                                                                                               |
|  [Civic Preset / URL] --> [SSRF Guard & DNS Validation] --> [Playwright Chromium Headless]   |
|                                                                          |                    |
|                                                                          v                    |
|                                                               [axe-core 4.13.0 Engine]        |
|                                                                          |                    |
|                                                                          v                    |
|                                                           [Privacy-Sanitized Finding Node]    |
|                                                                          |                    |
|                                                                          v                    |
|                                                            +--------------------------+       |
|                                                            | Strands Decider 2B       |       |
|                                                            | Pattern: #policy         |       |
|                                                            | POST /v1/decide          |       |
|                                                            +--------------------------+       |
|                                                                          |                    |
|                     +----------------------------------------------------+----------------+   |
|                     |                                                    |                |   |
|                     v (Conf >= 85% & Low Risk)                           v (Conf < 70%    v   |
|                                                                             or Critical)      |
|           [GENERATE_REMEDIATION]                                         |                |   |
|                     |                                                    v                v   |
|                     v                                         [ESCALATE_HUMAN_REVIEW] [ENRICH_CONTEXT]
|         AdvisoryRemediationPatch                                         |                |   |
|       - Proposed HTML snippet                                            v                v   |
|       - Developer checklist                                   CivicAuditorTicket   EnrichmentReport
|       - Advisory disclaimer                                  - 4-Step AT Protocol - DOM Landmark
|                                                              - Statutory Notice   - Container
+-----------------------------------------------------------------------------------------------+
```

### Architectural Pillars
1. **Real Browser-Grade Scanning**: Uses Playwright Chromium to render full client-side JavaScript Single Page Applications (SPAs), evaluate computed CSS styles, and inject the official `axe-core 4.13.0` engine.
2. **Multi-Layered SSRF & Network Defenses**: Protects internal infrastructure by validating schemes (`http`/`https`), resolving DNS before browser launch, and strictly blocking loopback (`127.0.0.0/8`), private RFC 1918 subnets, and cloud metadata services (`169.254.169.254`).
3. **Selectable Civic Demo Presets**: Pre-configured with realistic local civic scenarios:
   - *Public Scholarship Portal* (`fixture:civic_scholarship_portal`): Features intentional representative civic barriers (unlabelled inputs, low contrast, empty table headers, unlabelled search button, missing image alt text).
   - *Accessible Benefits Portal* (`fixture:civic_accessible_portal`): Verified against axe-core (0 violations, 43 passes) accompanied by the honest WCAG scope disclaimer and manual review requirements.
   - *W3C WAI Standards Reference*: Live public external URL.
4. **Prominent Fixture Mode Identification**: Controlled test scenarios are badged as `LOCAL CIVIC FIXTURE`, guaranteeing that local fixtures are never misrepresented as live website scans.
5. **Strands Decider 2B Gatekeeping (`#policy`)**: Evaluates sanitized findings via the AWS User Group Madurai hosted endpoint (`/v1/decide`) to classify triage actions.

---

## 3. The Meaningful Decision: Why Strands Decider 2B?

In automated compliance workflows, using a large conversational language model introduces distinct failure modes:
- **Unconstrained Output**: General chat models produce free-form paragraphs that require fragile regex parsing, whereas automated pipelines require deterministic categorical decisions.
- **Hallucination Risk**: Large LLMs frequently invent non-existent WCAG criteria or suggest invalid ARIA markup.
- **Latency & Cost Overhead**: Generating conversational text across hundreds of findings incurs heavy token costs and multi-second delays.

In contrast, **Strands Decider 2B** is designed specifically for structured decision problems:
- **Typed Question Contract**: Evaluates structured `choice` and `score` questions in a single forward pass.
- **Calibrated Probability Distributions**: Returns exact mathematical probabilities across permitted choices, enabling rigorous safety threshold gates.
- **Sub-Second Latency**: In our testing of the hosted endpoint, single-finding classification completed in approximately 825 ms.
- **Zero Hallucination Surface**: The model selects strictly from predefined operational choices without generating unconstrained code.

---

## 4. The Reusable Decision Pattern: `#policy`

We formalized our triage logic into the reusable decision pattern **`#policy`**.

### Input State Representation
The finding state is bounded, stripped of scripts and styles, and capped at $\le 300$ characters with sensitive query parameters redacted:

```text
ACCESSIBILITY AUDIT FINDING:
- Rule ID: image-alt
- Severity Impact: critical
- Description: Ensures <img> elements have alternate text or a role of none or presentation
- CSS Target: #main-content > header.banner > img#civic-seal-graphic
- Element Evidence: <img id="civic-seal-graphic" src="state_civic_emblem.png" width="64" height="64">
- Failure Summary: Fix any of the following: Element does not have an alt attribute
```

### Typed Questions & Criteria
1. **`action`** (`type: choice`):
   - `AUTO_FIX_CANDIDATE`: Unambiguous deterministic fix with minimal risk of breaking page semantics or requiring design decisions.
   - `EXPLAIN_ONLY`: Clear context and educational guidance, but code modification is risky or involves subjective design choices.
   - `HUMAN_REVIEW`: High impact or critical barrier, complex ARIA widget roles, color contrast changes involving brand palette, or ambiguous context requiring manual human judgment.
2. **`risk_level`** (`type: score`): Discrete rating scale: `low`, `medium`, `high`, `critical`.

---

## 5. Downstream Execution Branches

The Decider's classification is not merely cosmetic; it directly drives **three distinct, testable downstream execution paths**:

### Path 1: `GENERATE_REMEDIATION` (Advisory Remediation Patch)
When the Decider classifies a finding as `AUTO_FIX_CANDIDATE` with $\ge 85\%$ confidence for critical issues or $\ge 70\%$ for low-risk issues:
- Generates an `AdvisoryRemediationPatch` containing the proposed HTML fix and a 4-point verification checklist.
- Includes a statutory notice: *“Advisory recommendation only. Code was not modified or verified on the live website. Automated tools must not mutate production civic systems without developer sign-off.”*

### Path 2: `ENRICH_CONTEXT` (DOM Container & Landmark Analysis)
When the Decider returns `EXPLAIN_ONLY` or indicates that the element snippet requires surrounding context:
- Executes in-memory structural analysis of the DOM hierarchy.
- Identifies the surrounding container (`form_group`, `tabular_data_structure`, `navigation_bar`, `primary_content_region`) and W3C landmark (`form`, `navigation`, `main`).
- Emits a `CivicContextEnrichmentReport` guiding developers on form semantics and layout clarity.

### Path 3: `ESCALATE_HUMAN_REVIEW` (Human Auditor Escalation Ticket)
When the Decider returns `HUMAN_REVIEW`, or when confidence falls below safety thresholds, or when critical severity is detected:
- Generates a structured `CivicAuditorEscalationTicket` with a unique ticket ID.
- Categorizes the civic impact area (*Citizen Applications & Public Benefit Forms*, *Citizen Authentication*, *Low-Vision Access*).
- Prescribes a mandatory 4-step manual testing protocol:
  1. Screen reader flow verification (NVDA, JAWS, VoiceOver).
  2. Keyboard-only navigation and focus-indicator visibility inspection.
  3. Cognitive plain-language clarity check.
  4. 200% and 400% zoom reflow verification.
- Attaches a statutory notice explaining that automated testing covers only a subset of WCAG criteria and human auditor sign-off is legally required.

---

## 6. Conservative Safeguards & Honesty Principles

1. **Confidence Threshold Gates**: Any classification with $< 70\%$ confidence is automatically demoted to `HUMAN_REVIEW`.
2. **Critical Severity Penalty Guard**: Critical or serious violations must achieve $\ge 85\%$ confidence to remain `AUTO_FIX_CANDIDATE`; otherwise, they are demoted to `HUMAN_REVIEW`.
3. **No Direct Code Mutation**: AccessLens AI never writes to or executes code on the target website. All patches are advisory.
4. **Honest Automated Testing Scope**: The dashboard and scan reports explicitly state:
   > *"Axe-core automated accessibility tests identify a subset of machine-detectable WCAG criteria (such as missing alt text, contrast violations, and form labels). Zero reported violations does NOT certify complete WCAG compliance. Comprehensive civic accessibility requires human evaluation with assistive technologies."*

---

## 7. Step-by-Step Reproduction Guide (₹0 Spent)

Any developer or evaluator can run and verify the entire system locally without spending any money:

```bash
# 1. Clone repository and install dependencies
git clone <repo-url>
cd AccessLens-AI
pip install -r requirements.txt
playwright install chromium

# 2. Run the complete offline test suite (68 tests, 100% passing)
pytest

# 3. Launch the web dashboard
python -m accesslens.server --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in your browser:
1. Click **Scholarship Portal (Local Fixture — Barriers)** to audit the civic scholarship portal.
2. Expand the `image-alt` or `button-name` finding and click **"Analyze with Decider 2B"** to witness policy triage and downstream advisory patch generation.
3. Click **Citizen Benefits (Local Fixture — Accessible)** to see 0 automated violations with 43 passed checks and inspect the mandatory civic manual review protocol.

---

## 8. Summary & Next Steps

AccessLens AI: Civic Access Auditor demonstrates that combining deterministic browser-grade scanning with the lightweight, calibrated **Strands Decider 2B** model creates a safe, evidence-grounded gatekeeper for web accessibility. By rejecting blind code modifications and prioritizing human review where risks are high, we protect both engineering integrity and the rights of citizens with disabilities.

---

*Tags: `#strands-decider-2b`, `#policy`*  
*Built with the AWS User Group Madurai Strands Decider hackathon kit*
