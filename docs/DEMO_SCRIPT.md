# AccessLens AI: Civic Access Auditor — Video Demonstration Script (< 3 Minutes)

> **Total Target Duration**: 2 minutes 45 seconds (165 seconds)  
> **Topic**: Evidence-Gated Civic Accessibility Auditing with Strands Decider 2B Policy Gatekeeping  
> **Required Credit Line**: "Built with the AWS User Group Madurai Strands Decider hackathon kit"  
> **Tags**: `#strands-decider-2b`, `#policy`  
> **Status**: Verified Demonstration Storyboard & Narration (Factual Accuracy Checked)  

---

## Technical Setup Before Recording
1. **Server Running**: Terminal running `python -m accesslens.server --host 127.0.0.1 --port 8000`.
2. **Browser Window**: Chrome/Chromium open to `http://127.0.0.1:8000`.
3. **Environment**: `.env` configured with valid `DECIDER_API_KEY` for hosted Strands Decider 2B (or unconfigured to demonstrate graceful fallback).
4. **Bedrock Status Note**: In accordance with the ₹0 constraint, Amazon Bedrock is set to `LLM_PROVIDER=disabled` by default.

---

## Timeline & Scene Breakdown

```
+---------------+-----------------------------------------------+-----------------------+
| Timestamp     | Visual / On-Screen Action                     | Spoken Narration      |
+---------------+-----------------------------------------------+-----------------------+
| 0:00 - 0:25   | Title screen, credits, & dashboard landing    | Intro & Civic Mission |
| 0:25 - 0:55   | SSRF defense demo & Civic Scholarship Audit   | Real Browser Scan     |
| 0:55 - 1:40   | Decider 2B triage: Path 1 Advisory Patch      | #policy Gatekeeping   |
| 1:40 - 2:15   | Decider 2B triage: Path 2 Human Escalation    | Conservative Safety   |
| 2:15 - 2:45   | Accessible preset, 68 tests, wrap-up          | Verification & Wrap   |
+---------------+-----------------------------------------------+-----------------------+
```

---

### Scene 1: Introduction & The Civic Accessibility Mission (0:00 – 0:25)
**Duration**: 25 seconds  
**Visual**:
- Display title card: **AccessLens AI: Civic Access Auditor — Evidence-Gated Accessibility Agent**.
- Subtitle: *Built with the AWS User Group Madurai Strands Decider hackathon kit*.
- Badges shown: `#strands-decider-2b` | `#policy` | `Apache-2.0`.
- Transition into the clean AccessLens AI dashboard at `http://127.0.0.1:8000`.
- Point to the skip-to-content link and high-contrast keyboard navigation.

**Narration (Spoken)**:
> "Hello! Today we are demonstrating AccessLens AI: Civic Access Auditor, an open-source accessibility auditing agent for public-service websites, scholarships, and welfare portals.
> Public digital services must be accessible to all citizens, but blind automated code modifications risk breaking layout, misleading blind users, or violating statutory guidelines.
> AccessLens AI pairs real browser scanning with the Strands Decider 2B model using our reusable policy pattern to decide whether a barrier can be safely patched, context-enriched, or escalated to human auditors.
> This project was built with the AWS User Group Madurai Strands Decider hackathon kit."

---

### Scene 2: Built-in SSRF Defenses & Civic Scholarship Audit (0:25 – 0:55)
**Duration**: 30 seconds  
**Visual**:
- Enter `http://169.254.169.254` (cloud metadata service) into the URL field and click **Run Audit**.
- Point out the instant red alert: *Scan Target Prohibited by Security Policy (SSRF Guard)*.
- Click the preset: **Scholarship Portal (Local Fixture — Barriers)** (`fixture:civic_scholarship_portal`).
- Point out the prominent banner: **LOCAL CIVIC FIXTURE ACTIVE** (*controlled in-memory scenario, never confused with a live site scan*).
- Click **Run Audit**. Watch the live progress steps: *SSRF Verification -> Chromium DOM Render -> axe-core 4.13.0 Evaluation -> Structure Findings*.
- Scan completes in ~1.5s: 6 violations detected (missing form labels, low contrast, empty document links, table-header issues, unlabelled buttons, missing alt text).

**Narration (Spoken)**:
> "First, security. In public compliance workflows, auditing external URLs poses severe Server-Side Request Forgery risks. AccessLens AI validates DNS and intercepts private IP ranges—attempting to hit cloud metadata or internal subnets is blocked instantly before browser launch.
> Next, we select our civic scholarship preset. This evaluates a realistic public grant application fixture. Notice the clear LOCAL CIVIC FIXTURE label so auditors know it's a controlled in-memory scenario.
> axe-core 4.13.0 evaluates computed DOM styles and catches six representative barriers: missing citizen ID labels, low-contrast buttons, empty document download links, and missing table headers."

---

### Scene 3: Meaningful Decider 2B Triage — Path 1: Advisory Patch (0:55 – 1:40)
**Duration**: 45 seconds  
**Visual**:
- Expand the **`image-alt`** violation (state civic emblem graphic).
- Point to the sanitized HTML snippet, CSS target, and failure summary.
- Click **"Analyze with Decider 2B"**.
- Spinner runs; card displays:
  - **Category**: `Strands Decider 2B Classification`
  - **Action**: `AUTO_FIX_CANDIDATE` (92% confidence, Risk: LOW)
  - **Downstream Workflow Card**: `Advisory Remediation Patch Available`
  - Show the proposed corrected HTML snippet: `<img src="..." alt="Concise description...">`.
  - Show the 4-point developer verification checklist.
  - Highlight the explicit statutory disclaimer: *“Advisory recommendation only. Automated tools must not mutate production civic systems without developer sign-off.”*

**Narration (Spoken)**:
> "Now, how does Strands Decider 2B govern downstream behavior?
> For the state civic emblem missing alt text, we click 'Analyze with Decider 2B'. The model evaluates our typed question and classifies it as AUTO_FIX_CANDIDATE with 92% confidence and low risk.
> Because it is deterministic, the downstream workflow generates an Advisory Remediation Patch with a developer verification checklist. Note that AccessLens AI never directly alters production websites—every patch is strictly advisory for engineering review."

---

### Scene 4: Decider 2B Triage — Path 2: Human-Review Escalation (1:40 – 2:15)
**Duration**: 35 seconds  
**Visual**:
- Expand the **`color-contrast`** or **`label`** violation (citizen identity input / submit button).
- Click **"Analyze with Decider 2B"**.
- The card updates:
  - **Action**: `HUMAN_REVIEW` (Risk: HIGH)
  - **Downstream Workflow Card**: `Civic Auditor Escalation Required`
  - Show the generated **Civic Auditor Escalation Ticket** with ticket ID (`ESC-XXXXXXXX`).
  - Highlight the categorized civic impact area: *Citizen Applications & Public Benefit Forms*.
  - Show the **4-Step Manual Assistive Technology Testing Checklist**:
    1. Screen reader announcement protocol (NVDA / JAWS / VoiceOver).
    2. Keyboard-only navigation and focus indicator check.
    3. Plain-language and statutory clarity check.
    4. 200% and 400% zoom reflow verification.
  - Point to the Statutory Notice explaining automated remediation is blocked.

**Narration (Spoken)**:
> "Now let's see how the Decider alters the downstream path when risks are high.
> For the low-contrast submit button or citizen identity input, modifying styles blindly could break departmental branding or disorient low-vision users.
> Decider 2B classifies this as HUMAN_REVIEW with high risk. The downstream engine immediately locks automated patching and issues a formal Civic Auditor Escalation Ticket. It provides auditors with a mandatory four-step manual testing protocol covering screen readers, keyboard navigation, and zoom reflow."

---

### Scene 5: Accessible Preset, 68 Offline Tests, & Wrap-Up (2:15 – 2:45)
**Duration**: 30 seconds  
**Visual**:
- Click the second preset: **Citizen Benefits (Local Fixture — Accessible)** (`fixture:civic_accessible_portal`).
- Click **Run Audit**.
- Scan completes with **0 violations** and **43 passed checks**.
- Highlight the **Mandatory Civic Manual Compliance Testing Protocol** callout in the dashboard:
  - *"Zero reported violations does not certify complete WCAG compliance. Comprehensive compliance requires manual testing."*
- Switch to terminal: run `pytest`.
- Terminal shows: `============================= 68 passed in 22.19s =============================`.
- Return to dashboard, toggle Light/Dark mode, and show closing credits.

**Narration (Spoken)**:
> "Finally, we audit our accessible citizen benefits portal. It achieves zero automated violations and 43 passes, but AccessLens AI does not make false compliance claims: our dashboard prominently displays the mandatory manual review protocol.
> Behind the scenes, all 68 unit and integration tests run 100% offline in just 22 seconds with zero cloud spending.
> AccessLens AI: Civic Access Auditor combines real browser heuristics with Strands Decider 2B policy gatekeeping to protect digital equity for all citizens.
> Thank you!"

---

*Tags: `#strands-decider-2b`, `#policy`*  
*Built with the AWS User Group Madurai Strands Decider hackathon kit*
