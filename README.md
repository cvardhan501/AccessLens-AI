# AccessLens AI: Civic Access Auditor — Evidence-Gated Accessibility Agent

> **Deterministic Civic Web Accessibility Auditing powered by Playwright and axe-core 4.13.0.**  
> **Intelligent Triage & Remediation Gatekeeping powered by Strands Decider 2B.**  
> **Built with the AWS User Group Madurai Strands Decider hackathon kit**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Pattern](https://img.shields.io/badge/Pattern-%23policy-success)](#reusable-decision-pattern-policy)
[![Model](https://img.shields.io/badge/Model-%23strands--decider--2b-orange)](#strands-decider-2b-integration)
[![Tests](https://img.shields.io/badge/Tests-68%20Passing%20(100%25)-brightgreen)](#running-the-automated-test-suite)
[![Axe-core](https://img.shields.io/badge/Engine-axe--core%204.13.0-informational)](#key-capabilities)

AccessLens AI: Civic Access Auditor is an open-source (Apache-2.0) accessibility auditing and decision agent designed for public-service, education, scholarship, and digital governance websites. It combines real browser-grade client DOM scanning via **axe-core 4.13.0** with **Strands Decider 2B** policy triage (**`#policy`**) to safely gate automated remediation and protect citizens with disabilities.

---

## Required Submission Tags & Credits

- **Decision Pattern Tag**: `#policy`
- **Model Tag**: `#strands-decider-2b`
- **Kit Credit**: Built with the AWS User Group Madurai Strands Decider hackathon kit
- **Documentation**:
  - [Reusable Decision Pattern Guide (docs/DECISION_PATTERN.md)](docs/DECISION_PATTERN.md)
  - [AWS Builder Center Draft Article (docs/ARTICLE.md)](docs/ARTICLE.md)
  - [3-Minute Video Demonstration Script (docs/DEMO_SCRIPT.md)](docs/DEMO_SCRIPT.md)

---

## The Civic Access Mission

Public websites—such as government welfare portals, state scholarship applications, pension enrollment forms, and statutory notice boards—serve as essential lifelines for citizens. When these portals have digital barriers (such as unlabelled identity inputs, low-contrast buttons, inaccessible data tables, or uncaptioned icons), elderly citizens and people using assistive technologies (screen readers, braille displays, keyboard-only navigation) are locked out of essential services.

At the same time, **blind automated remediation on civic websites is dangerous**:
- An automated tool that replaces missing form labels with arbitrary text can cause citizens to submit incorrect statutory information.
- Modifying brand colors or buttons automatically can break established departmental visual identity or fail contrast in varied outdoor sunlight.
- Automated tools must **never directly execute or mutate code on production civic websites**.

AccessLens AI addresses this challenge through **evidence-gated policy triage**: every automated finding is evaluated against calibrated confidence thresholds and routed to the correct downstream workflow.

---

## Key Capabilities

1. **Deterministic axe-core 4.13.0 Engine**: Bundles the official `axe-core 4.13.0` evaluation script inside headless Playwright Chromium. Captures computed styles, DOM accessibility trees, and exact element selectors.
2. **Strands Decider 2B Policy Gatekeeping (`#policy`)**: Routes findings through the hosted 2B decision model using calibrated probabilities to determine the safest operational path.
3. **Three Genuinely Distinct Downstream Workflows**:
   - `GENERATE_REMEDIATION`: Synthesizes an `AdvisoryRemediationPatch` with a developer verification checklist (strictly advisory; never mutates live websites).
   - `ENRICH_CONTEXT`: Synthesizes a `CivicContextEnrichmentReport` analyzing surrounding form containers and landmark structures.
   - `ESCALATE_HUMAN_REVIEW`: Locks automated patching and issues a `CivicAuditorEscalationTicket` with a 4-step manual assistive technology testing checklist and statutory compliance notice.
4. **Selectable Local Civic Demo Presets**:
   - **Scholarship Application Portal** (`fixture:civic_scholarship_portal`): Realistic civic portal fixture featuring intentional representative barriers: missing form labels (`label`), low contrast (`color-contrast`), unclear document links (`link-name`), empty table headers (`empty-table-header`), unlabelled buttons (`button-name`), and missing alt text (`image-alt`).
   - **Citizen Benefits Portal** (`fixture:civic_accessible_portal`): High-contrast accessible portal fixture verified against axe-core (0 violations, 43 passes) accompanied by the honest WCAG scope disclaimer and manual review requirements.
   - **W3C WAI Standards Reference**: Real public external URL (`https://www.w3.org/WAI/standards-guidelines/wcag/`).
5. **Clear Fixture Mode Identification**: Audits of local test scenarios are prominently badged as `LOCAL CIVIC FIXTURE`, clearly explaining that controlled in-memory conditions were evaluated without live network calls.
6. **Multi-Layered SSRF & Network Guard**:
   - Strictly validates `http` and `https` schemes.
   - Resolves DNS before browser navigation.
   - Blocks loopback (`127.0.0.0/8`, `::1`), private RFC 1918 subnets, link-local, and cloud metadata services (`169.254.169.254`).
   - Re-verifies redirect destinations.
7. **Honest WCAG Coverage Scope**: Clearly explains that automated testing covers only a subset of machine-detectable criteria; zero reported automated violations does NOT certify complete WCAG compliance.
8. **Decoupled Architecture & ₹0 Spending**: Runs 100% locally with zero cloud spending. Amazon Bedrock is supported as an optional explainer module (`accesslens/bedrock.py`) via the Strands Agents SDK, with `LLM_PROVIDER=disabled` as default.

---

## Architecture

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

---

## Project Structure

```
AccessLens-AI/
├── accesslens/
│   ├── __init__.py           # Package exports and version metadata
│   ├── cli.py                # Command-line interface with arg parsing
│   ├── config.py             # Safe configuration manager with secrets redaction
│   ├── db.py                 # SQLite scan history persistence and retrieval
│   ├── decider.py            # Strands Decider 2B adapter & #policy decision pattern
│   ├── bedrock.py            # Optional Amazon Bedrock explainer (Strands Agents SDK)
│   ├── models.py             # Structured dataclasses (ScanReport, Violation, etc.)
│   ├── scanner.py            # Core Playwright + axe-core scanning engine
│   ├── security.py           # SSRF protection, IP resolution, and redirect guard
│   ├── server.py             # FastAPI REST API, fixture serving & dashboard backend
│   ├── workflow.py           # Downstream workflow engine (remediation/escalation/enrichment)
│   ├── static/               # Accessible web dashboard frontend (Vanilla CSS & JS)
│   │   ├── app.js
│   │   ├── index.html
│   │   └── styles.css
│   └── vendor/
│       ├── __init__.py       # Vendor asset loader
│       └── axe.min.js        # Official axe-core 4.13.0 engine
├── docs/
│   ├── ARTICLE.md            # AWS Builder Center draft article
│   ├── DECISION_PATTERN.md   # Reusable Strands Decider 2B #policy pattern documentation
│   └── DEMO_SCRIPT.md        # < 3-minute video demonstration script
├── tests/
│   ├── fixtures/
│   │   ├── accessible.html             # Clean baseline fixture
│   │   ├── inaccessible.html           # Flawed baseline fixture
│   │   ├── civic_scholarship_portal.html # Civic portal fixture with representative barriers
│   │   └── civic_accessible_portal.html  # Accessible civic portal fixture (WCAG 2.1 AA)
│   ├── test_ai.py            # Deterministic offline Decider, Bedrock & workflow tests
│   ├── test_cli.py           # CLI invocation, stdout, and file output tests
│   ├── test_db.py            # SQLite database persistence tests
│   ├── test_scanner.py       # Playwright scanner tests against real HTTP & civic fixtures
│   ├── test_security.py      # SSRF, scheme, private IP, and redirect guard tests
│   └── test_server.py        # FastAPI server, fixture serving, & REST API tests
├── .env.example              # Template environment configuration
├── .gitignore                # Git exclusions (strictly excludes .env and sqlite databases)
├── LICENSE                   # Official Apache-2.0 License
├── pytest.ini                # Pytest configuration
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation and submission guide
```

---

## Quick Start: Running the Local Demo

### 1. Prerequisites & Virtual Environment

AccessLens AI requires **Python 3.10+** and **Playwright Chromium**.

```bash
# 1. Navigate to the project directory
cd AccessLens-AI

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install Playwright Chromium browser
playwright install chromium
```

### 2. Configure Environment

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Ensure `.env` contains:
```bash
DECIDER_MODE=ugmdu
DECIDER_URL=https://da25tnxy06gjk.cloudfront.net
DECIDER_API_KEY=your_ugmdu_api_key_here
DECIDER_CONFIDENCE_THRESHOLD=0.70
LLM_PROVIDER=disabled
HOST=127.0.0.1
PORT=8000
DATABASE_URL=sqlite:///accesslens.db
```

> **Security Guarantee:** Secrets in `.env` are git-ignored. The application redacts keys in all logs, `/api/config`, and outgoing Decider state evidence.

### 3. Launch Web Dashboard

```bash
python -m accesslens.server --host 127.0.0.1 --port 8000
```

Open your browser to `http://127.0.0.1:8000`.

### 4. Try the Civic Presets

1. Click **Scholarship Portal (Local Fixture — Barriers)**:
   - Initiates in-memory evaluation of `fixture:civic_scholarship_portal`.
   - Badged with prominent `LOCAL CIVIC FIXTURE` banner.
   - Detects real violations: missing form labels (`label`), low contrast (`color-contrast`), empty link (`link-name`), empty table header (`empty-table-header`), unlabelled button (`button-name`), and missing alt text (`image-alt`).
   - Click **"Analyze with Decider 2B"** on any finding to observe policy triage and downstream workflow execution.
2. Click **Citizen Benefits (Local Fixture — Accessible)**:
   - Evaluates `fixture:civic_accessible_portal`.
   - Returns 0 automated violations with 43 passed checks.
   - Renders the **Mandatory Civic Manual Compliance Testing Protocol** reminding auditors that automated testing does not certify full compliance.
3. Click **W3C WAI Standards (External Live URL)**:
   - Demonstrates live public scanning with real Playwright browser navigation.

---

## Running the Complete Offline Test Suite

All 68 unit and integration tests run **100% offline** without live network calls, without invoking Bedrock, and without consuming Decider quota.

```bash
pytest
```

### Test Suite Structure (68 Tests, 100% Passing)

| Test Module | Coverage Area | Tests |
|---|---|---|
| `tests/test_ai.py` | Decider wire format, confidence demotion, static WCAG guidance, Bedrock decoupling, and downstream workflow branching | 35 |
| `tests/test_server.py` | FastAPI endpoints, fixture serving, fixture: scheme audit, and REST API | 9 |
| `tests/test_security.py` | SSRF defense, private RFC 1918 blocks, cloud metadata (169.254.169.254), redirect validation | 8 |
| `tests/test_scanner.py` | Playwright axe-core execution on accessible, inaccessible, and civic fixtures | 7 |
| `tests/test_db.py` | SQLite persistence, ordering, pagination, deletion | 5 |
| `tests/test_cli.py` | Command line flags, exit codes, output files, SSRF CLI blocking | 4 |
| **Total** | **Comprehensive offline test suite** | **68 Passing** |

---

## Reusable Decision Pattern: #policy

AccessLens AI uses Strands Decider 2B for **automated triage and policy gatekeeping** (`#policy`).

### 1. Decision Questions & Option Set
The decider answers two structured questions:
1. **`action`** (`type: choice`):
   - `AUTO_FIX_CANDIDATE`: Deterministic, low-risk fix with minimal risk of breaking layout or semantics.
   - `EXPLAIN_ONLY`: Clear informative context, but code modification involves subjective design choices.
   - `HUMAN_REVIEW`: Critical severity, complex ARIA widget roles, color contrast affecting brand palettes, or ambiguous context.
2. **`risk_level`** (`type: score`): Discrete rating scale: `low`, `medium`, `high`, `critical`.

### 2. Conservative Safety Gates
- **Base Confidence Threshold (`0.70`)**: Any decision with confidence $< 70\%$ is automatically demoted to `HUMAN_REVIEW`.
- **Severity-Sensitive Demotion (`0.85`)**: For `critical` and `serious` violations, candidates require $\ge 85\%$ confidence to remain `AUTO_FIX_CANDIDATE`. Below 85%, they are demoted to `HUMAN_REVIEW`.
- **Fail-Safe Fallback**: If network errors or HTTP 401/402/429/503 occur, the system safely defaults to `HUMAN_REVIEW` with deterministic static WCAG guidance.

For complete integration code and architectural details, see [docs/DECISION_PATTERN.md](docs/DECISION_PATTERN.md).

---

## Honest Scope & Limitations

- **Automated Detection Scope**: Automated engines like `axe-core` reliably check rules with deterministic heuristics (syntax, missing attributes, computed contrast ratios). Subjective requirements—such as screen reader announcement clarity, logical focus management across modals, and cognitive readability—require manual testing. Zero reported automated violations does not guarantee complete WCAG compliance.
- **Advisory Recommendations**: Remediation guidance and Decider suggestions are strictly advisory. AccessLens AI never mutates target production websites.
- **Cloud Independence**: Scanning, persistence, and static guidance require zero external cloud resources. AI triage utilizes only the designated Strands Decider 2B endpoint.

---

## License

This project is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for the full license text.

---

## Acknowledgments

Built with the AWS User Group Madurai Strands Decider hackathon kit.
