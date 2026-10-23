# AccessLens AI: Civic Accessibility Auditor Governed by Strands Decider 2B Policy Gatekeeping

By C Vishnu Vardhan

Public digital services like scholarship portals, pension enrollment forms, and citizen grievance desks are essential lifelines, yet WebAIM reports that over 96% of public homepages fail automated accessibility audits. But blind automated code remediation on public websites is dangerous: altering colors breaks statutory brand guidelines, auto-generating alt text injects misleading placeholders on official state seals, and modifying form controls can corrupt citizen benefit submissions. I built AccessLens AI, an open-source civic accessibility auditing agent that pairs Playwright and axe-core 4.13.0 with Strands Decider 2B policy gatekeeping (#policy) to evaluate findings and enforce human-review safeguards, verified with 68 passing offline tests and zero unauthorized code mutation.

## The project

AccessLens AI is designed for civic software engineers, government digital service teams, and accessibility auditors responsible for public-service web applications. Public portals must serve all citizens, including elderly individuals, blind citizens using screen readers, people with motor impairments navigating by keyboard, and citizens with low vision.

When automated tools detect accessibility violations on public portals, ordinary tools either dump raw JSON reports that overwhelm developers or attempt blind automated code rewrites that introduce legal and operational risks. AccessLens AI provides an evidence-gated alternative:

- Deterministic browser scanning: Uses headless Playwright Chromium to render full client-side JavaScript Single Page Applications (SPAs), evaluate computed CSS styles, and inject the official axe-core 4.13.0 engine.
- Multi-layered SSRF defense: Validates schemes, pre-resolves DNS before browser navigation, and blocks loopback addresses, private RFC 1918 subnets, and cloud metadata services.
- Civic presets: Includes pre-configured civic scenarios such as a scholarship portal fixture featuring representative barriers (unlabelled identity inputs, low-contrast buttons, empty table headers, uncaptioned search buttons, missing image alt text) and an accessible benefits portal fixture with honest WCAG scope disclaimers.
- Clear fixture mode identification: Audits of local test scenarios are prominently badged as LOCAL CIVIC FIXTURE, guaranteeing that controlled in-memory tests are never misrepresented as live website audits.

< FIGURE 1 of 4: upload submission/article/img/demo-dashboard.png here >
Alt text: AccessLens AI web dashboard showing civic portal audit results, compliance score, violation distribution, and finding cards

When auditing the civic scholarship portal preset, AccessLens AI renders the page, executes axe-core, and reports six representative barriers categorized by WCAG impact. Instead of mutating live code, the auditor expands any finding and invokes policy triage.

## How I built it

AccessLens AI is built with Python 3.12 and FastAPI, backed by a local SQLite database running in WAL mode for persistent audit logs and scan history. The frontend dashboard uses vanilla HTML, CSS, and JavaScript, providing high-contrast themes, keyboard navigation, and transparent evidence cards.

In public compliance workflows, auditing external URLs introduces severe Server-Side Request Forgery (SSRF) risks. I implemented a strict multi-layer defense in accesslens/security.py:
- Scheme restriction: Only http and https schemes are permitted.
- Pre-flight DNS resolution: Hostnames are resolved to IP addresses before launching the browser.
- Network blocklist: Rejects IPv4 loopback (127.0.0.0/8), IPv6 loopback (::1), private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), link-local addresses, and cloud metadata services (169.254.169.254).
- Redirect protection: HTTP redirects are intercepted and re-validated against the same IP safety rules.

< FIGURE 2 of 4: upload submission/article/img/demo-ssrf.png here >
Alt text: AccessLens AI SSRF defense blocking an attempt to scan cloud metadata service 169.254.169.254

Before sending an accessibility finding to Strands Decider 2B, AccessLens AI constructs a bounded, privacy-safe state string. Script tags and style blocks are stripped, query tokens (token, key, secret, password) are replaced with [REDACTED], and the raw HTML snippet is capped at 300 characters.

< FIGURE 3 of 4: upload submission/article/img/architecture.png here >
Alt text: Architecture diagram of AccessLens AI showing audit input, SSRF guard, axe-core engine, sanitized finding state, Strands Decider 2B policy triage, and three downstream execution branches

For architectural completeness, AccessLens AI includes an optional Amazon Bedrock explainer module in accesslens/bedrock.py using the Strands Agents SDK. By default, the application runs offline with LLM_PROVIDER=disabled at zero cloud cost, using deterministic static WCAG guidance. In addition to offline validation, we verified the live integration via a successful application-level request through POST /api/findings/analyze to Amazon Nova Pro (us.amazon.nova-pro-v1:0) in us-east-1. In this verified run, the Strands Decider 2B policy gate evaluated the input finding and returned HUMAN_REVIEW at 19.41% confidence. Because this fell below the 70% confidence safety threshold, automated patching was locked, and Amazon Nova Pro generated contextual advisory remediation guidance tailored to the finding. The observed end-to-end round-trip latency for this single live request was approximately 5.1 seconds. We explicitly emphasize that this is an empirical observation of a single request, not a formal performance benchmark. Bedrock served strictly in an advisory capacity: it never overrode the Decider policy gate, never mutated live code, and preserves strict human-review safeguards with immediate fallback to static guidance if Bedrock is disabled, uncredentialed, or times out.

## The decision I handed to Strands Decider 2B

In automated compliance auditing, delegating decisions to large conversational language models has significant downsides: chat models generate unconstrained text requiring brittle regex parsing, risk hallucinating invalid WCAG rules or ARIA roles, and incur high latency.

Strands Decider 2B is an open 2-billion-parameter decision model that reads structured state and typed questions, returning exact mathematical probability distributions across permitted options in a single forward pass. I formalized our triage logic into the reusable decision pattern #policy using two typed questions:

```python
QUESTIONS = {
    "action": {
        "type": "choice",
        "instructions": "Based on the accessibility violation rule, severity, and HTML snippet, what is the recommended remediation action?",
        "criteria": {
            "AUTO_FIX_CANDIDATE": "Unambiguous deterministic fix with minimal risk of breaking page semantics or requiring design decisions (e.g. alt attribute on standalone images or label for an id)",
            "EXPLAIN_ONLY": "Clear context and guidance, but automated code generation is risky or involves subjective design choices",
            "HUMAN_REVIEW": "High impact or critical barrier, complex ARIA widget roles, color contrast changes involving brand palette, or ambiguous context requiring manual judgment",
        },
    },
    "risk_level": {
        "type": "score",
        "instructions": "Rate the technical and visual risk of modifying this element automatically:",
        "criteria": ["low", "medium", "high", "critical"],
    },
}
```

The Decider's classification directly drives three distinct downstream execution branches in accesslens/workflow.py:

1. GENERATE_REMEDIATION: When the model classifies a finding as AUTO_FIX_CANDIDATE with high confidence, the agent synthesizes an AdvisoryRemediationPatch. This includes the proposed HTML fix, a 4-point developer verification checklist, and an explicit disclaimer: "Advisory recommendation only. Code was not modified or verified on the live website. Automated tools must not mutate production civic systems without developer sign-off."
2. ENRICH_CONTEXT: When the model returns EXPLAIN_ONLY, the agent conducts in-memory structural DOM analysis to identify surrounding containers (form_group, table, navigation_bar) and W3C landmarks (main, nav, form), producing a CivicContextEnrichmentReport.
3. ESCALATE_HUMAN_REVIEW: When the model returns HUMAN_REVIEW, or when confidence falls below safety thresholds, the agent locks automated patching and issues a formal CivicAuditorEscalationTicket with a unique tracking ID and a mandatory 4-step manual assistive technology evaluation protocol.

< FIGURE 4 of 4: upload submission/article/img/demo-analysis.png here >
Alt text: Strands Decider 2B finding analysis card showing calibrated confidence, policy triage, and downstream advisory remediation patch with developer verification checklist

I implemented two conservative safety thresholds:
- Confidence floor: Any classification with confidence below 70% is automatically demoted to HUMAN_REVIEW.
- Critical severity penalty: Critical or serious violations must achieve at least 85% confidence to remain an AUTO_FIX_CANDIDATE; otherwise they are immediately demoted to HUMAN_REVIEW.

## Measured

Rather than fabricating synthetic benchmarks or presenting uncalibrated single-request response times, I evaluated AccessLens AI through a comprehensive offline test suite.

The repository includes 68 unit and integration tests across six test modules, achieving a 100% pass rate:
- tests/test_ai.py (35 tests): Validates Decider payload wire formatting, 70% confidence floor enforcement, 85% critical severity penalty demotions, HTTP error mappings (401, 402, 429, 503), graceful unconfigured fallbacks, static WCAG guidance, and downstream workflow dispatch.
- tests/test_security.py (8 tests): Validates scheme enforcement, loopback blocking, private RFC 1918 subnet blocking, cloud metadata blocking (169.254.169.254), internal domain blocking, and HTTP redirect re-validation.
- tests/test_scanner.py (7 tests): Validates headless Playwright scanning, axe-core 4.13.0 script execution, in-memory HTML scanning, and civic portal barrier detection.
- tests/test_server.py (9 tests): Validates FastAPI REST endpoints, SSRF rejection responses, scan history retrieval, and fixture routes.
- tests/test_db.py (5 tests): Validates SQLite schema initialization, WAL mode persistence, scan history pagination, and error record isolation.
- tests/test_cli.py (4 tests): Validates command-line interface arguments, default SSRF enforcement, and JSON report generation.

Regarding latency, single-call response time on the hosted Decider endpoint reflects internet round-trip to the AWS User Group Madurai hosted server and is not presented as a formal benchmark. Similarly, our verified live invocation of Amazon Nova Pro (us.amazon.nova-pro-v1:0) through POST /api/findings/analyze recorded an observed latency of approximately 5.1 seconds for that single application-level request. We explicitly state that this is an empirical observation, not a performance benchmark. Across both the offline test suite and the live Bedrock integration, the architectural separation of concerns remains strict: Strands Decider 2B acts as the authoritative policy gatekeeper (classifying the sample finding as HUMAN_REVIEW at 19.41% confidence, below the 70% threshold), while Amazon Bedrock generates advisory remediation guidance. Bedrock never overrides the policy gate, never attempts automated fixes on live sites, and falls back to static WCAG remediation guidance whenever LLM_PROVIDER=disabled, credentials are absent, or requests exceed the 25-second timeout window. Furthermore, AccessLens AI never claims automatic production fixes; every patch is strictly advisory for human developer verification.

## The reusable decision pattern

The reusable decision pattern #policy is implemented in accesslens/decider.py and accesslens/workflow.py. Another builder can drop this pattern into their agent in four steps:

1. Import AccessibilityDecider from accesslens.decider.
2. Build the bounded, sanitized state with build_finding_state(rule_id, impact, description, target, html, failure_summary).
3. Call decider.decide(...), which submits the typed action and risk_level questions to the hosted Strands Decider endpoint.
4. Pass the resulting DecisionResult to execute_workflow_action(result, finding), which enforces the 70% confidence floor and routes execution to the appropriate advisory patch, context enrichment, or human escalation ticket.

## What I learned and what is next

Building AccessLens AI reinforced a critical truth about civic web development: automated testing engines like axe-core are essential for catching machine-detectable syntax errors, but they can never certify full accessibility. Complete WCAG compliance requires human evaluation with screen readers, keyboard navigation, and cognitive clarity assessments.

Pairing deterministic scanning with Strands Decider 2B proved that small, specialized decision models offer a major architectural advantage over general LLMs. By restricting the model to calibrated probability distributions across typed options, we eliminate hallucination, prevent unauthorized code mutations, and create a transparent, auditable gatekeeper for public digital services.

Next steps for AccessLens AI include adding automated civic PDF accessibility scanning, expanding civic fixture presets, and evaluating AWS AgentCore Runtime as a potential future deployment option.

---

Code: https://github.com/cvardhan501/AccessLens-AI . Video: docs/DEMO_SCRIPT.md (video script verified; demo video will be linked upon publication) . Tags: #strands-decider-2b #policy

Built with the AWS User Group Madurai Strands Decider hackathon kit
