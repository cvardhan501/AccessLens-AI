"""End-to-end tests for AccessLens AI scanner using real Playwright and axe-core."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import pytest

from accesslens.scanner import AccessibilityScanner

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class _FixtureHandler(SimpleHTTPRequestHandler):
    """Serve test fixture files with quiet logging."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FIXTURES_DIR), **kwargs)

    def log_message(self, format, *args):
        pass  # suppress stdout server logs during tests


@pytest.fixture(scope="module")
def local_fixture_server():
    """Spin up a real local HTTP server to serve test fixtures over HTTP."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base_url = f"http://127.0.0.1:{port}"
    yield base_url
    server.shutdown()


def test_scan_accessible_page_reports_zero_violations(local_fixture_server):
    """Accessible fixture page completes real axe-core scan with 0 violations."""
    scanner = AccessibilityScanner(allow_local=True, timeout_seconds=15.0)
    report = scanner.scan_url(f"{local_fixture_server}/accessible.html")

    assert report.status == "SUCCESS"
    assert report.summary is not None
    assert report.summary.total_violations == 0
    assert report.summary.critical_count == 0
    assert report.summary.serious_count == 0
    assert report.summary.passes_count > 0
    assert len(report.violations) == 0
    assert "Axe-core automated accessibility tests" in report.disclaimer


def test_scan_inaccessible_page_detects_real_violations(local_fixture_server):
    """Inaccessible fixture page detects actual violations: image-alt, label, button-name, etc."""
    scanner = AccessibilityScanner(allow_local=True, timeout_seconds=15.0)
    report = scanner.scan_url(f"{local_fixture_server}/inaccessible.html")

    assert report.status == "SUCCESS"
    assert report.summary is not None
    assert report.summary.total_violations >= 4

    detected_rule_ids = {v.rule_id for v in report.violations}

    # Verify critical expected rule violations
    assert "image-alt" in detected_rule_ids
    assert "label" in detected_rule_ids
    assert "button-name" in detected_rule_ids

    # Inspect the image-alt violation details
    alt_violation = next(v for v in report.violations if v.rule_id == "image-alt")
    assert alt_violation.impact in ("critical", "serious")
    assert len(alt_violation.nodes) >= 1

    node = alt_violation.nodes[0]
    assert any("broken-hero" in t or "img" in t for t in node.target)
    assert "hero-graphic.png" in node.html
    assert "alt" in node.failure_summary.lower()
    assert "Action needed:" in node.suggested_remediation or "Remediation" in node.suggested_remediation

    # Inspect the form label violation
    label_violation = next(v for v in report.violations if v.rule_id == "label")
    assert label_violation.impact in ("critical", "serious")
    assert any("unlabeled-account-input" in t or "input" in t for n in label_violation.nodes for t in n.target)


def test_scanner_blocks_ssrf_without_launching_browser():
    """Scanning loopback address without allow_local is blocked immediately as SECURITY_BLOCKED."""
    scanner = AccessibilityScanner(allow_local=False)
    report = scanner.scan_url("http://127.0.0.1:8080/secret")

    assert report.status == "SECURITY_BLOCKED"
    assert report.error_category == "SECURITY_VIOLATION"
    assert "Blocked" in str(report.error)
    assert len(report.violations) == 0


def test_scan_html_in_memory_directly():
    """In-memory HTML scanning runs real axe-core without network port binding."""
    scanner = AccessibilityScanner()
    raw_html = (FIXTURES_DIR / "inaccessible.html").read_text(encoding="utf-8")
    report = scanner.scan_html(raw_html, base_url="http://test.local")

    assert report.status == "SUCCESS"
    assert report.summary is not None
    assert report.summary.total_violations >= 4
    rule_ids = [v.rule_id for v in report.violations]
    assert "image-alt" in rule_ids
    assert "button-name" in rule_ids


def test_scanner_distinguishes_network_errors_from_findings():
    """Unresolvable domain returns structured SCAN_ERROR, never inventing fake violations."""
    scanner = AccessibilityScanner(timeout_seconds=5.0, allow_local=False)
    # RFC 2606 reserved invalid TLD guarantees resolution failure
    report = scanner.scan_url("https://invalid-nonexistent-domain-482019482.invalid")

    assert report.status in ("SECURITY_BLOCKED", "SCAN_ERROR")
    assert report.error is not None
    assert report.summary is None
    assert len(report.violations) == 0


def test_scan_civic_scholarship_portal_detects_representative_barriers():
    """Civic scholarship portal fixture detects representative real-world civic barriers.

    Verifies detection of:
    - Missing form labels (WCAG 1.3.1, 4.1.2)
    - Low contrast on controls and text (WCAG 1.4.3)
    - Unclear document link / empty anchor (WCAG 2.4.4)
    - Table-header issues / empty th (WCAG 1.3.1)
    - Unlabelled button (WCAG 4.1.2)
    - Missing image alt text (WCAG 1.1.1)
    """
    scanner = AccessibilityScanner()
    raw_html = (FIXTURES_DIR / "civic_scholarship_portal.html").read_text(encoding="utf-8")
    report = scanner.scan_html(raw_html, base_url="http://civic.test.local")

    assert report.status == "SUCCESS"
    assert report.summary is not None
    assert report.summary.total_violations >= 5

    rule_ids = {v.rule_id for v in report.violations}

    # Verify all representative barriers required by Phase 4
    assert "label" in rule_ids, "Should detect missing form labels"
    assert "color-contrast" in rule_ids, "Should detect low contrast button/text"
    assert "link-name" in rule_ids, "Should detect empty document link"
    assert "empty-table-header" in rule_ids, "Should detect table-header issues"
    assert "button-name" in rule_ids, "Should detect unlabelled icon button"
    assert "image-alt" in rule_ids, "Should detect missing alt text on state emblem"

    # Verify specific node evidence for form label
    label_v = next(v for v in report.violations if v.rule_id == "label")
    assert len(label_v.nodes) >= 2
    assert any("citizen-identity-input" in t or "household-income-input" in t for n in label_v.nodes for t in n.target)

    # Verify table-header node evidence
    table_v = next(v for v in report.violations if v.rule_id == "empty-table-header")
    assert len(table_v.nodes) >= 1
    assert any("eligibility-table" in t or "th" in t for n in table_v.nodes for t in n.target)


def test_scan_civic_accessible_portal_tested_with_disclaimer_and_incomplete():
    """Civic accessible portal is tested against real axe-core and verified with honest disclaimer.

    Automated testing yields 0 violations, but does NOT certify full compliance.
    """
    scanner = AccessibilityScanner()
    raw_html = (FIXTURES_DIR / "civic_accessible_portal.html").read_text(encoding="utf-8")
    report = scanner.scan_html(raw_html, base_url="http://civic.test.local")

    assert report.status == "SUCCESS"
    assert report.summary is not None
    assert report.summary.total_violations == 0
    assert report.summary.critical_count == 0
    assert report.summary.serious_count == 0
    assert report.summary.passes_count >= 30
    assert len(report.violations) == 0

    # Verify the honest WCAG scope disclaimer is present and truthful
    assert "subset of machine-detectable WCAG" in report.disclaimer
    assert "Zero reported violations does not certify complete WCAG compliance" in report.disclaimer
    assert "requires manual verification" in report.disclaimer

