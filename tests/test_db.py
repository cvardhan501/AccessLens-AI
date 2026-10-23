"""Unit tests for AccessLens AI local SQLite scan history persistence."""

from pathlib import Path
import pytest

from accesslens.db import clear_history, delete_scan, get_history, get_history_count, get_scan, init_db, save_scan
from accesslens.models import ElementNode, ScanReport, ScanSummary, Violation


@pytest.fixture
def temp_db(tmp_path: Path):
    """Provide a fresh SQLite database path for testing."""
    db_file = tmp_path / "test_accesslens.db"
    init_db(db_file)
    return db_file


def test_save_and_retrieve_successful_scan(temp_db: Path):
    """Saving a successful scan report records all metric counts and JSON report."""
    summary = ScanSummary(
        total_violations=1,
        critical_count=1,
        serious_count=0,
        moderate_count=0,
        minor_count=0,
        passes_count=20,
        inapplicable_count=30,
        incomplete_count=2,
    )
    violation = Violation(
        rule_id="image-alt",
        impact="critical",
        description="Images must have alt text",
        help="Help text",
        help_url="https://example.com/rules/image-alt",
        tags=["wcag2a", "wcag111"],
        nodes=[
            ElementNode(
                target=["#hero"],
                html="<img src='hero.png'>",
                failure_summary="Fix alt attribute",
                suggested_remediation="Action needed: Add alt attribute",
            )
        ],
        node_count=1,
    )
    report = ScanReport(
        status="SUCCESS",
        url="https://example.com",
        final_url="https://example.com/",
        timestamp="2026-10-20T12:00:00+00:00",
        duration_ms=1250.5,
        summary=summary,
        violations=[violation],
    )

    scan_id = save_scan(report, db_path=temp_db)
    assert scan_id > 0

    fetched = get_scan(scan_id, db_path=temp_db)
    assert fetched is not None
    assert fetched["id"] == scan_id
    assert fetched["status"] == "SUCCESS"
    assert fetched["url"] == "https://example.com"
    assert fetched["summary"]["total_violations"] == 1
    assert fetched["summary"]["critical_count"] == 1
    assert len(fetched["violations"]) == 1
    assert fetched["violations"][0]["rule_id"] == "image-alt"


def test_save_scan_error_never_saved_as_success(temp_db: Path):
    """Errors must be saved with error status, error message, and zero violations."""
    err_report = ScanReport(
        status="SCAN_ERROR",
        url="https://nonexistent-site-test-1234.org",
        final_url="https://nonexistent-site-test-1234.org",
        timestamp="2026-10-20T12:01:00+00:00",
        duration_ms=450.0,
        error="Browser execution error: net::ERR_NAME_NOT_RESOLVED",
        error_category="DNS_FAILURE",
    )

    scan_id = save_scan(err_report, db_path=temp_db)
    fetched = get_scan(scan_id, db_path=temp_db)

    assert fetched is not None
    assert fetched["status"] == "SCAN_ERROR"
    assert fetched["summary"] is None
    assert fetched["error_category"] == "DNS_FAILURE"
    assert "ERR_NAME_NOT_RESOLVED" in fetched["error"]
    assert len(fetched["violations"]) == 0

    history = get_history(limit=10, db_path=temp_db)
    assert len(history) == 1
    assert history[0]["status"] == "SCAN_ERROR"
    assert history[0]["total_violations"] == 0
    assert history[0]["error_category"] == "DNS_FAILURE"


def test_save_security_blocked_scan(temp_db: Path):
    """SSRF-blocked scans are recorded with SECURITY_BLOCKED status."""
    sec_report = ScanReport(
        status="SECURITY_BLOCKED",
        url="http://127.0.0.1:8080/admin",
        timestamp="2026-10-20T12:02:00+00:00",
        duration_ms=12.0,
        error="Blocked access to local host '127.0.0.1'",
        error_category="SECURITY_VIOLATION",
    )

    scan_id = save_scan(sec_report, db_path=temp_db)
    fetched = get_scan(scan_id, db_path=temp_db)

    assert fetched is not None
    assert fetched["status"] == "SECURITY_BLOCKED"
    assert fetched["error_category"] == "SECURITY_VIOLATION"


def test_history_ordering_and_pagination(temp_db: Path):
    """Scan history is returned newest-first and supports pagination."""
    for i in range(5):
        report = ScanReport(
            status="SUCCESS",
            url=f"https://example{i}.com",
            timestamp=f"2026-10-20T12:0{i}:00+00:00",
            duration_ms=100.0 * (i + 1),
            summary=ScanSummary(0, 0, 0, 0, 0, 10, 20, 0),
        )
        save_scan(report, db_path=temp_db)

    assert get_history_count(db_path=temp_db) == 5

    page1 = get_history(limit=2, offset=0, db_path=temp_db)
    assert len(page1) == 2
    assert page1[0]["url"] == "https://example4.com"
    assert page1[1]["url"] == "https://example3.com"

    page2 = get_history(limit=2, offset=2, db_path=temp_db)
    assert len(page2) == 2
    assert page2[0]["url"] == "https://example2.com"
    assert page2[1]["url"] == "https://example1.com"


def test_delete_and_clear_history(temp_db: Path):
    """Scans can be deleted individually or completely cleared."""
    report = ScanReport(
        status="SUCCESS",
        url="https://test.com",
        timestamp="2026-10-20T12:00:00+00:00",
        duration_ms=100.0,
        summary=ScanSummary(0, 0, 0, 0, 0, 5, 5, 0),
    )
    s_id = save_scan(report, db_path=temp_db)
    assert get_history_count(db_path=temp_db) == 1

    deleted = delete_scan(s_id, db_path=temp_db)
    assert deleted is True
    assert get_history_count(db_path=temp_db) == 0

    # Save multiple and clear
    save_scan(report, db_path=temp_db)
    save_scan(report, db_path=temp_db)
    assert get_history_count(db_path=temp_db) == 2

    cleared = clear_history(db_path=temp_db)
    assert cleared == 2
    assert get_history_count(db_path=temp_db) == 0
