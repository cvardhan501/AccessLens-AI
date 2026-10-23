"""Integration tests for AccessLens AI web dashboard server and REST API."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import pytest
from fastapi.testclient import TestClient

from accesslens.db import clear_history, init_db
from accesslens.server import app

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class _FixtureHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FIXTURES_DIR), **kwargs)

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def local_test_server():
    """Spin up local HTTP fixture server for live scanner testing."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    """Provide a TestClient connected to a clean temporary SQLite database."""
    temp_db_path = tmp_path / "test_server.db"
    init_db(temp_db_path)
    monkeypatch.setattr("accesslens.db.DEFAULT_DB_PATH", temp_db_path)
    monkeypatch.setattr("accesslens.server.STATIC_DIR", Path(__file__).resolve().parent.parent / "accesslens" / "static")

    with TestClient(app) as test_client:
        yield test_client


def test_health_check_endpoint(client):
    """GET /api/health returns 200, engine info, and WCAG disclaimer."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "axe-core" in data["engine"]
    assert "ssrf_protection" in data
    assert "Axe-core automated accessibility tests" in data["disclaimer"]


def test_serve_dashboard_html(client):
    """GET / serves the dashboard HTML with proper semantic tags and branding."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    html = resp.text
    assert "<title>AccessLens AI" in html
    assert "axe-core 4.13.0" in html
    assert "Target Website URL" in html
    assert "Automated Testing Scope &amp; WCAG Disclaimer" in html


def test_server_blocks_ssrf_and_persists_as_blocked(client):
    """POST /api/scan blocks loopback/private target and records it as SECURITY_BLOCKED."""
    payload = {"url": "http://127.0.0.1:8080/secret", "allow_local": False}
    resp = client.post("/api/scan", json=payload)
    assert resp.status_code == 200

    data = resp.json()
    assert data["status"] == "SECURITY_BLOCKED"
    assert data["error_category"] == "SECURITY_VIOLATION"
    assert "Blocked" in data["error"]
    assert "id" in data

    # Verify recorded in history as failed/blocked
    history_resp = client.get("/api/history")
    assert history_resp.status_code == 200
    history = history_resp.json()
    assert history["total"] >= 1
    recent = history["items"][0]
    assert recent["status"] == "SECURITY_BLOCKED"
    assert recent["total_violations"] == 0


def test_server_blocks_cloud_metadata(client):
    """POST /api/scan intercepts 169.254.169.254 metadata endpoint."""
    payload = {"url": "http://169.254.169.254/latest/meta-data/", "allow_local": False}
    resp = client.post("/api/scan", json=payload)
    assert resp.status_code == 200

    data = resp.json()
    assert data["status"] == "SECURITY_BLOCKED"
    assert "Blocked direct IP" in data["error"]


def test_server_real_scan_success_and_history(client, local_test_server):
    """POST /api/scan performs actual axe-core evaluation against test fixture."""
    url = f"{local_test_server}/inaccessible.html"
    payload = {"url": url, "timeout": 20.0, "allow_local": True}

    resp = client.post("/api/scan", json=payload)
    assert resp.status_code == 200

    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["url"] == url
    assert data["summary"]["total_violations"] >= 4
    assert data["summary"]["passes_count"] > 0
    assert any(v["rule_id"] == "image-alt" for v in data["violations"])

    scan_id = data["id"]
    assert scan_id > 0

    # Test GET /api/scans/{id}
    fetch_resp = client.get(f"/api/scans/{scan_id}")
    assert fetch_resp.status_code == 200
    fetched_data = fetch_resp.json()
    assert fetched_data["id"] == scan_id
    assert fetched_data["url"] == url

    # Test GET /api/scans/{id}/download
    dl_resp = client.get(f"/api/scans/{scan_id}/download")
    assert dl_resp.status_code == 200
    assert dl_resp.headers["content-type"] == "application/json"
    assert f'filename="accesslens-report-{scan_id}.json"' in dl_resp.headers["content-disposition"]

    # Test GET /api/history
    hist_resp = client.get("/api/history")
    assert hist_resp.status_code == 200
    hist = hist_resp.json()
    assert any(item["id"] == scan_id for item in hist["items"])


def test_delete_scan_and_clear_history(client, local_test_server):
    """Scans can be deleted individually and history can be cleared."""
    # First clear history
    del_all = client.delete("/api/history")
    assert del_all.status_code == 200

    # Add a scan
    url = f"{local_test_server}/accessible.html"
    resp = client.post("/api/scan", json={"url": url, "allow_local": True})
    assert resp.status_code == 200
    scan_id = resp.json()["id"]

    # Delete the scan
    del_resp = client.delete(f"/api/scans/{scan_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "deleted"

    # Confirm 404
    get_404 = client.get(f"/api/scans/{scan_id}")
    assert get_404.status_code == 404


def test_server_serve_fixture_files(client):
    """GET /fixtures/{name} serves civic HTML fixtures and blocks path traversal."""
    resp1 = client.get("/fixtures/civic_scholarship_portal.html")
    assert resp1.status_code == 200
    assert "text/html" in resp1.headers["content-type"]
    assert "National Higher Education Grant Application" in resp1.text

    resp2 = client.get("/fixtures/civic_accessible_portal.html")
    assert resp2.status_code == 200
    assert "text/html" in resp2.headers["content-type"]
    assert "State Social Security" in resp2.text

    # Path traversal protection
    bad_resp = client.get("/fixtures/..%2F..%2Fserver.py")
    assert bad_resp.status_code in (400, 404)


def test_server_audit_civic_scholarship_portal_via_fixture_scheme(client):
    """POST /api/scan with fixture:civic_scholarship_portal evaluates in-memory safely."""
    payload = {"url": "fixture:civic_scholarship_portal"}
    resp = client.post("/api/scan", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "SUCCESS"
    assert data["is_fixture"] is True
    assert data["url"] == "fixture://civic_scholarship_portal.html"
    assert data["summary"]["total_violations"] >= 5
    rules = [v["rule_id"] for v in data["violations"]]
    assert "label" in rules
    assert "color-contrast" in rules
    assert "link-name" in rules
    assert "empty-table-header" in rules


def test_server_audit_civic_accessible_portal_via_fixture_scheme(client):
    """POST /api/scan with fixture:civic_accessible_portal runs real axe-core returning 0 violations."""
    payload = {"url": "fixture:civic_accessible_portal"}
    resp = client.post("/api/scan", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "SUCCESS"
    assert data["is_fixture"] is True
    assert data["url"] == "fixture://civic_accessible_portal.html"
    assert data["summary"]["total_violations"] == 0
    assert data["summary"]["passes_count"] >= 30
    assert "Zero reported violations does not certify complete WCAG compliance" in data["disclaimer"]

