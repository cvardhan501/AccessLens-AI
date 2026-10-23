"""Unit tests for AccessLens AI command-line interface."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import pytest

from accesslens.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class _FixtureHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FIXTURES_DIR), **kwargs)

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_cli_missing_url_exits_with_code_2(capsys):
    """Running CLI with no arguments exits with syntax error code 2."""
    code = main([])
    assert code == 2
    captured = capsys.readouterr()
    assert "error: Target URL is required" in captured.err


def test_cli_scan_inaccessible_page_outputs_json(local_server, capsys):
    """Running CLI against local fixture outputs valid structured JSON."""
    url = f"{local_server}/inaccessible.html"
    code = main([url, "--allow-local"])
    assert code == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert data["status"] == "SUCCESS"
    assert data["url"] == url
    assert data["summary"]["total_violations"] >= 4
    assert any(v["rule_id"] == "image-alt" for v in data["violations"])


def test_cli_output_file_flag(local_server, tmp_path, capsys):
    """--output writes the structured report to the specified file."""
    url = f"{local_server}/accessible.html"
    out_file = tmp_path / "scan_results.json"

    code = main([url, "--allow-local", "-o", str(out_file), "--summary"])
    assert code == 0
    assert out_file.exists()

    file_data = json.loads(out_file.read_text(encoding="utf-8"))
    assert file_data["status"] == "SUCCESS"
    assert file_data["summary"]["total_violations"] == 0

    captured = capsys.readouterr()
    assert "AccessLens AI Scan Summary" in captured.err


def test_cli_blocks_ssrf_by_default(capsys):
    """CLI exits with code 1 when attempting to scan localhost without --allow-local."""
    code = main(["http://127.0.0.1:8080/internal"])
    assert code == 1

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "SECURITY_BLOCKED"
    assert data["error_category"] == "SECURITY_VIOLATION"
