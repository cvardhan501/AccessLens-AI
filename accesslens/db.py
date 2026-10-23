"""Local SQLite database persistence for AccessLens AI scan history.

Persists complete scan reports, audit summaries, execution durations,
and failure/error states locally. Never stores an error as a success.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Generator

from .models import ScanReport, ScanSummary, Violation

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "accesslens.db"


@contextmanager
def get_db_connection(db_path: Path | str | None = None) -> Generator[sqlite3.Connection, None, None]:
    """Yield a configured sqlite3 connection with foreign keys and row factory enabled."""
    target_path = Path(db_path) if db_path else DEFAULT_DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path), timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path | str | None = None) -> Path:
    """Initialize database tables and indexes if they do not already exist."""
    target_path = Path(db_path) if db_path else DEFAULT_DB_PATH
    with get_db_connection(target_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                final_url TEXT,
                timestamp TEXT NOT NULL,
                duration_ms REAL NOT NULL,
                status TEXT NOT NULL,
                engine TEXT NOT NULL,
                total_violations INTEGER NOT NULL DEFAULT 0,
                critical_count INTEGER NOT NULL DEFAULT 0,
                serious_count INTEGER NOT NULL DEFAULT 0,
                moderate_count INTEGER NOT NULL DEFAULT 0,
                minor_count INTEGER NOT NULL DEFAULT 0,
                passes_count INTEGER NOT NULL DEFAULT 0,
                incomplete_count INTEGER NOT NULL DEFAULT 0,
                inapplicable_count INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                error_category TEXT,
                report_json TEXT NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_url ON scans (url);")
    return target_path


def save_scan(report: ScanReport, db_path: Path | str | None = None) -> int:
    """Persist a ScanReport to SQLite database and return the inserted record ID.
    
    Clearly distinguishes successful scans from errors or security blocks.
    Errors are never saved with success status or fake counts.
    """
    target_path = init_db(db_path)

    # Derive accurate summary numbers
    is_success = (report.status == "SUCCESS")
    summary = report.summary if is_success else None

    total_violations = summary.total_violations if summary else 0
    critical_count = summary.critical_count if summary else 0
    serious_count = summary.serious_count if summary else 0
    moderate_count = summary.moderate_count if summary else 0
    minor_count = summary.minor_count if summary else 0
    passes_count = summary.passes_count if summary else 0
    incomplete_count = summary.incomplete_count if summary else 0
    inapplicable_count = summary.inapplicable_count if summary else 0

    error_text = report.error if not is_success else None
    error_cat = report.error_category if not is_success else None

    report_dict = report.to_dict()
    report_json_str = json.dumps(report_dict, indent=2)

    with get_db_connection(target_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (
                url, final_url, timestamp, duration_ms, status, engine,
                total_violations, critical_count, serious_count, moderate_count,
                minor_count, passes_count, incomplete_count, inapplicable_count,
                error, error_category, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.url,
                report.final_url or report.url,
                report.timestamp,
                report.duration_ms,
                report.status,
                report.engine,
                total_violations,
                critical_count,
                serious_count,
                moderate_count,
                minor_count,
                passes_count,
                incomplete_count,
                inapplicable_count,
                error_text,
                error_cat,
                report_json_str,
            ),
        )
        scan_id = cursor.lastrowid
        if scan_id is None:
            raise RuntimeError("Failed to obtain scan record ID after insertion.")
        return scan_id


def get_scan(scan_id: int, db_path: Path | str | None = None) -> dict[str, Any] | None:
    """Retrieve a single scan record by ID, parsing the full JSON report."""
    target_path = init_db(db_path)
    with get_db_connection(target_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None

        report_data = json.loads(row["report_json"])
        report_data["id"] = row["id"]
        return report_data


def get_history(
    limit: int = 50,
    offset: int = 0,
    status_filter: str | None = None,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve list of scan records ordered by timestamp descending, without raw JSON."""
    target_path = init_db(db_path)
    query = """
        SELECT
            id, url, final_url, timestamp, duration_ms, status, engine,
            total_violations, critical_count, serious_count, moderate_count,
            minor_count, passes_count, incomplete_count, inapplicable_count,
            error, error_category
        FROM scans
    """
    params: list[Any] = []

    if status_filter:
        query += " WHERE status = ?"
        params.append(status_filter)

    query += " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_db_connection(target_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_history_count(status_filter: str | None = None, db_path: Path | str | None = None) -> int:
    """Return total number of scan records."""
    target_path = init_db(db_path)
    query = "SELECT COUNT(*) FROM scans"
    params: list[Any] = []
    if status_filter:
        query += " WHERE status = ?"
        params.append(status_filter)

    with get_db_connection(target_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return int(cursor.fetchone()[0])


def delete_scan(scan_id: int, db_path: Path | str | None = None) -> bool:
    """Delete a single scan record by ID."""
    target_path = init_db(db_path)
    with get_db_connection(target_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0


def clear_history(db_path: Path | str | None = None) -> int:
    """Clear all scan records from history."""
    target_path = init_db(db_path)
    with get_db_connection(target_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans")
        return cursor.rowcount
