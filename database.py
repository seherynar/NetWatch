"""SQLite persistence for NetSentinel scan history."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "netsentinel.db"
DATA_DIR.mkdir(exist_ok=True)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                arguments TEXT,
                created_at TEXT NOT NULL,
                total_hosts INTEGER DEFAULT 0,
                total_open_ports INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                baseline_created INTEGER DEFAULT 0,
                report_filename TEXT,
                warning TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                protocol TEXT,
                port INTEGER,
                service TEXT,
                state TEXT,
                product TEXT,
                version TEXT,
                risk TEXT,
                risk_score INTEGER,
                risk_reason TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                severity TEXT,
                message TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );
            """
        )


def save_scan_result(result: Dict[str, Any]) -> int:
    summary = result["summary"]
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (
                target, arguments, created_at, total_hosts, total_open_ports,
                critical_count, high_count, medium_count, low_count, info_count,
                baseline_created, report_filename, warning
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["target"],
                result.get("arguments", ""),
                result["started_at"],
                summary["total_hosts"],
                summary["total_open_ports"],
                summary["critical_count"],
                summary["high_count"],
                summary["medium_count"],
                summary["low_count"],
                summary["info_count"],
                1 if result.get("baseline_created") else 0,
                result.get("report_filename"),
                result.get("warning"),
            ),
        )
        scan_id = int(cursor.lastrowid)

        for finding in result["findings"]:
            conn.execute(
                """
                INSERT INTO findings (
                    scan_id, host, protocol, port, service, state, product,
                    version, risk, risk_score, risk_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding["host"],
                    finding["protocol"],
                    finding["port"],
                    finding["service"],
                    finding["state"],
                    finding["product"],
                    finding["version"],
                    finding["risk"],
                    finding["risk_score"],
                    finding["risk_reason"],
                ),
            )

        for alert in result["alerts"]:
            conn.execute(
                "INSERT INTO alerts (scan_id, severity, message) VALUES (?, ?, ?)",
                (scan_id, alert["severity"], alert["message"]),
            )

    return scan_id


def get_recent_scans(limit: int = 10) -> List[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()


def get_dashboard_stats() -> Dict[str, Any]:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS scan_count,
                COALESCE(SUM(total_hosts), 0) AS total_hosts,
                COALESCE(SUM(total_open_ports), 0) AS total_open_ports,
                COALESCE(SUM(critical_count), 0) AS critical_count,
                COALESCE(SUM(high_count), 0) AS high_count
            FROM scans
            """
        ).fetchone()
        latest = conn.execute("SELECT created_at FROM scans ORDER BY id DESC LIMIT 1").fetchone()

    return {
        "scan_count": row["scan_count"],
        "total_hosts": row["total_hosts"],
        "total_open_ports": row["total_open_ports"],
        "critical_count": row["critical_count"],
        "high_count": row["high_count"],
        "last_scan": latest["created_at"] if latest else "Henüz tarama yok",
    }


def get_scan_detail(scan_id: int) -> Dict[str, Any] | None:
    with get_connection() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if scan is None:
            return None
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY host, port",
            (scan_id,),
        ).fetchall()
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
    return {"scan": scan, "findings": findings, "alerts": alerts}
