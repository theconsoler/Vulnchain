import sqlite3
import json
from pathlib import Path


def get_db(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    conn = get_db(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE,
            password    TEXT    NOT NULL,
            created_at  TEXT    DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_runs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    NOT NULL,
            filename     TEXT    NOT NULL,
            scanner_type TEXT,
            vuln_count   INTEGER DEFAULT 0,
            node_count   INTEGER DEFAULT 0,
            status       TEXT    DEFAULT 'pending',
            created_at   TEXT    DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            job_id      TEXT    PRIMARY KEY,
            username    TEXT    NOT NULL,
            status      TEXT    DEFAULT 'running',
            progress    TEXT    DEFAULT 'Starting...',
            phase       INTEGER DEFAULT 0,
            vuln_count  INTEGER DEFAULT 0,
            node_count  INTEGER DEFAULT 0,
            path_count  INTEGER DEFAULT 0,
            error_msg   TEXT,
            created_at  TEXT    DEFAULT (datetime('now')),
            updated_at  TEXT    DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_snapshots (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    NOT NULL,
            scan_run_id  INTEGER,
            vuln_json    TEXT    NOT NULL,
            created_at   TEXT    DEFAULT (datetime('now'))
        )
    """)
def save_scan_snapshot(db_path: str, username: str, vuln_list: list) -> None:
    conn = get_db(db_path)
    conn.execute(
        "INSERT INTO scan_snapshots (username, vuln_json) VALUES (?, ?)",
        (username, json.dumps(vuln_list))
    )
    conn.commit()
    conn.close()


def get_last_two_snapshots(db_path: str) -> tuple[list, list]:
    """Returns (latest_vulns, previous_vulns). Either can be empty list."""
    conn   = get_db(db_path)
    rows   = conn.execute(
        "SELECT vuln_json FROM scan_snapshots ORDER BY created_at DESC LIMIT 2"
    ).fetchall()
    conn.close()
    latest   = json.loads(rows[0]["vuln_json"]) if len(rows) > 0 else []
    previous = json.loads(rows[1]["vuln_json"]) if len(rows) > 1 else []
    return latest, previous
    conn.commit()
    conn.close()


def get_user_by_username(db_path: str, username: str) -> dict | None:
    conn = get_db(db_path)
    row  = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(db_path: str, username: str, password_hash: str) -> None:
    conn = get_db(db_path)
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password_hash)
    )
    conn.commit()
    conn.close()


def log_scan_run(db_path: str, username: str, filename: str,
                 scanner_type: str, vuln_count: int,
                 node_count: int, status: str) -> None:
    conn = get_db(db_path)
    conn.execute(
        """INSERT INTO scan_runs
           (username, filename, scanner_type, vuln_count, node_count, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (username, filename, scanner_type, vuln_count, node_count, status)
    )
    conn.commit()
    conn.close()


def get_recent_scans(db_path: str, limit: int = 10) -> list[dict]:
    conn = get_db(db_path)
    rows = conn.execute(
        "SELECT * FROM scan_runs ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_job(db_path: str, job_id: str, username: str) -> None:
    conn = get_db(db_path)
    conn.execute(
        "INSERT INTO jobs (job_id, username, status) VALUES (?, ?, 'running')",
        (job_id, username)
    )
    conn.commit()
    conn.close()


def update_job(db_path: str, job_id: str, **kwargs) -> None:
    if not kwargs:
        return
    fields = ", ".join(f"{k} = ?" for k in kwargs)
    fields += ", updated_at = datetime('now')"
    values = list(kwargs.values())
    values.append(job_id)
    conn = get_db(db_path)
    conn.execute(f"UPDATE jobs SET {fields} WHERE job_id = ?", values)
    conn.commit()
    conn.close()


def get_job(db_path: str, job_id: str) -> dict | None:
    conn = get_db(db_path)
    row  = conn.execute(
        "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None
