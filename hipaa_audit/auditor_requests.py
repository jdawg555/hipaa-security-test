from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def db_path(repo_path: Path, config: dict[str, Any]) -> Path:
    rel = config.get("auditor_portal", {}).get("requests_db", "compliance/auditor-requests.db")
    return repo_path / rel


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path: Path) -> None:
    with _connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                control_ref TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                due_date TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                author TEXT NOT NULL,
                author_role TEXT NOT NULL,
                body TEXT NOT NULL,
                attachment_path TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (request_id) REFERENCES requests(id)
            );
            """
        )


def create_request(
    path: Path,
    *,
    title: str,
    control_ref: str = "",
    due_date: str = "",
) -> dict[str, Any]:
    init_db(path)
    now = datetime.now(UTC).isoformat()
    req_id = f"PBC-{datetime.now(UTC).strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
    with _connect(path) as conn:
        conn.execute(
            "INSERT INTO requests (id, title, control_ref, status, due_date, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (req_id, title, control_ref, "open", due_date, now, now),
        )
    return {"id": req_id, "title": title, "control_ref": control_ref, "status": "open", "due_date": due_date}


def list_requests(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    init_db(path)
    with _connect(path) as conn:
        rows = conn.execute("SELECT * FROM requests ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def get_request(path: Path, request_id: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    init_db(path)
    with _connect(path) as conn:
        row = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
        if not row:
            return None
        messages = conn.execute(
            "SELECT * FROM messages WHERE request_id = ? ORDER BY created_at",
            (request_id,),
        ).fetchall()
    data = dict(row)
    data["messages"] = [dict(m) for m in messages]
    return data


def add_message(
    path: Path,
    *,
    request_id: str,
    author: str,
    author_role: str,
    body: str,
    attachment_path: str = "",
) -> bool:
    init_db(path)
    now = datetime.now(UTC).isoformat()
    with _connect(path) as conn:
        exists = conn.execute("SELECT 1 FROM requests WHERE id = ?", (request_id,)).fetchone()
        if not exists:
            return False
        conn.execute(
            "INSERT INTO messages (request_id, author, author_role, body, attachment_path, created_at) VALUES (?,?,?,?,?,?)",
            (request_id, author, author_role, body, attachment_path, now),
        )
        conn.execute("UPDATE requests SET updated_at = ? WHERE id = ?", (now, request_id))
    return True


def update_request_status(path: Path, request_id: str, status: str) -> bool:
    init_db(path)
    now = datetime.now(UTC).isoformat()
    with _connect(path) as conn:
        cur = conn.execute(
            "UPDATE requests SET status = ?, updated_at = ? WHERE id = ?",
            (status, now, request_id),
        )
        return cur.rowcount > 0


def verify_auditor_passphrase(config: dict[str, Any], passphrase: str) -> bool:
    import os

    env_key = config.get("auditor_portal", {}).get("access_passphrase_env", "AUDITOR_PORTAL_PASSPHRASE")
    expected = os.environ.get(env_key, "")
    if not expected:
        return True
    return secrets.compare_digest(passphrase, expected)


def session_token(passphrase: str) -> str:
    return hashlib.sha256(passphrase.encode()).hexdigest()
