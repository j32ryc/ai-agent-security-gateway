"""SQLite-backed audit log. Every input scan, tool-output scan, and tool-call
decision the gateway makes is persisted here so a session can be replayed and
reviewed after the fact -- the same instinct as keeping SIEM/EDR event logs
rather than only alerting in real time."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    ts REAL NOT NULL,
    event_type TEXT NOT NULL,      -- user_input | tool_output | tool_call | detection
    actor TEXT,                    -- tool name or 'user'
    content TEXT,                  -- truncated text snippet, for context in the dashboard
    risk_level TEXT,
    decision TEXT,                 -- allow | confirm | block | (null for pure detections)
    detail_json TEXT
);
"""


class AuditLog:
    def __init__(self, db_path: str = "gateway_audit.db", session_id: str | None = None):
        self.db_path = db_path
        self.session_id = session_id or str(uuid.uuid4())[:8]
        Path(db_path).parent.mkdir(parents=True, exist_ok=True) if Path(db_path).parent != Path(".") else None
        # check_same_thread=False: Streamlit reruns the script on a worker thread
        # that can differ from the one that created this connection, even within
        # a single user session. Access here is still effectively sequential (one
        # script rerun at a time per session), so this is safe.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def log(
        self,
        event_type: str,
        actor: str | None = None,
        content: str | None = None,
        risk_level: str | None = None,
        decision: str | None = None,
        detail: dict | None = None,
    ) -> None:
        snippet = (content or "")[:500]
        self._conn.execute(
            "INSERT INTO events (session_id, ts, event_type, actor, content, risk_level, decision, detail_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                self.session_id,
                time.time(),
                event_type,
                actor,
                snippet,
                risk_level,
                decision,
                json.dumps(detail or {}),
            ),
        )
        self._conn.commit()

    def events_for_session(self, session_id: str | None = None) -> list[dict]:
        sid = session_id or self.session_id
        cur = self._conn.execute(
            "SELECT ts, event_type, actor, content, risk_level, decision, detail_json "
            "FROM events WHERE session_id = ? ORDER BY id ASC",
            (sid,),
        )
        cols = ["ts", "event_type", "actor", "content", "risk_level", "decision", "detail_json"]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()
