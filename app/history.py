"""
Local-only session history for THE GATE. Logs "first-seen" events (a new
device joins the LAN, a new process starts talking, a new remote
organization is contacted) to a small SQLite file in this folder -
nothing leaves the machine, this is purely a local record so you can
review what happened while you were away.

The file lives at history.db right next to server.py. Delete it (or use
the in-app "Clear History" button) any time - it will be recreated
automatically on next launch.
"""

import os
import sqlite3
import threading
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "history.db"

_lock = threading.Lock()
_conn = None


def _get_conn():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                kind TEXT NOT NULL,
                label TEXT NOT NULL,
                detail TEXT
            )
        """)
        _conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC)")
        _conn.commit()
    return _conn


def log_event(kind, label, detail=""):
    """kind: 'device' | 'process' | 'org' - what first appeared."""
    with _lock:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO events (ts, kind, label, detail) VALUES (?, ?, ?, ?)",
            (time.time(), kind, label, detail),
        )
        conn.commit()


def get_recent(limit=200):
    with _lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT ts, kind, label, detail FROM events ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [{"ts": r[0], "kind": r[1], "label": r[2], "detail": r[3]} for r in rows]


def clear_history():
    with _lock:
        conn = _get_conn()
        conn.execute("DELETE FROM events")
        conn.commit()
        conn.execute("VACUUM")


def open_history_folder():
    """Opens Explorer at the folder containing history.db, so it can be
    moved, backed up, or deleted manually outside the app."""
    try:
        os.startfile(DB_PATH.parent)  # Windows-only, matches the rest of this app
        return True
    except Exception:
        return False
