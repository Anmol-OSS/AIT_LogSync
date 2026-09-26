"""SQLite: the operational index (events, archive objects, tree heads, drafts).

Normalized events are also written to Parquet for the data lake (lake.py);
SQLite is what the API queries by event id. WAL mode lets the API read while
the pipeline worker writes.
"""
import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (          -- content-addressed raw archive
    sha256   TEXT PRIMARY KEY,
    ref      TEXT NOT NULL,                    -- segment:offset:length
    length   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT UNIQUE NOT NULL,
    received_at  TEXT NOT NULL,
    created      REAL NOT NULL,                -- unix time processed (for EPS)
    source_name  TEXT NOT NULL,
    source_host  TEXT NOT NULL,
    status       TEXT NOT NULL,                -- accepted | blocked | unparsed
    pack         TEXT,                         -- pack_id@version
    sha256       TEXT NOT NULL,
    leaf_index   INTEGER NOT NULL,
    doc          TEXT NOT NULL                 -- proof-carrying event JSON (without live proof)
);
CREATE INDEX IF NOT EXISTS events_status ON events(status);
CREATE INDEX IF NOT EXISTS events_source ON events(source_name);
CREATE INDEX IF NOT EXISTS events_created ON events(created);
CREATE TABLE IF NOT EXISTS tree_heads (       -- signed tree heads
    tree_size  INTEGER PRIMARY KEY,
    root       TEXT NOT NULL,
    timestamp  TEXT NOT NULL,
    signature  TEXT NOT NULL,
    rfc3161    BLOB
);
CREATE TABLE IF NOT EXISTS drafts (
    draft_id  TEXT PRIMARY KEY,
    created   REAL NOT NULL,
    doc       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS demo_tamper (       -- original byte, so the demo can be undone
    sha256      TEXT PRIMARY KEY,
    byte_index  INTEGER NOT NULL,
    original    INTEGER NOT NULL
);
"""


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        with self.connect() as c:
            c.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        """One connection per thread (sqlite3 connections are not thread-safe)."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
