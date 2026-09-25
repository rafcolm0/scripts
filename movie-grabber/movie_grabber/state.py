"""SQLite-backed state: which titles are wanted, downloading, done."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

WANTED, DOWNLOADING, COMPLETED, GAVE_UP = "wanted", "downloading", "completed", "gave_up"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS movies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    key           TEXT UNIQUE NOT NULL,
    title         TEXT NOT NULL,
    year          INTEGER,
    library       TEXT NOT NULL DEFAULT 'default',
    status        TEXT NOT NULL DEFAULT 'wanted',
    attempts      INTEGER NOT NULL DEFAULT 0,
    last_search   TEXT,
    release_name  TEXT,
    source        TEXT,
    size          INTEGER,
    info_hash     TEXT,
    added_at      TEXT,
    completed_at  TEXT,
    dest_path     TEXT,
    error         TEXT,
    rejected      TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    return datetime.fromisoformat(value) if value else None


class State:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ---------------------------------------------------------------- movies
    def upsert_wanted(self, key: str, title: str, year: Optional[int], library: str) -> sqlite3.Row:
        self.conn.execute(
            "INSERT INTO movies (key, title, year, library) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET library = excluded.library",
            (key, title, year, library),
        )
        self.conn.commit()
        return self.get_by_key(key)

    def get_by_key(self, key: str) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM movies WHERE key = ?", (key,)).fetchone()

    def get(self, movie_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM movies WHERE id = ?", (movie_id,)).fetchone()

    def by_status(self, *statuses: str) -> list[sqlite3.Row]:
        q = f"SELECT * FROM movies WHERE status IN ({','.join('?' * len(statuses))}) ORDER BY id"
        return self.conn.execute(q, statuses).fetchall()

    def all(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM movies ORDER BY status, title").fetchall()

    def update(self, movie_id: int, **fields: Any) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        self.conn.execute(f"UPDATE movies SET {cols} WHERE id = ?", (*fields.values(), movie_id))
        self.conn.commit()

    def reject_release(self, movie_id: int, release_name: str) -> None:
        row = self.get(movie_id)
        rejected = json.loads(row["rejected"] or "[]")
        if release_name and release_name not in rejected:
            rejected.append(release_name)
        self.update(movie_id, rejected=json.dumps(rejected))

    @staticmethod
    def rejected_names(row: sqlite3.Row) -> set[str]:
        return set(json.loads(row["rejected"] or "[]"))

    # ------------------------------------------------------------------ meta
    def get_meta(self, key: str) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) "
                          "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
        self.conn.commit()
