"""SQLite-backed state for discovered networks, clients, captures and events."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable


SCHEMA = """
CREATE TABLE IF NOT EXISTS aps (
    bssid       TEXT PRIMARY KEY,
    ssid        TEXT NOT NULL DEFAULT '',
    channel     INTEGER,
    rssi        INTEGER,
    privacy     TEXT,
    beacons     INTEGER NOT NULL DEFAULT 0,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
    mac         TEXT NOT NULL,
    bssid       TEXT NOT NULL DEFAULT '',
    rssi        INTEGER,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    PRIMARY KEY (mac, bssid)
);
CREATE TABLE IF NOT EXISTS handshakes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    bssid       TEXT NOT NULL DEFAULT '',
    ssid        TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL DEFAULT 'eapol',
    path        TEXT NOT NULL DEFAULT '',
    size        INTEGER NOT NULL DEFAULT 0,
    verified    INTEGER NOT NULL DEFAULT 0,
    note        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    level       TEXT NOT NULL DEFAULT 'info',
    kind        TEXT NOT NULL DEFAULT 'system',
    message     TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started     REAL NOT NULL,
    ended       REAL,
    mode        TEXT NOT NULL DEFAULT '',
    aps         INTEGER NOT NULL DEFAULT 0,
    clients     INTEGER NOT NULL DEFAULT 0,
    handshakes  INTEGER NOT NULL DEFAULT 0,
    hops        INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aps_last_seen ON aps(last_seen);
CREATE INDEX IF NOT EXISTS idx_clients_last_seen ON clients(last_seen);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(
            str(self.path),
            check_same_thread=False,
            timeout=10,
            isolation_level=None,
        )
        self.db.row_factory = sqlite3.Row
        with self._lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.execute("PRAGMA busy_timeout=5000")
            self.db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            try:
                self.db.close()
            except sqlite3.Error:
                pass

    def upsert_ap(
        self,
        bssid: str,
        ssid: str,
        channel: int | None,
        rssi: int | None,
        privacy: str | None,
        ts: float | None = None,
    ) -> None:
        ts = ts or time.time()
        with self._lock:
            self.db.execute(
                """
                INSERT INTO aps (bssid, ssid, channel, rssi, privacy, beacons, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid = CASE WHEN excluded.ssid != '' THEN excluded.ssid ELSE aps.ssid END,
                    channel = COALESCE(excluded.channel, aps.channel),
                    rssi = COALESCE(excluded.rssi, aps.rssi),
                    privacy = COALESCE(excluded.privacy, aps.privacy),
                    beacons = aps.beacons + 1,
                    last_seen = excluded.last_seen
                """,
                (bssid, ssid, channel, rssi, privacy, ts, ts),
            )

    def upsert_client(
        self,
        mac: str,
        bssid: str = "",
        rssi: int | None = None,
        ts: float | None = None,
    ) -> None:
        ts = ts or time.time()
        with self._lock:
            self.db.execute(
                """
                INSERT INTO clients (mac, bssid, rssi, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(mac, bssid) DO UPDATE SET
                    rssi = COALESCE(excluded.rssi, clients.rssi),
                    last_seen = excluded.last_seen
                """,
                (mac, bssid, rssi, ts, ts),
            )

    def add_handshake(
        self,
        *,
        bssid: str,
        ssid: str,
        kind: str,
        path: str,
        size: int,
        ts: float | None = None,
        cooldown: float = 30.0,
        note: str = "",
    ) -> int | None:
        ts = ts or time.time()
        with self._lock:
            recent = self.db.execute(
                "SELECT ts FROM handshakes WHERE bssid = ? AND kind = ? ORDER BY ts DESC LIMIT 1",
                (bssid, kind),
            ).fetchone()
            if recent is not None and ts - float(recent["ts"]) < cooldown:
                return None
            cursor = self.db.execute(
                """
                INSERT INTO handshakes (ts, bssid, ssid, kind, path, size, note)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (ts, bssid, ssid, kind, path, size, note),
            )
            return int(cursor.lastrowid)

    def add_event(self, level: str, kind: str, message: str, ts: float | None = None) -> int:
        ts = ts or time.time()
        with self._lock:
            cursor = self.db.execute(
                "INSERT INTO events (ts, level, kind, message) VALUES (?, ?, ?, ?)",
                (ts, level, kind, message),
            )
            self.db.execute(
                "DELETE FROM events WHERE id < (SELECT MAX(id) - 5000 FROM events)"
            )
            return int(cursor.lastrowid)

    def events(self, limit: int = 100, after_id: int = 0) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            if after_id:
                rows = self.db.execute(
                    "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
                    (after_id, limit),
                ).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT * FROM (SELECT * FROM events ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
                    (limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    def aps(self, limit: int = 300, since: float | None = None) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 2000))
        with self._lock:
            if since:
                rows = self.db.execute(
                    "SELECT * FROM aps WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT ?",
                    (since, limit),
                ).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT * FROM aps ORDER BY last_seen DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(row) for row in rows]

    def clients(self, limit: int = 300, since: float | None = None) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 2000))
        with self._lock:
            if since:
                rows = self.db.execute(
                    "SELECT * FROM clients WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT ?",
                    (since, limit),
                ).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT * FROM clients ORDER BY last_seen DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(row) for row in rows]

    def handshakes(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM handshakes ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def handshake(self, handshake_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.db.execute(
                "SELECT * FROM handshakes WHERE id = ?", (int(handshake_id),)
            ).fetchone()
        return dict(row) if row else None

    def mark_verified(self, handshake_id: int, verified: bool, note: str = "") -> None:
        with self._lock:
            self.db.execute(
                "UPDATE handshakes SET verified = ?, note = ? WHERE id = ?",
                (1 if verified else 0, note, int(handshake_id)),
            )

    def counts(self) -> dict[str, int]:
        with self._lock:
            aps = self.db.execute("SELECT COUNT(*) FROM aps").fetchone()[0]
            clients = self.db.execute(
                "SELECT COUNT(DISTINCT mac) FROM clients"
            ).fetchone()[0]
            handshakes = self.db.execute("SELECT COUNT(*) FROM handshakes").fetchone()[0]
            verified = self.db.execute(
                "SELECT COUNT(*) FROM handshakes WHERE verified = 1"
            ).fetchone()[0]
        return {
            "aps": int(aps),
            "clients": int(clients),
            "handshakes": int(handshakes),
            "verified": int(verified),
        }

    def recent_counts(self, seconds: float = 120) -> dict[str, int]:
        cutoff = time.time() - max(0, seconds)
        with self._lock:
            aps = self.db.execute(
                "SELECT COUNT(*) FROM aps WHERE first_seen >= ?", (cutoff,)
            ).fetchone()[0]
            handshakes = self.db.execute(
                "SELECT COUNT(*) FROM handshakes WHERE ts >= ?", (cutoff,)
            ).fetchone()[0]
        return {"new_aps": int(aps), "handshakes": int(handshakes)}

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self.db.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def start_session(self, mode: str) -> int:
        with self._lock:
            cursor = self.db.execute(
                "INSERT INTO sessions (started, mode) VALUES (?, ?)",
                (time.time(), mode),
            )
            return int(cursor.lastrowid)

    def end_session(
        self,
        session_id: int,
        *,
        aps: int = 0,
        clients: int = 0,
        handshakes: int = 0,
        hops: int = 0,
    ) -> None:
        with self._lock:
            self.db.execute(
                """
                UPDATE sessions SET ended = ?, aps = ?, clients = ?, handshakes = ?, hops = ?
                WHERE id = ?
                """,
                (time.time(), aps, clients, handshakes, hops, int(session_id)),
            )

    def import_aps(self, rows: Iterable[dict[str, Any]]) -> None:
        for row in rows:
            self.upsert_ap(
                bssid=row["bssid"],
                ssid=row.get("ssid", ""),
                channel=row.get("channel"),
                rssi=row.get("rssi"),
                privacy=row.get("privacy"),
                ts=row.get("last_seen"),
            )
