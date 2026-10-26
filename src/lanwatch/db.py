"""SQLite inventory: devices, IP history, runs and the event timeline."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac             TEXT PRIMARY KEY,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    last_ip         TEXT,
    vendor          TEXT,
    hostname        TEXT,
    hostname_source TEXT,
    model_hint      TEXT,
    label           TEXT,
    known           INTEGER NOT NULL DEFAULT 0,
    randomized      INTEGER NOT NULL DEFAULT 0,
    last_sources    TEXT
);
CREATE TABLE IF NOT EXISTS ip_history (
    mac        TEXT NOT NULL REFERENCES devices(mac),
    ip         TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (mac, ip)
);
CREATE INDEX IF NOT EXISTS ip_history_ip ON ip_history(ip);
CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started      TEXT NOT NULL,
    finished     TEXT,
    mode         TEXT NOT NULL,
    status       TEXT NOT NULL,
    device_count INTEGER,
    new_count    INTEGER,
    note         TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    run_id   INTEGER REFERENCES runs(id),
    kind     TEXT NOT NULL,
    severity TEXT NOT NULL,
    mac      TEXT,
    ip       TEXT,
    message  TEXT NOT NULL,
    data     TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Inventory:
    def __init__(self, path: Path | str) -> None:
        if isinstance(path, Path):
            path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        if str(path) != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # --- devices ---------------------------------------------------------
    def device(self, mac: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()

    def devices(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM devices ORDER BY known ASC, last_seen DESC").fetchall()

    def devices_with_hostname(self, hostname: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM devices WHERE lower(hostname) = lower(?)", (hostname,)).fetchall()

    def insert_device(self, mac: str, now: str, **fields) -> None:
        cols = {"mac": mac, "first_seen": now, "last_seen": now, **fields}
        names = ", ".join(cols)
        marks = ", ".join("?" for _ in cols)
        self.conn.execute(f"INSERT INTO devices ({names}) VALUES ({marks})", tuple(cols.values()))

    _UPDATABLE = {"last_seen", "last_ip", "vendor", "hostname", "hostname_source", "model_hint", "label", "known", "randomized", "last_sources"}

    def update_device(self, mac: str, **fields) -> None:
        bad = set(fields) - self._UPDATABLE
        if bad:
            raise ValueError(f"not updatable: {bad}")
        if not fields:
            return
        sets = ", ".join(f"{k} = ?" for k in fields)
        self.conn.execute(f"UPDATE devices SET {sets} WHERE mac = ?", (*fields.values(), mac))

    def set_known(self, mac: str, known: bool) -> bool:
        cur = self.conn.execute("UPDATE devices SET known = ? WHERE mac = ?", (1 if known else 0, mac))
        self.conn.commit()
        return cur.rowcount == 1

    def set_label(self, mac: str, label: str | None) -> bool:
        cur = self.conn.execute("UPDATE devices SET label = ? WHERE mac = ?", ((label or "").strip()[:80] or None, mac))
        self.conn.commit()
        return cur.rowcount == 1

    # --- ip history --------------------------------------------------------
    def touch_ip(self, mac: str, ip: str, now: str) -> None:
        self.conn.execute(
            "INSERT INTO ip_history (mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(mac, ip) DO UPDATE SET last_seen = excluded.last_seen",
            (mac, ip, now, now),
        )

    def ip_history(self, mac: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM ip_history WHERE mac = ? ORDER BY last_seen DESC", (mac,)).fetchall()

    def other_holders(self, ip: str, mac: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM ip_history WHERE ip = ? AND mac != ? ORDER BY last_seen DESC", (ip, mac)
        ).fetchall()

    # --- runs & events ---------------------------------------------------
    def start_run(self, mode: str, now: str) -> int:
        cur = self.conn.execute("INSERT INTO runs (started, mode, status) VALUES (?, ?, 'running')", (now, mode))
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_run(self, run_id: int, status: str, device_count: int | None = None, new_count: int | None = None, note: str | None = None) -> None:
        self.conn.execute(
            "UPDATE runs SET finished = ?, status = ?, device_count = ?, new_count = ?, note = ? WHERE id = ?",
            (utcnow(), status, device_count, new_count, note, run_id),
        )
        self.conn.commit()

    def runs(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def add_event(self, ts: str, run_id: int | None, kind: str, severity: str, message: str, mac: str | None = None, ip: str | None = None, data: dict | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO events (ts, run_id, kind, severity, mac, ip, message, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, run_id, kind, severity, mac, ip, message, json.dumps(data) if data else None),
        )
        return int(cur.lastrowid)

    def events(self, limit: int = 200) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def recent_event(self, kind: str, since: str, mac: str | None = None, ip: str | None = None) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM events WHERE kind = ? AND ts >= ? AND coalesce(mac,'') = coalesce(?,'') AND coalesce(ip,'') = coalesce(?,'') ORDER BY id DESC LIMIT 1",
            (kind, since, mac, ip),
        ).fetchone()

    # --- meta --------------------------------------------------------------
    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    def commit(self) -> None:
        self.conn.commit()
