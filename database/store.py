"""SQLite persistence: entities, policies, settings and the audit log.

All SQL uses parameter binding. Table and column names only ever come from the
whitelists below, never from user input.
"""
from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import pandas as pd

import config

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    identity_status TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    device_type TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES users(user_id),
    compliance_status TEXT NOT NULL,
    last_verified TEXT,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS resources (
    resource_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    sensitivity INTEGER NOT NULL,
    allowed_roles TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    resource_category TEXT NOT NULL,
    max_sensitivity INTEGER NOT NULL,
    request_types TEXT NOT NULL,
    require_compliant_device INTEGER NOT NULL DEFAULT 1,
    business_hours_only INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    user_id TEXT,
    user_role TEXT,
    device_id TEXT,
    resource_id TEXT,
    request_type TEXT,
    event_type TEXT NOT NULL,
    policy_id TEXT,
    policy_checks TEXT,
    risk_score REAL,
    risk_level TEXT,
    risk_factors TEXT,
    anomaly_score REAL,
    anomaly_flag INTEGER,
    anomaly_method TEXT,
    decision TEXT NOT NULL,
    reason TEXT,
    is_simulated INTEGER NOT NULL DEFAULT 1,
    context TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
"""

# table -> (primary key, editable columns, "is active" column)
TABLES = {
    "users": ("user_id", ["display_name", "role", "identity_status", "active"], "active"),
    "devices": ("device_id", ["device_type", "owner_id", "compliance_status", "last_verified", "active"], "active"),
    "resources": ("resource_id", ["name", "category", "sensitivity", "allowed_roles", "active"], "active"),
    "policies": (
        "policy_id",
        ["name", "role", "resource_category", "max_sensitivity", "request_types",
         "require_compliant_device", "business_hours_only", "enabled", "description"],
        "enabled",
    ),
}

EVENT_COLUMNS = [
    "event_id", "timestamp", "user_id", "user_role", "device_id", "resource_id",
    "request_type", "event_type", "policy_id", "policy_checks", "risk_score",
    "risk_level", "risk_factors", "anomaly_score", "anomaly_flag", "anomaly_method",
    "decision", "reason", "is_simulated", "context",
]
_INSERTABLE_EVENT_COLUMNS = [c for c in EVENT_COLUMNS if c != "event_id"]


class DuplicateIdError(Exception):
    """Raised when inserting an entity whose ID already exists."""


class Database:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    # ------------------------------------------------------------ connection
    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    # -------------------------------------------------------------- entities
    @staticmethod
    def _table(table: str):
        if table not in TABLES:
            raise ValueError(f"Unknown table '{table}'.")
        return TABLES[table]

    def list_entities(self, table: str, active_only: bool = False) -> list[dict]:
        pk, _, active_col = self._table(table)
        sql = f"SELECT * FROM {table}"
        if active_only:
            sql += f" WHERE {active_col} = 1"
        sql += f" ORDER BY {pk}"
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(sql).fetchall()]

    def get_entity(self, table: str, entity_id: str) -> dict | None:
        pk, _, _ = self._table(table)
        with self._conn() as conn:
            row = conn.execute(f"SELECT * FROM {table} WHERE {pk} = ?", (entity_id,)).fetchone()
        return dict(row) if row else None

    def insert_entity(self, table: str, data: dict) -> None:
        pk, editable, _ = self._table(table)
        cols = [pk] + editable
        values = [data.get(c) for c in cols]
        sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})"
        try:
            with self._conn() as conn:
                conn.execute(sql, values)
        except sqlite3.IntegrityError as exc:
            if "UNIQUE" in str(exc) or "PRIMARY KEY" in str(exc):
                raise DuplicateIdError(f"{data.get(pk)} already exists in {table}.") from exc
            raise

    def update_entity(self, table: str, entity_id: str, fields: dict) -> bool:
        pk, editable, _ = self._table(table)
        bad = set(fields) - set(editable)
        if bad:
            raise ValueError(f"Cannot edit column(s): {', '.join(sorted(bad))}.")
        if not fields:
            raise ValueError("No fields to update.")
        assignments = ", ".join(f"{c} = ?" for c in fields)
        with self._conn() as conn:
            cur = conn.execute(
                f"UPDATE {table} SET {assignments} WHERE {pk} = ?",
                [*fields.values(), entity_id],
            )
            return cur.rowcount == 1

    def set_active(self, table: str, entity_id: str, active: bool) -> bool:
        _, _, active_col = self._table(table)
        return self.update_entity(table, entity_id, {active_col: 1 if active else 0})

    # -------------------------------------------------------------- settings
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self._conn() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )

    def get_thresholds(self) -> dict:
        out = {}
        for key, default in config.DEFAULT_SETTINGS.items():
            raw = self.get_setting(key)
            try:
                out[key] = float(raw) if raw is not None else float(default)
            except ValueError:
                logger.warning("Setting %s holds a non-numeric value %r; using default.", key, raw)
                out[key] = float(default)
        return out

    # ---------------------------------------------------------------- events
    def add_event(self, event: dict) -> int:
        return self.add_events([event])[0]

    def add_events(self, events: list[dict], extra_settings: dict | None = None) -> list[int]:
        """Insert several events (and optional settings) in one transaction."""
        sql = (
            f"INSERT INTO events ({', '.join(_INSERTABLE_EVENT_COLUMNS)}) "
            f"VALUES ({', '.join('?' * len(_INSERTABLE_EVENT_COLUMNS))})"
        )
        ids: list[int] = []
        with self._conn() as conn:
            for ev in events:
                cur = conn.execute(sql, [ev.get(c) for c in _INSERTABLE_EVENT_COLUMNS])
                ids.append(int(cur.lastrowid))
            for key, value in (extra_settings or {}).items():
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, str(value)),
                )
        return ids

    def get_event(self, event_id: int) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM events WHERE event_id = ?", (int(event_id),)).fetchone()
        return dict(row) if row else None

    def count_events(self) -> int:
        with self._conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def query_events(
        self,
        start: str | None = None,
        end: str | None = None,
        roles=None,
        resources=None,
        event_types=None,
        decisions=None,
        search: str | None = None,
        sort_by: str = "timestamp",
        ascending: bool = False,
        limit: int | None = None,
    ) -> pd.DataFrame:
        where: list[str] = []
        params: list = []
        if start:
            where.append("timestamp >= ?")
            params.append(start)
        if end:
            where.append("timestamp <= ?")
            params.append(end)
        for column, values in (
            ("user_role", roles),
            ("resource_id", resources),
            ("event_type", event_types),
            ("decision", decisions),
        ):
            if values:
                values = list(values)
                where.append(f"{column} IN ({', '.join('?' * len(values))})")
                params.extend(values)
        if search:
            like = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append(
                "(user_id LIKE ? ESCAPE '\\' OR device_id LIKE ? ESCAPE '\\' "
                "OR resource_id LIKE ? ESCAPE '\\' OR reason LIKE ? ESCAPE '\\')"
            )
            params.extend([like] * 4)
        if sort_by not in EVENT_COLUMNS:
            raise ValueError(f"Cannot sort by '{sort_by}'.")
        sql = f"SELECT {', '.join(EVENT_COLUMNS)} FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY {sort_by} {'ASC' if ascending else 'DESC'}, event_id {'ASC' if ascending else 'DESC'}"
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        with self._conn() as conn:
            rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        return pd.DataFrame(rows, columns=EVENT_COLUMNS)

    def clear_events(self) -> int:
        """Delete every audit event. Entities and policies are kept."""
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM events")
            return cur.rowcount

    def wipe_all(self) -> None:
        """Delete everything (events, entities, policies, settings)."""
        with self._conn() as conn:
            for table in ("events", "devices", "users", "resources", "policies", "settings"):
                conn.execute(f"DELETE FROM {table}")

    def seed_entities(self, users, devices, resources, policies) -> None:
        """Insert default entities in one transaction. Existing IDs are left untouched."""
        spec = {
            "users": users,
            "devices": devices,
            "resources": resources,
            "policies": policies,
        }
        with self._conn() as conn:
            for table, rows in spec.items():
                pk, editable, _ = TABLES[table]
                cols = [pk] + editable
                sql = f"INSERT OR IGNORE INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})"
                for row in rows:
                    conn.execute(sql, [row.get(c) for c in cols])
