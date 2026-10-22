"""Storage layer:
- Normalised events -> DuckDB (`EventStore`) for fast analytical log search & entity timelines
- Incidents, approvals, reports, feedback -> SQLite (`StateStore`)
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

import duckdb

from .correlate import Incident
from .normalize import NormalizedEvent


COLUMNS = (
    "event_id", "raw_hash", "timestamp", "iso_timestamp", "source", "event_category", "event_action",
    "event_outcome", "username", "customer_id", "source_ip", "host", "device_id", "url", "account",
    "counterparty_account", "amount", "cloud_key", "bytes_out", "message", "entities_json",
    "enrichment_json", "details_json",
)


def _row_to_event(row: tuple) -> NormalizedEvent:
    d = dict(zip(COLUMNS, row))
    d["user"] = d.pop("username")
    for key in ("entities", "enrichment", "details"):
        d[key] = json.loads(d.pop(f"{key}_json") or "null") or ([] if key == "entities" else {})
    return NormalizedEvent.from_dict(d)


class EventStore:
    """Stores normalised events in DuckDB for single-machine OLAP search and timelines.
    Events are also kept in memory for the correlator; with a file path they are reloaded
    from DuckDB on start, so a restart does not lose the evidence behind open incidents."""

    def __init__(self, path: str | Path | None = None):
        self.path = str(path) if path else ":memory:"
        self._lock = threading.Lock()
        self.conn = duckdb.connect(self.path)
        self._init_schema()
        # ponytail: whole event set in memory; page from DuckDB once it outgrows RAM
        self._cache: dict[str, NormalizedEvent] = {
            r[0]: _row_to_event(r)
            for r in self.conn.execute(f"SELECT {', '.join(COLUMNS)} FROM normalized_events").fetchall()
        }

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS normalized_events (
                event_id VARCHAR PRIMARY KEY,
                raw_hash VARCHAR,
                timestamp DOUBLE,
                iso_timestamp VARCHAR,
                source VARCHAR,
                event_category VARCHAR,
                event_action VARCHAR,
                event_outcome VARCHAR,
                username VARCHAR,
                customer_id VARCHAR,
                source_ip VARCHAR,
                host VARCHAR,
                device_id VARCHAR,
                url VARCHAR,
                account VARCHAR,
                counterparty_account VARCHAR,
                amount DOUBLE,
                cloud_key VARCHAR,
                bytes_out BIGINT,
                message VARCHAR,
                entities_json VARCHAR,
                enrichment_json VARCHAR,
                details_json VARCHAR
            )
            """
        )

    def clear(self) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM normalized_events")
            self._cache.clear()

    def insert_many(self, events: list[NormalizedEvent]) -> int:
        if not events:
            return 0
        rows = [
            (
                ev.event_id,
                ev.raw_hash,
                ev.timestamp,
                ev.iso_timestamp,
                ev.source,
                ev.event_category,
                ev.event_action,
                ev.event_outcome,
                ev.user,
                ev.customer_id,
                ev.source_ip,
                ev.host,
                ev.device_id,
                ev.url,
                ev.account,
                ev.counterparty_account,
                ev.amount,
                ev.cloud_key,
                ev.bytes_out,
                ev.message,
                json.dumps(ev.entities),
                json.dumps(ev.enrichment, default=str),
                json.dumps(ev.details, default=str),
            )
            for ev in events
        ]
        with self._lock:
            self.conn.executemany(
                """
                INSERT OR REPLACE INTO normalized_events VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                rows,
            )
            for ev in events:
                self._cache[ev.event_id] = ev
        return len(events)

    def get(self, event_id: str) -> NormalizedEvent | None:
        return self._cache.get(event_id)

    def all_events(self) -> list[NormalizedEvent]:
        return sorted(self._cache.values(), key=lambda e: e.timestamp)

    def count(self) -> int:
        with self._lock:
            row = self.conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()
            return int(row[0]) if row else 0

    def search_logs(
        self,
        query: str | None = None,
        entity: str | None = None,
        category: str | None = None,
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        # contains() is a literal substring test, so % and _ in a query are not wildcards
        clauses: list[str] = ["1=1"]
        params: list[Any] = []
        if query:
            clauses.append("(contains(LOWER(message), ?) OR contains(LOWER(event_action), ?) OR contains(LOWER(host), ?))")
            q = str(query).lower()
            params.extend([q, q, q])
        if entity:
            # match the whole quoted token: ip:10.0.0.1 must not also match ip:10.0.0.15
            clauses.append("contains(LOWER(entities_json), ?)")
            params.append(json.dumps(str(entity).lower()))
        if category:
            clauses.append("LOWER(event_category) = ?")
            params.append(category.lower())

        sql = (
            "SELECT event_id, iso_timestamp, source, event_category, event_action, event_outcome, "
            "username, customer_id, source_ip, host, account, amount, message "
            f"FROM normalized_events WHERE {' AND '.join(clauses)} "
            f"ORDER BY timestamp ASC LIMIT {int(max(1, min(limit, 200)))}"
        )
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        cols = [
            "event_id", "iso_timestamp", "source", "event_category", "event_action", "event_outcome",
            "user", "customer_id", "source_ip", "host", "account", "amount", "message",
        ]
        return [dict(zip(cols, r)) for r in rows]

    def entity_timeline(self, entity: str, limit: int = 50) -> list[dict[str, Any]]:
        return self.search_logs(entity=entity, limit=limit)

    def customer_transactions(self, customer_id: str, limit: int = 25) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT event_id, iso_timestamp, event_action, event_outcome, account,
                       counterparty_account, amount, source_ip, device_id, message
                FROM normalized_events
                WHERE customer_id = ? AND source = 'payments'
                ORDER BY timestamp ASC
                LIMIT ?
                """,
                [customer_id, max(1, min(int(limit), 200))],
            ).fetchall()
        cols = [
            "event_id", "iso_timestamp", "action", "outcome", "account",
            "counterparty_account", "amount", "source_ip", "device_id", "message",
        ]
        return [dict(zip(cols, r)) for r in rows]


class StateStore:
    """SQLite store for incidents, triage reports, playbook approvals, and analyst feedback."""

    def __init__(self, path: str | Path | None = None):
        self.path = str(path) if path else ":memory:"
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    risk_score REAL,
                    severity TEXT,
                    status TEXT,
                    created_at REAL,
                    payload_json TEXT
                );
                CREATE TABLE IF NOT EXISTS reports (
                    incident_id TEXT PRIMARY KEY,
                    created_at REAL,
                    payload_json TEXT
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    action_id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    status TEXT,
                    created_at REAL,
                    payload_json TEXT
                );
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT,
                    verdict TEXT,
                    reason TEXT,
                    analyst TEXT,
                    created_at REAL,
                    payload_json TEXT
                );
                CREATE TABLE IF NOT EXISTS rule_weights (
                    rule_id TEXT PRIMARY KEY,
                    weight REAL
                );
                """
            )
            self.conn.commit()

    def clear(self) -> None:
        with self._lock:
            self.conn.executescript(
                """
                DELETE FROM incidents;
                DELETE FROM reports;
                DELETE FROM approvals;
                DELETE FROM feedback;
                DELETE FROM rule_weights;
                """
            )
            self.conn.commit()

    def save_incident(self, inc: Incident) -> None:
        self.save_incidents([inc])

    def save_incidents(self, incidents: list[Incident], replace_all: bool = False) -> None:
        with self._lock:
            if replace_all:
                self.conn.execute("DELETE FROM incidents")
            self.conn.executemany(
                "INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (
                        inc.incident_id,
                        inc.risk_score,
                        inc.severity,
                        inc.status,
                        inc.created_at,
                        json.dumps(inc.to_dict(), default=str),
                    )
                    for inc in incidents
                ],
            )
            self.conn.commit()

    def replace_incidents(self, incidents: list[Incident]) -> None:
        """Make the stored set match the current correlation, so an incident that was merged
        into another one does not linger as a stale duplicate."""
        self.save_incidents(incidents, replace_all=True)

    def list_incidents(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT payload_json FROM incidents ORDER BY risk_score DESC, created_at ASC"
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT payload_json FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def save_report(self, incident_id: str, report: dict[str, Any], ts: float) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO reports VALUES (?, ?, ?)",
                (incident_id, ts, json.dumps(report, default=str)),
            )
            self.conn.commit()

    def get_report(self, incident_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT payload_json FROM reports WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def save_approval(self, action_id: str, incident_id: str, status: str, created_at: float, payload: dict[str, Any]) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO approvals VALUES (?, ?, ?, ?, ?)",
                (action_id, incident_id, status, created_at, json.dumps(payload, default=str)),
            )
            self.conn.commit()

    def list_approvals(self, incident_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if incident_id:
                rows = self.conn.execute(
                    "SELECT payload_json FROM approvals WHERE incident_id = ? ORDER BY created_at ASC",
                    (incident_id,),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT payload_json FROM approvals ORDER BY created_at ASC"
                ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def rule_weights(self) -> dict[str, float]:
        with self._lock:
            return dict(self.conn.execute("SELECT rule_id, weight FROM rule_weights").fetchall())

    def save_feedback(self, incident_id: str, verdict: str, reason: str, analyst: str, ts: float, payload: dict[str, Any]) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO feedback (incident_id, verdict, reason, analyst, created_at, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
                (incident_id, verdict, reason, analyst, ts, json.dumps(payload, default=str)),
            )
            for rid, w in payload.get("updated_rule_weights", {}).items():
                self.conn.execute(
                    "INSERT OR REPLACE INTO rule_weights VALUES (?, ?)", (rid, float(w))
                )
            self.conn.commit()
