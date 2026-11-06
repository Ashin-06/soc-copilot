"""Storage layer:
- Normalised events -> DuckDB (`EventStore`) for fast analytical log search & entity timelines
- Incidents, approvals, reports, feedback -> SQLite or Postgres (`StateStore`, db.py, migrations/)
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import duckdb
import pandas as pd
from sqlalchemy import text

from . import db
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
        # Whole event set in memory; page from DuckDB once it outgrows RAM
        # (the SQL below only interpolates the COLUMNS constant)
        self._cache: dict[str, NormalizedEvent] = {
            r[0]: _row_to_event(r)
            for r in self.conn.execute(f"SELECT {', '.join(COLUMNS)} FROM normalized_events").fetchall()  # nosec B608
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
        ).fetchall()

    def clear(self) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM normalized_events").fetchall()
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
        # one bulk insert from a DataFrame: executemany binds row by row and took ~170 s per 5,000 events
        batch = pd.DataFrame(rows, columns=list(COLUMNS)).astype({"bytes_out": "int64", "amount": "float64", "timestamp": "float64"})
        with self._lock:
            self.conn.register("_batch", batch)
            try:
                # consume the result: DuckDB 2 refuses register/unregister while one is pending
                self.conn.execute(f"INSERT OR REPLACE INTO normalized_events SELECT {', '.join(COLUMNS)} FROM _batch").fetchall()  # nosec B608
            finally:
                self.conn.unregister("_batch")
            for ev in events:
                self._cache[ev.event_id] = ev
        return len(events)

    def get(self, event_id: str) -> NormalizedEvent | None:
        return self._cache.get(event_id)

    def all_events(self) -> list[NormalizedEvent]:
        return sorted(self._cache.values(), key=lambda e: e.timestamp)

    def count(self) -> int:
        with self._lock:
            # fetchall, not fetchone: DuckDB 2 keeps a result open until a fetch comes back empty
            rows = self.conn.execute("SELECT COUNT(*) FROM normalized_events").fetchall()
            return int(rows[0][0]) if rows else 0

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

        # clauses are fixed templates; every value is a bound ? parameter
        sql = (
            "SELECT event_id, iso_timestamp, source, event_category, event_action, event_outcome, "  # nosec B608
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
    """Incidents, triage reports, playbook approvals and analyst feedback in SQLite or Postgres.

    `path` is a database URL, a SQLite file path, or None for an in-memory database."""

    def __init__(self, path: str | Path | None = None):
        url = "sqlite://" if path is None else str(path) if "://" in str(path) else f"sqlite:///{Path(path).as_posix()}"
        self.db = db.connect(url)
        self._lock = threading.Lock()

    def _run(self, *statements: tuple[str, Any]) -> None:
        with self._lock, self.db.begin() as c:
            for sql, params in statements:
                c.execute(text(sql), params)

    def _rows(self, sql: str, params: dict | None = None) -> list[tuple]:
        with self._lock, self.db.connect() as c:
            return [tuple(r) for r in c.execute(text(sql), params or {})]

    def clear(self) -> None:
        self._run(("DELETE FROM incidents", {}), ("DELETE FROM reports", {}), ("DELETE FROM approvals", {}),
                  ("DELETE FROM feedback", {}), ("DELETE FROM rule_weights", {}))

    def save_incident(self, inc: Incident) -> None:
        self.save_incidents([inc])

    def save_incidents(self, incidents: list[Incident], replace_all: bool = False) -> None:
        upsert = ("INSERT INTO incidents (incident_id, risk_score, severity, status, created_at, payload_json) "
                  "VALUES (:id, :risk, :sev, :status, :ts, :payload) ON CONFLICT (incident_id) DO UPDATE SET "
                  "risk_score = excluded.risk_score, severity = excluded.severity, status = excluded.status, "
                  "created_at = excluded.created_at, payload_json = excluded.payload_json")
        self._run(*([("DELETE FROM incidents", {})] if replace_all else []),
                  *((upsert, {"id": i.incident_id, "risk": i.risk_score, "sev": i.severity, "status": i.status,
                              "ts": i.created_at, "payload": json.dumps(i.to_dict(), default=str)}) for i in incidents))

    def replace_incidents(self, incidents: list[Incident]) -> None:
        """Make the stored set match the current correlation, so an incident that was merged
        into another one does not linger as a stale duplicate."""
        self.save_incidents(incidents, replace_all=True)

    def list_incidents(self) -> list[dict[str, Any]]:
        rows = self._rows("SELECT payload_json FROM incidents ORDER BY risk_score DESC, created_at ASC")
        return [json.loads(r[0]) for r in rows]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        rows = self._rows("SELECT payload_json FROM incidents WHERE incident_id = :id", {"id": incident_id})
        return json.loads(rows[0][0]) if rows else None

    def save_report(self, incident_id: str, report: dict[str, Any], ts: float) -> None:
        self._run(("INSERT INTO reports (incident_id, created_at, payload_json) VALUES (:id, :ts, :payload) "
                   "ON CONFLICT (incident_id) DO UPDATE SET created_at = excluded.created_at, payload_json = excluded.payload_json",
                   {"id": incident_id, "ts": ts, "payload": json.dumps(report, default=str)}))

    def get_report(self, incident_id: str) -> dict[str, Any] | None:
        rows = self._rows("SELECT payload_json FROM reports WHERE incident_id = :id", {"id": incident_id})
        return json.loads(rows[0][0]) if rows else None

    def save_approval(self, action_id: str, incident_id: str, status: str, created_at: float, payload: dict[str, Any]) -> None:
        self._run(("INSERT INTO approvals (action_id, incident_id, status, created_at, payload_json) "
                   "VALUES (:id, :inc, :status, :ts, :payload) ON CONFLICT (action_id) DO UPDATE SET "
                   "incident_id = excluded.incident_id, status = excluded.status, created_at = excluded.created_at, "
                   "payload_json = excluded.payload_json",
                   {"id": action_id, "inc": incident_id, "status": status, "ts": created_at,
                    "payload": json.dumps(payload, default=str)}))

    def list_approvals(self, incident_id: str | None = None) -> list[dict[str, Any]]:
        if incident_id:
            rows = self._rows("SELECT payload_json FROM approvals WHERE incident_id = :id ORDER BY created_at ASC",
                              {"id": incident_id})
        else:
            rows = self._rows("SELECT payload_json FROM approvals ORDER BY created_at ASC")
        return [json.loads(r[0]) for r in rows]

    def rule_weights(self) -> dict[str, float]:
        return dict(self._rows("SELECT rule_id, weight FROM rule_weights"))

    def save_feedback(self, incident_id: str, verdict: str, reason: str, analyst: str, ts: float, payload: dict[str, Any]) -> None:
        self._run(("INSERT INTO feedback (incident_id, verdict, reason, analyst, created_at, payload_json) "
                   "VALUES (:id, :verdict, :reason, :analyst, :ts, :payload)",
                   {"id": incident_id, "verdict": verdict, "reason": reason, "analyst": analyst, "ts": ts,
                    "payload": json.dumps(payload, default=str)}),
                  *(("INSERT INTO rule_weights (rule_id, weight) VALUES (:r, :w) "
                     "ON CONFLICT (rule_id) DO UPDATE SET weight = excluded.weight", {"r": rid, "w": float(w)})
                    for rid, w in payload.get("updated_rule_weights", {}).items()))
