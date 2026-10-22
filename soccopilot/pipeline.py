"""Pipeline coordinator: runs every stage from ingest to triage for a batch of raw events."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .correlate import Correlator, Incident
from .detect import Alert, DetectionEngine
from .enrich import Enricher
from .ingest import IngestService
from .normalize import NormalizedEvent, normalize_envelope
from .playbooks import PlaybookEngine
from .store import EventStore, StateStore
from .triage import TriageEngine


class SOCCopilot:
    """Coordinates all 8 stages of the SOC Copilot pipeline."""

    def __init__(
        self,
        duckdb_path: str | Path | None = None,
        sqlite_path: str | Path | None = None,
        audit_path: str | Path | None = None,
        audit_key: bytes | str | None = None,
    ):
        self.audit = AuditLog(path=audit_path, key=audit_key)
        self.event_store = EventStore(path=duckdb_path)
        self.state_store = StateStore(path=sqlite_path)
        self.ingest_service = IngestService()
        self.enricher = Enricher()
        self.detector = DetectionEngine()
        self.correlator = Correlator()
        self.playbooks = PlaybookEngine(audit=self.audit, state_store=self.state_store)
        self.triage_engine = TriageEngine(
            event_store=self.event_store,
            state_store=self.state_store,
            enricher=self.enricher,
            playbooks=self.playbooks,
            audit=self.audit,
        )
        self.alerts: list[Alert] = []
        self.incidents: dict[str, Incident] = {}
        self._event_seq = 0

    def reset(self) -> None:
        self.event_store.clear()
        self.state_store.clear()
        self.ingest_service = IngestService()
        self.enricher = Enricher()
        self.detector.reset()
        self.correlator = Correlator()
        self.playbooks.reset()
        self.alerts.clear()
        self.incidents.clear()
        self._event_seq = 0
        self.audit.append("system_reset")

    def process_raw_events(
        self,
        raw_events: list[dict[str, Any]],
        source: str | None = None,
        transport: str = "webhook",
        auto_triage: bool = False,
    ) -> dict[str, Any]:
        t0 = time.perf_counter()
        batch = self.ingest_service.ingest_batch(raw_events, source=source, transport=transport)
        normalized_batch: list[NormalizedEvent] = []
        new_alerts: list[Alert] = []

        for env in batch.accepted:
            self._event_seq += 1
            ev = normalize_envelope(env, seq=self._event_seq)
            ev = self.enricher.enrich(ev)
            normalized_batch.append(ev)
            fired = self.detector.evaluate_event(ev)
            new_alerts.extend(fired)

        self.event_store.insert_many(normalized_batch)
        self.alerts.extend(new_alerts)

        # Re-correlate active alerts into incidents
        correlated = self.correlator.correlate(self.alerts, self.event_store.all_events())
        self.incidents = {inc.incident_id: inc for inc in correlated}
        self.state_store.save_incidents(correlated)

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        self.audit.append(
            "ingest_processed",
            transport=transport,
            accepted=len(batch.accepted),
            duplicates=batch.duplicates,
            rejected=len(batch.rejected),
            new_alerts=len(new_alerts),
            active_incidents=len(correlated),
            latency_ms=elapsed_ms,
        )

        if auto_triage:
            for inc in correlated:
                self.triage_engine.triage_incident(inc, use_llm=False)

        return {
            "accepted": len(batch.accepted),
            "duplicates": batch.duplicates,
            "rejected": batch.rejected,
            "new_alerts": len(new_alerts),
            "incidents": len(correlated),
            "latency_ms": elapsed_ms,
        }
