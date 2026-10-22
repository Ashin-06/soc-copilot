"""Pipeline coordinator: runs every stage from ingest to triage for a batch of raw events."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .correlate import Correlator, Incident
from .detect import Alert, DetectionEngine
from .enrich import Enricher
from .ingest import IngestBatchResult, IngestService
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
        if self.event_store.count():
            self._replay()

    def _replay(self) -> None:
        """Rebuild in-memory state after a restart. Alerts are derived data, so they are
        recomputed from the stored events; incident IDs, analyst status and feedback come back
        from SQLite through the correlator's carry-over."""
        events = self.event_store.all_events()
        for ev in events:
            self.ingest_service.validator.seen_hashes[ev.raw_hash] = ev.timestamp
            self.alerts.extend(self.detector.evaluate_event(self.enricher.enrich(ev)))
        self.correlator.rule_weights.update(self.state_store.rule_weights())
        previous = {d["incident_id"]: Incident(**d) for d in self.state_store.list_incidents()}
        self.incidents = {i.incident_id: i for i in self.correlator.correlate(self.alerts, events, previous=previous)}

    def reset(self) -> None:
        self.event_store.clear()
        self.state_store.clear()
        self.ingest_service = IngestService()
        self.enricher = Enricher()
        self.triage_engine.enricher = self.enricher
        self.detector.reset()
        self.correlator = Correlator()
        self.playbooks.reset()
        self.alerts.clear()
        self.incidents.clear()
        self.audit.append("system_reset")

    def _claim_event_id(self, ev: NormalizedEvent, taken: set[str]) -> None:
        """Event IDs are evidence references: a reused source ID gets a hash suffix instead of
        overwriting the event already stored under that ID."""
        base, n = ev.event_id, 1
        while ev.event_id in taken or self.event_store.get(ev.event_id) is not None:
            ev.details.setdefault("source_event_id", base)
            ev.event_id = f"{base}-{ev.raw_hash[:8].upper()}" + (f"-{n}" if n > 1 else "")
            n += 1
        taken.add(ev.event_id)

    def process_raw_events(
        self,
        raw_events: list[dict[str, Any]],
        source: str | None = None,
        transport: str = "webhook",
        auto_triage: bool = False,
    ) -> dict[str, Any]:
        t0 = time.perf_counter()
        batch = self.ingest_service.ingest_batch(raw_events, source=source, transport=transport)
        return self._process(batch, transport, auto_triage, t0)

    def process_file(self, path: str | Path, source: str | None = None, auto_triage: bool = False) -> dict[str, Any]:
        t0 = time.perf_counter()
        return self._process(self.ingest_service.ingest_file(path, source=source), "file_drop", auto_triage, t0)

    def _process(self, batch: IngestBatchResult, transport: str, auto_triage: bool, t0: float) -> dict[str, Any]:
        normalized_batch: list[NormalizedEvent] = []
        new_alerts: list[Alert] = []
        rejected = list(batch.rejected)
        taken: set[str] = set()

        for env in batch.accepted:
            try:
                ev = self.enricher.enrich(normalize_envelope(env))
            except Exception as e:  # one unparseable event must not drop the rest of the batch
                rejected.append({"event_hash": env.event_hash, "reason": f"normalisation failed: {type(e).__name__}"})
                continue
            self._claim_event_id(ev, taken)
            normalized_batch.append(ev)
            new_alerts.extend(self.detector.evaluate_event(ev))

        self.event_store.insert_many(normalized_batch)
        self.alerts.extend(new_alerts)

        # Re-correlate active alerts into incidents
        # ponytail: re-correlates every alert on each batch; window by time once alert volume makes this slow
        correlated = self.correlator.correlate(self.alerts, self.event_store.all_events(), previous=self.incidents)
        self.incidents = {inc.incident_id: inc for inc in correlated}
        self.state_store.replace_incidents(correlated)

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        self.audit.append(
            "ingest_processed",
            transport=transport,
            accepted=len(normalized_batch),
            duplicates=batch.duplicates,
            rejected=len(rejected),
            new_alerts=len(new_alerts),
            active_incidents=len(correlated),
            latency_ms=elapsed_ms,
        )

        if auto_triage:
            for inc in correlated:
                self.triage_engine.triage_incident(inc, use_llm=False)

        return {
            "accepted": len(normalized_batch),
            "duplicates": batch.duplicates,
            "rejected": rejected,
            "new_alerts": len(new_alerts),
            "incidents": len(correlated),
            "latency_ms": elapsed_ms,
        }
