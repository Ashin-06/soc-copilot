"""Pipeline coordinator: runs every stage from ingest to triage for a batch of raw events."""
from __future__ import annotations

import os
import time
import tomllib
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .correlate import Correlator, Incident
from .detect import Alert, DetectionEngine
from .enrich import Enricher
from .ingest import IngestBatchResult, IngestService
from .normalize import NormalizedEvent, normalize_envelope
from .playbooks import PendingAction, PlaybookEngine
from .store import EventStore, StateStore
from .triage import MODEL, PrivacyBridge, TriageEngine, TriageReport

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policy.toml"


def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    with open(path or os.environ.get("SOCCOPILOT_POLICY") or DEFAULT_POLICY, "rb") as f:
        return tomllib.load(f)


class SOCCopilot:
    """Coordinates all 8 stages of the SOC Copilot pipeline."""

    def __init__(
        self,
        duckdb_path: str | Path | None = None,
        sqlite_path: str | Path | None = None,
        audit_path: str | Path | None = None,
        audit_key: bytes | str | None = None,
        audit_previous_keys: tuple[bytes, ...] = (),
        policy_path: str | Path | None = None,
        context_path: str | Path | None = None,
    ):
        self.policy = load_policy(policy_path)
        self.context_path = context_path or os.environ.get("SOCCOPILOT_CONTEXT")
        tri, pb = self.policy.get("triage", {}), self.policy.get("playbooks", {})
        self.audit = AuditLog(path=audit_path, key=audit_key, previous_keys=audit_previous_keys)
        self.event_store = EventStore(path=duckdb_path)
        self.state_store = StateStore(path=sqlite_path)
        self.ingest_service = self._new_ingest()
        self.enricher = Enricher(self.context_path)
        self.detector = DetectionEngine()
        self.correlator = self._new_correlator()
        self.playbooks = PlaybookEngine(
            audit=self.audit,
            state_store=self.state_store,
            ttl=float(pb.get("approval_ttl_seconds", 3600)),
            allowed_actions=pb.get("allowed_actions"),
        )
        self.triage_engine = TriageEngine(
            event_store=self.event_store,
            state_store=self.state_store,
            enricher=self.enricher,
            playbooks=self.playbooks,
            audit=self.audit,
            privacy=PrivacyBridge(role=tri.get("privacy_role", "fraud_analyst")),
            model=os.environ.get("SOCCOPILOT_MODEL") or tri.get("model", MODEL),
            max_turns=int(tri.get("max_turns", 8)),
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

    def _new_ingest(self) -> IngestService:
        ing = self.policy.get("ingest", {})
        return IngestService(
            max_event_bytes=int(ing.get("max_event_bytes", 65536)),
            max_batch_size=int(ing.get("max_batch_size", 5000)),
            silence_thresholds={k: float(v) for k, v in ing.get("silence_seconds", {}).items()},
            dedup_window_s=float(ing.get("dedup_window_seconds", 86400)),
        )

    def _new_correlator(self) -> Correlator:
        cor, sc = self.policy.get("correlate", {}), self.policy.get("scoring", {})
        return Correlator(
            time_window_s=float(cor.get("time_window_seconds", 3600)),
            security_fraud_bonus=float(cor.get("security_fraud_bonus", 18.0)),
            min_incident_score=float(cor.get("min_incident_score", 25.0)),
            suppressed_ips=cor.get("suppressed_ips"),
            suppressed_users=cor.get("suppressed_users"),
            severity_weights=sc.get("severity_weights"),
            tactic_bonus_per_stage=float(sc.get("tactic_bonus_per_stage", 7.5)),
            asset_criticality_weight=float(sc.get("asset_criticality_weight", 3.0)),
            money_at_risk_scale=float(sc.get("money_at_risk_scale", 10000.0)),
            money_at_risk_max_bonus=float(sc.get("money_at_risk_max_bonus", 20.0)),
        )

    def reset(self) -> None:
        self.event_store.clear()
        self.state_store.clear()
        self.ingest_service = self._new_ingest()
        self.enricher = Enricher(self.context_path)
        self.triage_engine.enricher = self.enricher
        self.detector.reset()
        self.correlator = self._new_correlator()
        self.playbooks.reset()
        self.alerts.clear()
        self.incidents.clear()
        self.audit.append("system_reset")

    # Analyst actions. The API and the Streamlit console both go through these, so a verdict or
    # approval is saved and audited the same way whichever screen it came from.

    def triage(self, incident_id: str, use_llm: bool = False, client: Any = None) -> TriageReport:
        inc = self.incidents[incident_id]
        report = self.triage_engine.triage_incident(inc, client=client, use_llm=use_llm)
        if inc.status == "open":
            inc.status = "triaged"
        self.state_store.save_incident(inc)
        return report

    def record_feedback(self, incident_id: str, verdict: str, reason: str, analyst: str) -> dict[str, Any]:
        inc = self.incidents[incident_id]
        fb = self.correlator.record_feedback(inc, verdict, reason, analyst)
        self.state_store.save_incident(inc)
        self.state_store.save_feedback(incident_id, verdict, reason, analyst, time.time(), fb)
        self.audit.append(
            "analyst_feedback",
            incident_id=incident_id,
            verdict=verdict,
            reason=reason,
            analyst=analyst,
            updated_rule_weights=fb["updated_rule_weights"],
        )
        return fb

    def decide_action(self, action_id: str, approve: bool, analyst: str) -> PendingAction:
        act = self.playbooks.decide_and_run(action_id, approve=approve, analyst=analyst)
        inc = self.incidents.get(act.incident_id)
        if inc is not None and act.status == "executed":
            # telling the customer is not containment; anything else that ran is
            if act.action_type != "notify_customer":
                inc.status = "contained"
            elif inc.status == "open":
                inc.status = "triaged"
            self.state_store.save_incident(inc)
        return act

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
        before = {i: set(inc.alert_ids) for i, inc in self.incidents.items()}
        correlated = self.correlator.correlate(self.alerts, self.event_store.all_events(), previous=self.incidents)
        self.incidents = {inc.incident_id: inc for inc in correlated}
        changed = [inc for inc in correlated if before.get(inc.incident_id) != set(inc.alert_ids)]
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
            for inc in changed:  # only cases this batch created or grew
                self.triage_engine.triage_incident(inc, use_llm=False)

        return {
            "accepted": len(normalized_batch),
            "duplicates": batch.duplicates,
            "rejected": rejected,
            "new_alerts": len(new_alerts),
            "incidents": len(correlated),
            "latency_ms": elapsed_ms,
        }
