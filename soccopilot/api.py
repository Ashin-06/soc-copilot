"""FastAPI backend for the SOC Copilot Analyst Console and real-time webhook ingestion.

Endpoints:
- GET  /                         Interactive Analyst Console (web/console.html)
- POST /ingest                   Ingest raw event or batch (Wazuh, ECS, CloudTrail, Auth, API, Payments)
- GET  /health                   Per-source heartbeat health monitor & storage stats
- GET  /incidents                Incident queue ordered by composite risk score
- GET  /incidents/{id}           Full incident detail (storyline timeline, entity graph, alerts, actions)
- GET  /incidents/{id}/report    Get or generate structured AI triage report (with [EVT-...] citations)
- POST /incidents/{id}/report    Run AI triage (Claude tool loop or template fallback)
- POST /incidents/{id}/feedback  Record analyst TP/FP verdict and tune detection rule weights
- GET  /actions                  List pending/decided/executed playbook actions
- POST /actions                  Propose a containment playbook action (requires analyst approval)
- POST /actions/{id}/decide      Approve or decline a proposed action (verified against SHA-256 call digest)
- GET  /audit                    Inspect and verify the hash-chained audit trail
- GET  /evaluate                 Run the labelled campaign benchmark
- POST /reset                    Reset and re-seed demo state
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .evaluate import SOCCopilot, run_evaluation, seed_demo_copilot
from .ingest import IngestValidationError

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="SOC Copilot for a Digital Bank", version="1.0.0")
_lock = threading.Lock()
copilot: SOCCopilot = seed_demo_copilot()


class IngestRequest(BaseModel):
    events: list[dict[str, Any]] | dict[str, Any]
    source: str | None = None
    auto_triage: bool = True


class TriageRequest(BaseModel):
    use_llm: bool = False


class FeedbackRequest(BaseModel):
    verdict: str = Field(..., pattern="^(true_positive|false_positive)$")
    reason: str = Field(..., min_length=2, max_length=500)
    analyst: str = "soc.analyst"


class ActionProposalRequest(BaseModel):
    incident_id: str
    action_type: str
    target: str
    rationale: str
    params: dict[str, Any] = Field(default_factory=dict)


class ActionDecisionRequest(BaseModel):
    approve: bool
    analyst: str = "soc.analyst"


@app.get("/")
def console_ui():
    return FileResponse(ROOT / "web" / "console.html")


@app.get("/health")
def health_status():
    with _lock:
        src_health = copilot.ingest_service.health.check_health()
        quiet = [a.__dict__ for a in copilot.ingest_service.health.quiet_sources()]
        ok_chain, chain_msg = copilot.audit.verify()
        return {
            "status": "degraded" if quiet else "healthy",
            "events_stored": copilot.event_store.count(),
            "active_alerts": len(copilot.alerts),
            "active_incidents": len(copilot.incidents),
            "audit_verified": ok_chain,
            "audit_message": chain_msg,
            "quiet_sources": quiet,
            "sources": src_health,
        }


@app.post("/ingest")
def ingest_webhook(body: IngestRequest):
    raw_list = body.events if isinstance(body.events, list) else [body.events]
    with _lock:
        try:
            res = copilot.process_raw_events(
                raw_list,
                source=body.source,
                transport="webhook",
                auto_triage=body.auto_triage,
            )
        except IngestValidationError as e:
            raise HTTPException(400, str(e)) from e
    return res


@app.get("/incidents")
def list_incidents():
    with _lock:
        incs = sorted(copilot.incidents.values(), key=lambda x: (-x.risk_score, x.created_at))
        return {
            "count": len(incs),
            "incidents": [
                {
                    "incident_id": i.incident_id,
                    "title": i.title,
                    "severity": i.severity,
                    "risk_score": i.risk_score,
                    "status": i.status,
                    "tactics": i.tactics,
                    "techniques": i.techniques,
                    "domains": i.domains,
                    "security_fraud_joined": i.security_fraud_joined,
                    "money_at_risk": i.money_at_risk,
                    "entities": i.entities,
                    "alert_count": len(i.alert_ids),
                    "event_count": len(i.event_ids),
                }
                for i in incs
            ],
            "rule_weights": dict(copilot.correlator.rule_weights),
        }


@app.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    with _lock:
        inc = copilot.incidents.get(incident_id)
        if not inc:
            raise HTTPException(404, f"incident {incident_id} not found")
        rep = copilot.state_store.get_report(incident_id)
        if rep is None:
            rep = copilot.triage_engine.triage_incident(inc, use_llm=False).to_dict()
        actions = copilot.playbooks.list_actions(incident_id=incident_id)
        return {
            "incident": inc.to_dict(),
            "report": rep,
            "actions": actions,
        }


@app.get("/incidents/{incident_id}/report")
def get_incident_report(incident_id: str):
    with _lock:
        inc = copilot.incidents.get(incident_id)
        if not inc:
            raise HTTPException(404, f"incident {incident_id} not found")
        rep = copilot.state_store.get_report(incident_id)
        if rep is None:
            rep = copilot.triage_engine.triage_incident(inc, use_llm=False).to_dict()
        return rep


@app.post("/incidents/{incident_id}/report")
def generate_incident_report(incident_id: str, body: TriageRequest | None = None):
    use_llm = body.use_llm if body else False
    with _lock:
        inc = copilot.incidents.get(incident_id)
        if not inc:
            raise HTTPException(404, f"incident {incident_id} not found")
        rep = copilot.triage_engine.triage_incident(inc, use_llm=use_llm)
        inc.status = "triaged"
        copilot.state_store.save_incident(inc)
        return rep.to_dict()


@app.post("/incidents/{incident_id}/feedback")
def submit_incident_feedback(incident_id: str, body: FeedbackRequest):
    with _lock:
        inc = copilot.incidents.get(incident_id)
        if not inc:
            raise HTTPException(404, f"incident {incident_id} not found")
        fb = copilot.correlator.record_feedback(inc, body.verdict, body.reason, body.analyst)
        copilot.state_store.save_incident(inc)
        copilot.state_store.save_feedback(
            incident_id, body.verdict, body.reason, body.analyst, inc.updated_at, fb
        )
        copilot.audit.append(
            "analyst_feedback",
            incident_id=incident_id,
            verdict=body.verdict,
            reason=body.reason,
            analyst=body.analyst,
            updated_rule_weights=fb["updated_rule_weights"],
        )
        return {
            "incident_id": incident_id,
            "status": inc.status,
            "new_risk_score": inc.risk_score,
            "feedback": fb,
        }


@app.get("/actions")
def list_actions(incident_id: str | None = None):
    with _lock:
        return {
            "actions": copilot.playbooks.list_actions(incident_id=incident_id),
            "connector_state": {
                "blocked_ips": sorted(copilot.playbooks.connectors.blocked_ips),
                "frozen_accounts": sorted(copilot.playbooks.connectors.frozen_accounts),
                "revoked_sessions": sorted(copilot.playbooks.connectors.revoked_sessions),
                "password_resets": sorted(copilot.playbooks.connectors.password_resets),
                "disabled_cloud_keys": sorted(copilot.playbooks.connectors.disabled_cloud_keys),
                "notified_customers": copilot.playbooks.connectors.notified_customers,
            },
        }


@app.post("/actions")
def propose_action(body: ActionProposalRequest):
    with _lock:
        try:
            act = copilot.playbooks.propose(
                body.incident_id,
                body.action_type,
                body.target,
                body.rationale,
                body.params,
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return act.to_dict()


@app.post("/actions/{action_id}/decide")
def decide_action(action_id: str, body: ActionDecisionRequest):
    with _lock:
        try:
            act = copilot.playbooks.decide_and_run(action_id, approve=body.approve, analyst=body.analyst)
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except (ValueError, PermissionError) as e:
            raise HTTPException(400, str(e)) from e
        if body.approve and act.incident_id in copilot.incidents:
            inc = copilot.incidents[act.incident_id]
            inc.status = "contained"
            copilot.state_store.save_incident(inc)
        return act.to_dict()


@app.get("/audit")
def get_audit(limit: int = 100):
    with _lock:
        ok, msg = copilot.audit.verify()
        return {
            "verified": ok,
            "message": msg,
            "entries": copilot.audit.entries[-min(max(1, limit), 500):],
        }


@app.get("/evaluate")
def evaluate_endpoint():
    return run_evaluation()


@app.post("/reset")
def reset_demo():
    global copilot
    with _lock:
        copilot = seed_demo_copilot(copilot)
    return {"ok": True, "incidents": len(copilot.incidents)}
