"""FastAPI backend for the SOC Copilot Analyst Console and real-time webhook ingestion.

Endpoints (permission in brackets):
- GET  /                         Interactive Analyst Console (web/console.html)
- GET  /health                   Per-source heartbeat health monitor & storage stats  [read]
- POST /ingest                   Ingest raw event or batch (Wazuh, ECS, CloudTrail, Auth, API, Payments)  [ingest]
- GET  /incidents                Incident queue ordered by composite risk score  [read]
- GET  /incidents/{id}           Full incident detail (storyline timeline, entity graph, alerts, actions)  [read]
- GET  /incidents/{id}/report    Get or generate structured AI triage report (with [EVT-...] citations)  [read]
- POST /incidents/{id}/report    Run AI triage (Claude tool loop or template fallback)  [triage]
- POST /incidents/{id}/feedback  Record analyst TP/FP verdict and tune detection rule weights  [feedback]
- GET  /actions                  List pending/decided/executed playbook actions  [read]
- POST /actions                  Propose a containment playbook action (needs a second analyst to approve)  [propose]
- POST /actions/{id}/decide      Approve or decline a proposed action (verified against SHA-256 call digest)  [decide]
- GET  /audit                    Inspect and verify the hash-chained audit trail  [read]
- GET  /evaluate                 Labelled campaign benchmark (computed once, then cached)  [admin]
- POST /reset                    Reset and re-seed demo state (demo data only)  [admin]

Who is calling: set SOCCOPILOT_API_KEYS (JSON) or SOCCOPILOT_KEYS_FILE to
{"<key>": {"user": "meera", "role": "analyst"}, ...}. The key decides the user and role; any
"analyst" name in a request body is ignored. Without keys the API runs in demo mode: every
endpoint is open and the body's analyst name is trusted, which is only fit for a laptop.

Where state lives: with SOCCOPILOT_DATA_DIR set, events, cases and the audit log are kept on disk
there and nothing is seeded. Otherwise the server starts in memory with the demo campaigns loaded.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .evaluate import run_evaluation, seed_demo_copilot
from .ingest import IngestValidationError
from .pipeline import SOCCopilot
from .triage import check_recommendations

ROOT = Path(__file__).resolve().parent.parent
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "ingest": {"ingest"},                                   # log shippers
    "viewer": {"read"},
    "analyst": {"read", "ingest", "triage", "feedback", "propose"},
    "approver": {"read", "triage", "feedback", "propose", "decide"},
    "admin": {"read", "ingest", "triage", "feedback", "propose", "decide", "admin"},
}


def _load_keys() -> dict[str, dict[str, str]]:
    """Gateway keys, held only as SHA-256 hashes."""
    raw = os.environ.get("SOCCOPILOT_API_KEYS")
    path = os.environ.get("SOCCOPILOT_KEYS_FILE")
    if path:
        raw = Path(path).read_text(encoding="utf-8")
    if not raw:
        return {}
    keys = {}
    for key, ident in json.loads(raw).items():
        if ident.get("role") not in ROLE_PERMISSIONS or not ident.get("user"):
            raise ValueError(f"key for {ident.get('user')!r} needs a user and one of the roles {sorted(ROLE_PERMISSIONS)}")
        keys[hashlib.sha256(key.encode()).hexdigest()] = {"user": str(ident["user"]), "role": ident["role"]}
    return keys


API_KEYS = _load_keys()
DATA_DIR = os.environ.get("SOCCOPILOT_DATA_DIR")

app = FastAPI(title="SOC Copilot for a Digital Bank", version="1.1.0")
_lock = threading.Lock()


def _start() -> SOCCopilot:
    if DATA_DIR:
        d = Path(DATA_DIR)
        d.mkdir(parents=True, exist_ok=True)
        return SOCCopilot(duckdb_path=d / "events.duckdb", sqlite_path=d / "state.db", audit_path=d / "audit.jsonl")
    return seed_demo_copilot()


copilot: SOCCopilot = _start()


def require(permission: str):
    def check(request: Request) -> dict[str, str]:
        if not API_KEYS:
            return {"user": "", "role": "demo"}
        key = request.headers.get("x-api-key") or request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        digest = hashlib.sha256(key.encode()).hexdigest() if key else ""
        ident = next((v for k, v in API_KEYS.items() if hmac.compare_digest(k, digest)), None)
        if ident is None:
            raise HTTPException(401, "missing or unknown API key")
        if permission not in ROLE_PERMISSIONS[ident["role"]]:
            raise HTTPException(403, f"role {ident['role']!r} cannot {permission}")
        return ident

    return check


def _who(ident: dict[str, str], claimed: str | None) -> str:
    """The acting analyst: the key's user, or in demo mode whatever name the console sent."""
    return ident["user"] or (claimed or "demo.analyst")


def _incident(incident_id: str):
    inc = copilot.incidents.get(incident_id)
    if not inc:
        raise HTTPException(404, f"incident {incident_id} not found")
    return inc


class IngestRequest(BaseModel):
    events: list[dict[str, Any]] | dict[str, Any]
    source: str | None = Field(default=None, max_length=32)
    auto_triage: bool = True


class TriageRequest(BaseModel):
    use_llm: bool = False


class FeedbackRequest(BaseModel):
    verdict: str = Field(..., pattern="^(true_positive|false_positive)$")
    reason: str = Field(..., min_length=2, max_length=500)
    analyst: str | None = Field(default=None, max_length=64)


class ActionProposalRequest(BaseModel):
    incident_id: str = Field(..., max_length=64)
    action_type: str = Field(..., max_length=64)
    target: str = Field(..., min_length=1, max_length=128)
    rationale: str = Field(..., min_length=2, max_length=1000)
    analyst: str | None = Field(default=None, max_length=64)


class ActionDecisionRequest(BaseModel):
    approve: bool
    analyst: str | None = Field(default=None, max_length=64)


@app.get("/")
def console_ui():
    return FileResponse(ROOT / "web" / "console.html")


@app.get("/health")
def health_status(ident: dict = Depends(require("read"))):
    with _lock:
        src_health = copilot.ingest_service.health.check_health()
        quiet = [a.__dict__ for a in copilot.ingest_service.health.quiet_sources()]
        ok_chain, chain_msg = copilot.audit.verify()
        return {
            "status": "degraded" if quiet or not ok_chain else "healthy",
            "auth": "api keys" if API_KEYS else "demo (no keys configured)",
            "storage": "disk" if DATA_DIR else "memory (demo)",
            "privacy": copilot.triage_engine.privacy.mode,
            "events_stored": copilot.event_store.count(),
            "active_alerts": len(copilot.alerts),
            "active_incidents": len(copilot.incidents),
            "audit_verified": ok_chain,
            "audit_message": chain_msg,
            "quiet_sources": quiet,
            "sources": src_health,
        }


@app.post("/ingest")
def ingest_webhook(body: IngestRequest, ident: dict = Depends(require("ingest"))):
    raw_list = body.events if isinstance(body.events, list) else [body.events]
    with _lock:
        try:
            return copilot.process_raw_events(
                raw_list,
                source=body.source,
                transport="webhook",
                auto_triage=body.auto_triage,
            )
        except IngestValidationError as e:
            raise HTTPException(400, str(e)) from e


@app.get("/incidents")
def list_incidents(ident: dict = Depends(require("read"))):
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


def _report(incident_id: str) -> dict[str, Any]:
    rep = copilot.state_store.get_report(incident_id)
    return rep if rep is not None else copilot.triage_engine.triage_incident(_incident(incident_id), use_llm=False).to_dict()


@app.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: str, ident: dict = Depends(require("read"))):
    with _lock:
        inc = _incident(incident_id)
        return {
            "incident": inc.to_dict(),
            "report": _report(incident_id),
            "actions": copilot.playbooks.list_actions(incident_id=incident_id),
        }


@app.get("/incidents/{incident_id}/report")
def get_incident_report(incident_id: str, ident: dict = Depends(require("read"))):
    with _lock:
        _incident(incident_id)
        return _report(incident_id)


@app.post("/incidents/{incident_id}/report")
def generate_incident_report(incident_id: str, body: TriageRequest | None = None, ident: dict = Depends(require("triage"))):
    with _lock:
        _incident(incident_id)
        return copilot.triage(incident_id, use_llm=bool(body and body.use_llm)).to_dict()


@app.post("/incidents/{incident_id}/feedback")
def submit_incident_feedback(incident_id: str, body: FeedbackRequest, ident: dict = Depends(require("feedback"))):
    with _lock:
        inc = _incident(incident_id)
        fb = copilot.record_feedback(incident_id, body.verdict, body.reason, _who(ident, body.analyst))
        return {
            "incident_id": incident_id,
            "status": inc.status,
            "new_risk_score": inc.risk_score,
            "feedback": fb,
        }


@app.get("/actions")
def list_actions(incident_id: str | None = None, ident: dict = Depends(require("read"))):
    with _lock:
        conn = copilot.playbooks.connectors
        return {
            "actions": copilot.playbooks.list_actions(incident_id=incident_id),
            "connector_state": {
                "blocked_ips": sorted(conn.blocked_ips),
                "frozen_accounts": sorted(conn.frozen_accounts),
                "revoked_sessions": sorted(conn.revoked_sessions),
                "password_resets": sorted(conn.password_resets),
                "disabled_cloud_keys": sorted(conn.disabled_cloud_keys),
                "notified_customers": conn.notified_customers,
            },
        }


@app.post("/actions")
def propose_action(body: ActionProposalRequest, ident: dict = Depends(require("propose"))):
    with _lock:
        inc = _incident(body.incident_id)
        rec = {"action_type": body.action_type, "target": body.target, "rationale": body.rationale}
        # the analyst's judgment stands in for threat intel on block_ip, but the target must still be in the case
        _, rejected = check_recommendations([rec], inc.to_dict(), copilot.playbooks.allowed_actions, is_malicious=lambda ip: True)
        if rejected:
            raise HTTPException(400, rejected[0]["reason"])
        try:
            act = copilot.playbooks.propose(
                inc.incident_id, body.action_type, body.target, body.rationale, proposed_by=_who(ident, body.analyst)
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return act.to_dict()


@app.post("/actions/{action_id}/decide")
def decide_action(action_id: str, body: ActionDecisionRequest, ident: dict = Depends(require("decide"))):
    with _lock:
        try:
            act = copilot.decide_action(action_id, approve=body.approve, analyst=_who(ident, body.analyst))
        except KeyError as e:
            raise HTTPException(404, str(e)) from e
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        except ValueError as e:
            raise HTTPException(409, str(e)) from e
        return act.to_dict()


@app.get("/audit")
def get_audit(limit: int = 100, ident: dict = Depends(require("read"))):
    with _lock:
        ok, msg = copilot.audit.verify()
        return {
            "verified": ok,
            "message": msg,
            "entries": copilot.audit.entries[-min(max(1, limit), 500):],
        }


@lru_cache(maxsize=1)
def _evaluation() -> dict[str, Any]:
    return run_evaluation()


@app.get("/evaluate")
def evaluate_endpoint(ident: dict = Depends(require("admin"))):
    return _evaluation()


@app.post("/reset")
def reset_demo(ident: dict = Depends(require("admin"))):
    global copilot
    if DATA_DIR:
        raise HTTPException(409, "reset only applies to the in-memory demo; this server keeps data on disk")
    with _lock:
        copilot = seed_demo_copilot(copilot)
        copilot.audit.append("demo_reset", by=ident["user"] or "demo")
    return {"ok": True, "incidents": len(copilot.incidents)}
