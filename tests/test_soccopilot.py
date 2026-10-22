from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from soccopilot.audit import AuditLog
from soccopilot.evaluate import BASE_TS, SOCCopilot, build_labelled_campaigns, run_evaluation
from soccopilot.ingest import IngestService
from soccopilot.normalize import normalize_envelope
from soccopilot.playbooks import PlaybookEngine


def test_ingest_validation_deduplication_and_health_monitor(tmp_path):
    svc = IngestService(max_event_bytes=512, silence_thresholds={"auth": 300.0, "payments": 300.0})
    ev = {"source_type": "auth", "ts": BASE_TS, "action": "login_success", "user": "vikram.rao", "ip": "49.36.1.1"}
    env1, st1 = svc.ingest_event(ev)
    assert st1 == "accepted" and env1 is not None

    # Duplicate event hash is caught
    env2, st2 = svc.ingest_event(ev)
    assert st2 == "duplicate" and env2 is None

    # Oversized payload is rejected
    huge = {"source_type": "auth", "ts": BASE_TS, "action": "login_failed", "blob": "X" * 1000}
    env3, st3 = svc.ingest_event(huge)
    assert env3 is None and "exceeds limit" in st3

    # Missing required field is rejected
    bad = {"source_type": "cloudtrail", "eventTime": BASE_TS}
    env4, st4 = svc.ingest_event(bad)
    assert env4 is None and "missing required field" in st4

    # File drop & Kafka record ingestion
    f = tmp_path / "drop.jsonl"
    f.write_text(
        json.dumps({"source_type": "payments", "ts": BASE_TS + 10, "action": "upi_transfer", "amount": 500, "account": "50100984512011"}) + "\n",
        encoding="utf-8",
    )
    f_res = svc.ingest_file(f)
    assert len(f_res.accepted) == 1

    k_res = svc.ingest_kafka_records([
        {"topic": "soc.api", "value": json.dumps({"ts": BASE_TS + 20, "path": "/api/v1/health", "status_code": 200}).encode()}
    ])
    assert len(k_res.accepted) == 1

    # Health monitor alerts when 'auth' goes silent for > 300s
    quiet = svc.health.quiet_sources(reference_ts=BASE_TS + 450)
    quiet_names = {q.source for q in quiet}
    assert "auth" in quiet_names


def test_normalise_and_enrich_extracts_entities_and_context():
    cp = SOCCopilot()
    env1, _ = cp.ingest_service.ingest_event({
        "event_id": "EVT-T1",
        "source_type": "auth",
        "ts": BASE_TS,
        "action": "login_success",
        "outcome": "success",
        "customer_id": "CUST-1042",
        "ip": "49.36.10.10",
        "device_id": "DEV-KAVITA-01",
    })
    ev1 = cp.enricher.enrich(normalize_envelope(env1))
    assert "customer:CUST-1042" in ev1.entities
    assert "account:50100984512011" in ev1.entities
    assert ev1.enrichment["geo_country"] == "IN"

    # 10 minutes later, login from Tor exit node in NL -> impossible travel + high threat intel score
    env2, _ = cp.ingest_service.ingest_event({
        "event_id": "EVT-T2",
        "source_type": "auth",
        "ts": BASE_TS + 600,
        "action": "login_success",
        "outcome": "success",
        "customer_id": "CUST-1042",
        "ip": "185.220.101.42",
        "device_id": "DEV-NEW-9",
    })
    ev2 = cp.enricher.enrich(normalize_envelope(env2))
    assert ev2.enrichment["impossible_travel"] is True
    assert ev2.enrichment["ip_reputation_score"] >= 0.9
    assert ev2.enrichment["unrecognized_device"] is True


def test_sigma_window_aggregation_and_security_fraud_correlation():
    cp = SOCCopilot()
    camp1 = build_labelled_campaigns()[0]
    res = cp.process_raw_events(camp1.events)
    assert res["accepted"] == len(camp1.events)
    assert res["incidents"] == 1

    inc = list(cp.incidents.values())[0]
    assert inc.security_fraud_joined is True
    assert inc.money_at_risk == 185000.0
    assert inc.score_breakdown["security_fraud_bonus"] > 0
    # Verify storyline ordering: credential_access / initial_access appear before impact
    assert inc.tactics.index("impact") > 0


def test_triage_enforces_readonly_tools_and_privacy_gateway_masking():
    cp = SOCCopilot()
    camp1 = build_labelled_campaigns()[0]
    cp.process_raw_events(camp1.events)
    inc = list(cp.incidents.values())[0]

    # Guardrail 1: AI cannot call write/action tools
    with pytest.raises(PermissionError):
        cp.triage_engine.execute_read_tool("freeze_account", {"target": "50100984512011"})

    # Guardrail 2: Template fallback report cites 100% of claims and masks PII in prompt preview
    rep = cp.triage_engine.triage_incident(inc, use_llm=False)
    assert rep.citation_coverage == 1.0
    assert len(rep.cited_event_ids) >= 3
    assert "Mrs. Kavita Deshmukh" not in rep.sanitized_prompt_preview
    assert "ABCPD4412K" not in rep.sanitized_prompt_preview
    assert sum(rep.privacy_masked_counts.values()) > 0

    # Guardrail 3: Live Claude tool loop receives only sanitized tool outputs and restores tokens
    class _Block:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class _FakeClaudeMessages:
        def __init__(self):
            self.calls = 0

        def create(self, **kw):
            self.calls += 1
            if self.calls == 1:
                return _Block(
                    stop_reason="tool_use",
                    content=[_Block(type="tool_use", id="tu_1", name="customer_transactions", input={"customer_id": "CUST-1042"})],
                )
            tool_msg = kw["messages"][-1]["content"][0]["content"]
            # Customer account number must be tokenized, never raw, when sent to the model
            assert "50100984512011" not in tool_msg
            payload = {
                "summary": "Account takeover confirmed for [[ACCOUNT_1:2011]] [EVT-1008] [EVT-1010].",
                "timeline": ["Login from Tor exit node [EVT-1008] followed by wire transfer [EVT-1010]."],
                "attack_mapping": [{"tactic": "impact", "technique": "T1657", "evidence": "Wire drain [EVT-1010]."}],
                "likely_impact": ["₹1,85,000 wire transfer from [[ACCOUNT_1:2011]] [EVT-1010]."],
                "confidence": "high",
                "confidence_score": 0.96,
                "recommended_containment": [
                    {"action_type": "freeze_account", "target": "50100984512011", "rationale": "Freeze account [EVT-1010]."}
                ],
            }
            return _Block(stop_reason="end_turn", content=[_Block(type="text", text=json.dumps(payload))])

    fake_client = SimpleNamespace(messages=_FakeClaudeMessages())
    llm_rep = cp.triage_engine.triage_incident(inc, client=fake_client, use_llm=True)
    assert llm_rep.generated_by == "claude_tool_loop"
    assert llm_rep.citation_coverage == 1.0
    assert "50100984512011" in llm_rep.summary  # Restored for fraud_analyst role


def test_playbook_approval_is_bound_to_exact_call_and_single_use():
    audit = AuditLog()
    pb = PlaybookEngine(audit=audit)
    act = pb.propose("INC-0001", "freeze_account", "50100984512011", "Unauthorized transfer [EVT-1010]")
    assert act.status == "pending"
    assert "50100984512011" not in pb.connectors.frozen_accounts

    # Cannot execute before analyst approval
    with pytest.raises(PermissionError):
        pb.consume_and_execute(act.action_id)

    pb.decide(act.action_id, approve=True, analyst="analyst.meera")

    # Tampering with target after approval is refused by SHA-256 call digest check
    with pytest.raises(PermissionError):
        pb.consume_and_execute(act.action_id, target="50100000000000")

    # Exact approved target executes and updates connector state
    executed = pb.consume_and_execute(act.action_id)
    assert executed.status == "executed"
    assert "50100984512011" in pb.connectors.frozen_accounts

    # Single-use: cannot replay the same approval
    with pytest.raises(PermissionError):
        pb.consume_and_execute(act.action_id)


def test_audit_chain_detects_modification_and_deletion(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p, key=b"bank-soc-secret")
    for i in range(4):
        log.append("test_event", step=i)
    assert log.verify()[0] is True

    lines = p.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[2])
    tampered["step"] = 999
    lines[2] = json.dumps(tampered)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, msg = AuditLog(p, key=b"bank-soc-secret").verify()
    assert not ok and "entry 2" in msg


def test_benchmark_evaluates_recall_noise_speed_and_citations():
    res = run_evaluation(benign_count=180)
    assert res["detection_recall"] == 1.0
    assert res["campaigns_detected"] == 6
    assert res["security_fraud_join_rate"] == 1.0
    assert res["false_positive_incidents_per_day"] == 0
    assert res["report_citation_coverage"] == 1.0
    assert res["mean_time_to_first_alert_ms"] < 500.0


def test_fastapi_console_and_feedback_endpoints():
    from soccopilot.api import app

    c = TestClient(app)
    r_reset = c.post("/reset")
    assert r_reset.status_code == 200

    q = c.get("/incidents").json()
    assert q["count"] == 6
    inc_id = q["incidents"][0]["incident_id"]

    detail = c.get(f"/incidents/{inc_id}").json()
    assert detail["incident"]["incident_id"] == inc_id
    assert detail["report"]["citation_coverage"] == 1.0
    assert len(detail["actions"]) >= 1

    # Approve first proposed containment action via API
    act_id = detail["actions"][0]["action_id"]
    dec = c.post(f"/actions/{act_id}/decide", json={"approve": True, "analyst": "soc.lead"}).json()
    assert dec["status"] == "executed"

    # Submit analyst feedback to tune rule weights
    fb = c.post(
        f"/incidents/{inc_id}/feedback",
        json={"verdict": "true_positive", "reason": "Confirmed ATO wire drain", "analyst": "soc.lead"},
    ).json()
    assert fb["new_risk_score"] >= detail["incident"]["risk_score"]

    # Verify audit chain remains intact
    aud = c.get("/audit").json()
    assert aud["verified"] is True
