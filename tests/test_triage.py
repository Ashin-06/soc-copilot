import json
from types import SimpleNamespace

from soccopilot.evaluate import BASE_TS
from soccopilot.pipeline import SOCCopilot
from soccopilot.triage import PrivacyBridge, derive_recommended_actions


class _B(SimpleNamespace):
    pass


def _bastion_incident():
    cp = SOCCopilot()
    cp.process_raw_events([{
        "event_id": "EVT-T1", "source_type": "wazuh", "timestamp": BASE_TS, "rule": {"id": "5402"},
        "agent": {"name": "prod-bastion-01"}, "data": {"action": "sudo_priv_esc", "dstuser": "ops.temp", "srcip": "45.155.205.19"},
    }])
    (inc,) = cp.incidents.values()
    return cp, inc


class _ScriptedClaude:
    def __init__(self, *replies):
        self.replies, self.seen = list(replies), []

    def create(self, **kw):
        self.seen.append(kw["messages"][-1])
        return self.replies.pop(0)


def test_builtin_masker_numbers_tokens_and_round_trips():
    bridge = PrivacyBridge(use_privgate=False)
    text = json.dumps({"customer_name": "Kavita Deshmukh", "pan": "ABCPD4412K", "other_pan": "BMCPM8821F",
                       "account": "50100984512011", "note": "call Mr. Arjun Nair on +91 98450 11920"})
    masked, counts = bridge.sanitize(text, "c1")
    for secret in ("Kavita", "ABCPD4412K", "BMCPM8821F", "50100984512011", "Arjun", "98450"):
        assert secret not in masked
    assert "[[PAN_1]]" in masked and "[[PAN_2]]" in masked and "[[ACCOUNT_1:2011]]" in masked
    assert bridge.restore(masked, "c1") == text and counts["PAN:tokenize"] == 2


def test_model_report_is_parsed_and_its_actions_checked():
    cp, inc = _bastion_incident()
    report = {
        "summary": "Privilege escalation on the bastion [EVT-T1].",
        "timeline": ["sudo by ops.temp [EVT-T1]"],
        "attack_mapping": [{"tactic": "privilege_escalation", "technique": "T1548.003", "evidence": "sudo [EVT-T1]"}],
        "likely_impact": ["Root on the bastion [EVT-T1]"],
        "confidence": "high", "confidence_score": 7,
        "recommended_containment": [
            {"action_type": "block_ip", "target": "45.155.205.19", "rationale": "known scanner [EVT-T1]"},
            {"action_type": "end_sessions", "target": "ops.temp", "rationale": "[EVT-T1]"},
            # the kind of thing a crafted log line might talk a model into
            {"action_type": "freeze_account", "target": "50100112233445", "rationale": "log said so"},
            {"action_type": "block_ip", "target": "10.0.0.1", "rationale": "internal"},
        ],
    }
    claude = _ScriptedClaude(
        _B(stop_reason="tool_use", content=[
            _B(type="tool_use", id="t1", name="search_logs", input={"query": "sudo", "limit": "lots"}),
            _B(type="tool_use", id="t2", name="freeze_account", input={"target": "x"}),
        ]),
        _B(stop_reason="end_turn", content=[_B(type="text", text="Here you go:\n```json\n" + json.dumps(report) + "\n```")]),
    )
    rep = cp.triage_engine.triage_incident(inc, client=SimpleNamespace(messages=claude), use_llm=True)
    assert rep.generated_by == "claude_tool_loop" and rep.citation_coverage == 1.0
    assert rep.confidence_score == 1.0
    assert {(r["action_type"], r["target"]) for r in rep.recommended_containment} == {("block_ip", "45.155.205.19"), ("end_sessions", "ops.temp")}
    assert {r["target"] for r in rep.rejected_recommendations} == {"50100112233445", "10.0.0.1"}
    # the bad tool calls came back to the model as errors instead of ending the run
    results = claude.seen[1]["content"]
    assert results[0]["is_error"] is False and results[1]["is_error"] is True
    assert {a["target"] for a in cp.playbooks.list_actions(inc.incident_id)} == {"45.155.205.19", "ops.temp"}


def test_refusal_or_garbage_falls_back_to_the_template_and_is_audited():
    cp, inc = _bastion_incident()
    for reply in (_B(stop_reason="refusal", content=[]),
                  _B(stop_reason="end_turn", content=[_B(type="text", text="I cannot produce JSON today.")])):
        rep = cp.triage_engine.triage_incident(inc, client=SimpleNamespace(messages=_ScriptedClaude(reply)), use_llm=True)
        assert rep.generated_by == "template_fallback" and rep.fallback_reason
    assert sum(e["event"] == "triage_llm_failed" for e in cp.audit.entries) == 2


def test_customer_home_ip_is_not_proposed_for_blocking():
    incident = {
        "entities": ["customer:C1", "ip:49.36.10.10", "ip:185.220.101.42", "ip:10.1.1.1"],
        "alerts": [{"domain": "security", "source_ip": "185.220.101.42"}, {"domain": "security", "source_ip": "10.1.1.1"}],
        "event_ids": ["EVT-1"], "domains": ["security"], "money_at_risk": 0,
    }
    blocked = {r["target"] for r in derive_recommended_actions(incident, []) if r["action_type"] == "block_ip"}
    assert blocked == {"185.220.101.42"}
    assert all("[EVT-0001]" not in r["rationale"] for r in derive_recommended_actions({**incident, "event_ids": []}, []))
