from soccopilot.correlate import Correlator
from soccopilot.detect import Alert
from soccopilot.evaluate import BASE_TS
from soccopilot.pipeline import SOCCopilot


def _bastion(i, action, minutes):
    return {"event_id": f"EVT-C{i}", "source_type": "wazuh", "timestamp": BASE_TS + minutes * 60,
            "rule": {"id": "5402", "description": "privileged action on bastion"},
            "agent": {"name": "prod-bastion-01"}, "data": {"action": action, "dstuser": "ops.temp"}}


def test_incident_keeps_its_id_status_and_feedback_as_it_grows():
    cp = SOCCopilot()
    cp.process_raw_events([_bastion(1, "sudo_priv_esc", 0)])
    (inc_id, inc), = cp.incidents.items()
    inc.status = "triaged"
    inc.feedback.append({"verdict": "true_positive"})

    cp.process_raw_events([_bastion(2, "unauthorized_key_added", 20)])  # same user, joins the case
    assert list(cp.incidents) == [inc_id]
    grown = cp.incidents[inc_id]
    assert len(grown.alert_ids) == 2 and grown.status == "triaged" and grown.feedback
    assert [d["incident_id"] for d in cp.state_store.list_incidents()] == [inc_id]


def test_new_alerts_reopen_a_false_positive():
    cp = SOCCopilot()
    cp.process_raw_events([_bastion(1, "sudo_priv_esc", 0)])
    (inc,) = cp.incidents.values()
    inc.status = "false_positive"
    cp.process_raw_events([_bastion(2, "ssh_lateral_exec", 10)])
    assert cp.incidents[inc.incident_id].status == "open"


def test_state_survives_a_restart(tmp_path):
    paths = dict(duckdb_path=tmp_path / "e.duckdb", sqlite_path=tmp_path / "s.db", audit_path=tmp_path / "a.jsonl")
    cp = SOCCopilot(**paths)
    cp.process_raw_events([_bastion(1, "sudo_priv_esc", 0)])
    (inc,) = cp.incidents.values()
    inc.status = "contained"
    cp.state_store.save_incident(inc)
    cp.event_store.conn.close()
    cp.state_store.db.dispose()

    again = SOCCopilot(**paths)
    assert list(again.incidents) == [inc.incident_id] and again.incidents[inc.incident_id].status == "contained"
    # replayed events are known to the deduper, so re-sending them is not double counted
    assert again.process_raw_events([_bastion(1, "sudo_priv_esc", 0)])["duplicates"] == 1


def test_feedback_cannot_silence_high_severity_rules():
    c = Correlator()
    alert = dict(timestamp=BASE_TS, tactics=["impact"], techniques=["T1657"], event_ids=["EVT-1"], entities=["user:x"])
    c.rule_weights["R-HIGH"] = c.rule_weights["R-LOW"] = 0.1
    assert not c.is_suppressed(Alert(alert_id="A1", rule_id="R-HIGH", title="t", severity="critical", domain="fraud", **alert))
    assert c.is_suppressed(Alert(alert_id="A2", rule_id="R-LOW", title="t", severity="low", domain="security", **alert))


def test_auto_triage_only_reruns_cases_that_changed():
    cp = SOCCopilot()
    cp.process_raw_events([_bastion(1, "sudo_priv_esc", 0)], auto_triage=True)
    quiet = {**_bastion(9, "sudo_priv_esc", 600), "data": {"action": "sudo_priv_esc", "dstuser": "other.user"}}
    cp.process_raw_events([quiet], auto_triage=True)  # a second, unrelated case
    triaged = [e["incident_id"] for e in cp.audit.entries if e["event"] == "incident_triaged"]
    assert len(triaged) == 2 and len(set(triaged)) == 2
