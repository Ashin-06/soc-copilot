from soccopilot.evaluate import BASE_TS
from soccopilot.ingest import IngestService
from soccopilot.normalize import normalize_envelope
from soccopilot.pipeline import SOCCopilot


def _norm(raw, source=None):
    env, status = IngestService().ingest_event(raw, source=source)
    assert status == "accepted", status
    return normalize_envelope(env)


def test_malformed_fields_are_coerced_not_fatal():
    ev = _norm({"timestamp": BASE_TS, "rule": {"id": "5402"}, "agent": "not-an-object", "data": ["x"],
                "bytes_out": "lots", "user": {"name": "nested"}}, source="wazuh")
    assert ev.bytes_out == 0 and ev.user is None and ev.event_action == "5402"

    ecs = _norm({"@timestamp": BASE_TS, "event": {"category": ["authentication", "iam"], "action": "logon"},
                 "user": {"name": "dev.kulkarni"}, "amount": float("nan")})
    assert ecs.event_category == "authentication" and ecs.amount == 0.0


def test_event_ids_are_safe_and_never_overwrite_evidence():
    cp = SOCCopilot()
    first = {"event_id": "EVT-7", "source_type": "auth", "ts": BASE_TS, "action": "login_success", "user": "dev.kulkarni"}
    cp.process_raw_events([first])
    # a different event reusing the same source ID keeps the original intact
    cp.process_raw_events([{**first, "ts": BASE_TS + 60, "user": "rohit.verma"}])
    assert cp.event_store.get("EVT-7").user == "dev.kulkarni"
    clash = [e for e in cp.event_store.all_events() if e.event_id.startswith("EVT-7-")]
    assert len(clash) == 1 and clash[0].user == "rohit.verma" and clash[0].details["source_event_id"] == "EVT-7"

    # IDs that are not in the citable EVT- shape are replaced, and the original is kept for reference
    cp.process_raw_events([{**first, "event_id": "<img src=x>", "ts": BASE_TS + 120}])
    odd = [e for e in cp.event_store.all_events() if e.details.get("source_event_id") == "<img src=x>"]
    assert len(odd) == 1 and odd[0].event_id.startswith("EVT-") and "<" not in odd[0].event_id
