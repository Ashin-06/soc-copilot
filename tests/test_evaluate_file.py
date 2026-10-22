import json

from soccopilot.__main__ import main
from soccopilot.evaluate import BASE_TS, evaluate_labelled_file


def test_scoring_your_own_labelled_events(tmp_path, capsys):
    events = [
        {"event_id": "EVT-L1", "label": "bastion-case", "source_type": "wazuh", "timestamp": BASE_TS, "rule": {"id": "1"},
         "agent": {"name": "prod-bastion-01"}, "data": {"action": "sudo_priv_esc", "dstuser": "ops.temp"}},
        {"event_id": "EVT-L2", "label": "bastion-case", "source_type": "wazuh", "timestamp": BASE_TS + 300, "rule": {"id": "1"},
         "agent": {"name": "prod-bastion-01"}, "data": {"action": "unauthorized_key_added", "dstuser": "ops.temp"}},
        {"event_id": "EVT-L3", "source_type": "auth", "ts": BASE_TS + 60, "action": "login_success",
         "customer_id": "CUST-4090", "ip": "49.37.20.11"},
        {"event_id": "EVT-L4", "label": "missed-case", "source_type": "auth", "ts": BASE_TS + 90, "action": "login_success",
         "customer_id": "CUST-2088", "ip": "49.36.4.4"},
    ]
    f = tmp_path / "labelled.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    res = evaluate_labelled_file(f)
    by_id = {c["campaign_id"]: c for c in res["campaigns"]}
    assert by_id["bastion-case"]["detected"] and not by_id["missed-case"]["detected"]
    assert res["detection_recall"] == 0.5 and res["false_positive_incidents"] == 0

    main(["evaluate", "--labelled", str(f)])
    assert "Detection recall:     50%" in capsys.readouterr().out
