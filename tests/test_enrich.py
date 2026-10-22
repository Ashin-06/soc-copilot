import json

from soccopilot.enrich import Enricher
from soccopilot.evaluate import BASE_TS
from soccopilot.ingest import IngestService
from soccopilot.normalize import normalize_envelope


def _login(enricher, ts, ip, customer="CUST-1042"):
    env, _ = IngestService().ingest_event(
        {"source_type": "auth", "ts": ts, "action": "login_success", "outcome": "success", "customer_id": customer, "ip": ip}
    )
    return enricher.enrich(normalize_envelope(env))


def test_unknown_locations_are_not_invented():
    enr = Enricher()
    assert enr.lookup_ip_geo("8.8.4.4") == {"country": "UNKNOWN", "city": "Unknown"}
    assert enr.lookup_ip_geo("192.168.4.20")["country"] == "INTERNAL"
    assert enr.lookup_ip_geo("not-an-ip")["country"] == "UNKNOWN"
    # an address we cannot place never produces an impossible-travel verdict
    _login(enr, BASE_TS, "49.36.10.10")
    ev = _login(enr, BASE_TS + 300, "8.8.4.4")
    assert ev.enrichment["impossible_travel"] is False


def test_customer_identifiers_stay_out_of_event_enrichment():
    ev = _login(Enricher(), BASE_TS, "49.36.10.10")
    assert ev.enrichment["customer_account"] == "50100984512011"
    assert not {"customer_pan", "customer_phone", "customer_email"} & ev.enrichment.keys()


def test_context_file_replaces_demo_directories(tmp_path):
    ctx = tmp_path / "context.json"
    ctx.write_text(json.dumps({
        "assets": {"ledger-01": {"criticality": 5, "criticality_label": "critical", "environment": "prod",
                                 "owner_team": "Core", "service": "ledger"}},
        "customers": {"C-9": {"full_name": "Test Customer", "account": "12345678901", "account_age_days": 10,
                              "avg_transfer_amount": 1000.0, "known_devices": ["D1"]}},
        "threat_intel_ips": {"203.0.113.9": {"score": 0.9, "category": "test", "feeds": ["internal"], "country": "ZZ", "asn": "AS0"}},
    }))
    enr = Enricher(context_path=ctx)
    assert set(enr.assets) == {"ledger-01"} and set(enr.customers) == {"C-9"}
    assert enr.lookup_ip_reputation("203.0.113.9")["malicious"] is True
    assert enr.lookup_ip_reputation("185.220.101.42")["malicious"] is False  # demo feed replaced
    ev = _login(enr, BASE_TS, "49.36.10.10", customer="C-9")
    assert "account:12345678901" in ev.entities
