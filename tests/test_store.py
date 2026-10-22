from soccopilot.evaluate import BASE_TS
from soccopilot.pipeline import SOCCopilot
from soccopilot.store import EventStore


def _login(i, ip):
    return {"event_id": f"EVT-S{i}", "source_type": "auth", "ts": BASE_TS + i, "action": "login_success",
            "user": "dev.kulkarni", "ip": ip, "message": f"login {i} 100%_done"}


def test_entity_search_is_exact_and_query_is_literal():
    cp = SOCCopilot()
    cp.process_raw_events([_login(1, "10.0.0.1"), _login(2, "10.0.0.15"), _login(3, "10.0.0.2")])
    hits = cp.event_store.search_logs(entity="ip:10.0.0.1")
    assert [h["event_id"] for h in hits] == ["EVT-S1"]
    # % and _ are ordinary characters, not wildcards
    assert len(cp.event_store.search_logs(query="100%_done")) == 3
    assert cp.event_store.search_logs(query="1%0") == []


def test_events_survive_a_restart(tmp_path):
    db = tmp_path / "events.duckdb"
    cp = SOCCopilot(duckdb_path=db)
    cp.process_raw_events([_login(1, "49.36.1.1")])
    cp.event_store.conn.close()

    again = EventStore(db)
    ev = again.get("EVT-S1")
    assert ev is not None and ev.source_ip == "49.36.1.1" and "user:dev.kulkarni" in ev.entities
    assert ev.enrichment["geo_country"] == "IN"
