"""Settings, auth, limits, headers, metrics, health, persistence and migrations."""
import base64
import hashlib
import importlib
import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from soccopilot import db, ops
from soccopilot.store import StateStore

A32 = base64.b64encode(b"a" * 32).decode()
KEY = "soccopilot_" + "x" * 40
HASHED = {f"sha256:{hashlib.sha256(KEY.encode()).hexdigest()}": {"user": "meera", "role": "analyst"}}


def prod_env(**over):
    env = {"SOCCOPILOT_ENV": "production", "SOCCOPILOT_API_KEYS": json.dumps(HASHED), "SOCCOPILOT_AUDIT_KEY": A32,
           "SOCCOPILOT_DATA_DIR": "/data"}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


@pytest.fixture()
def boot(monkeypatch):
    import soccopilot.api as api

    def start(**env):
        for k in [k for k in os.environ if k.startswith("SOCCOPILOT_")]:
            monkeypatch.delenv(k)
        for k, v in env.items():
            monkeypatch.setenv(f"SOCCOPILOT_{k}", v)
        return importlib.reload(api)

    yield start
    for k in [k for k in os.environ if k.startswith("SOCCOPILOT_")]:
        monkeypatch.delenv(k)
    importlib.reload(api)  # back to the in-memory demo for the other test modules


def test_production_settings_accepted():
    s = ops.load_settings(prod_env())
    assert s.production and not s.demo and s.data_dir == "/data" and s.database_url == "sqlite:////data/state.db"
    assert ops.load_settings(prod_env(SOCCOPILOT_DATABASE_URL="postgresql://u:p@db/soc")).database_url.startswith("postgresql")


@pytest.mark.parametrize("change, message", [
    ({"SOCCOPILOT_API_KEYS": None}, "API keys"),
    ({"SOCCOPILOT_AUDIT_KEY": None}, "AUDIT_KEY"),
    ({"SOCCOPILOT_DATA_DIR": None}, "DATA_DIR"),
    ({"SOCCOPILOT_API_KEYS": json.dumps({KEY: {"user": "meera", "role": "analyst"}})}, "sha256"),
    ({"SOCCOPILOT_API_KEYS": json.dumps({"sha256:" + "0" * 64: {"user": "x", "role": "root"}})}, "roles"),
    ({"SOCCOPILOT_AUDIT_KEY": base64.b64encode(b"short").decode()}, "at least 32"),
    ({"SOCCOPILOT_CORS_ORIGINS": "*"}, "CORS"),
    ({"SOCCOPILOT_ENV": "prod"}, "development or production"),
    ({"SOCCOPILOT_DATABASE_URL": "mysql://x"}, "postgresql"),
])
def test_production_refuses_to_start(change, message):
    with pytest.raises(ops.ConfigError, match=message):
        ops.load_settings(prod_env(**change))


def test_a_data_dir_needs_a_fixed_audit_key():
    with pytest.raises(ops.ConfigError, match="AUDIT_KEY"):
        ops.load_settings({"SOCCOPILOT_DATA_DIR": "/tmp/soc"})
    demo = ops.load_settings({})
    assert demo.demo and not demo.data_dir and demo.database_url == "sqlite://"


def test_no_public_bind_without_keys():
    with pytest.raises(ops.ConfigError, match="without API keys"):
        ops.load_settings({"SOCCOPILOT_HOST": "0.0.0.0"})
    assert ops.load_settings({"SOCCOPILOT_HOST": "0.0.0.0", "SOCCOPILOT_API_KEYS": json.dumps(HASHED)}).host == "0.0.0.0"


def test_serve_exits_with_a_readable_error():
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOCCOPILOT_")}
    r = subprocess.run([sys.executable, "-m", "soccopilot", "serve", "--host", "0.0.0.0"], env=env,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode != 0 and "without API keys" in r.stderr


def test_metrics_need_the_monitor_role(boot):
    keys = {"k-view": {"user": "vera", "role": "viewer"}, "k-mon": {"user": "prom", "role": "monitor"}}
    c = TestClient(boot(API_KEYS=json.dumps(keys)).app)
    assert c.get("/incidents", headers={"x-api-key": "k-mon"}).status_code == 403
    assert c.get("/metrics", headers={"x-api-key": "k-view"}).status_code == 403
    assert c.get("/incidents", headers={"x-api-key": "k-view"}).status_code == 200
    m = c.get("/metrics", headers={"x-api-key": "k-mon"})
    assert m.status_code == 200 and 'http_requests_total{method="GET",route="/incidents",status="200"}' in m.text
    assert "http_request_duration_seconds_bucket" in m.text and "errors_total" in m.text


def test_rate_limit(boot):
    c = TestClient(boot(RATE_LIMIT="3").app)
    codes = [c.get("/incidents").status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]
    assert int(c.get("/incidents").headers["retry-after"]) >= 1
    assert c.get("/healthz").status_code == 200  # probes are never limited


def test_body_size_cap(boot):
    c = TestClient(boot(MAX_BODY_BYTES="1000").app)
    assert c.post("/ingest", json={"events": [{"message": "a" * 2000}]}).status_code == 413

    def chunks():  # no content-length: the cap still holds
        for _ in range(20):
            yield b"a" * 100

    assert c.post("/ingest", content=chunks(), headers={"content-type": "application/json"}).status_code == 413


def test_headers_and_request_ids(boot):
    c = TestClient(boot().app)
    r = c.get("/incidents", headers={"x-request-id": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123"
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-security-policy"] == ops.API_CSP and r.headers["cache-control"] == "no-store"
    assert "unsafe-inline" in c.get("/").headers["content-security-policy"]
    assert len(c.get("/healthz", headers={"x-request-id": "bad id\n"}).headers["x-request-id"]) == 32
    assert "access-control-allow-origin" not in c.get("/healthz", headers={"origin": "https://evil.example"}).headers


def test_errors_do_not_leak(boot):
    api = boot()

    @api.app.get("/boom")
    def boom():
        raise RuntimeError("secret detail: account 50100234567812")

    c = TestClient(api.app)
    r = c.get("/boom")
    assert r.status_code == 500 and "50100" not in r.text and r.json()["request_id"] == r.headers["x-request-id"]
    bad = c.post("/actions", json={"incident_id": ["50100234567812"], "action_type": "x", "target": "y", "rationale": "zz"})
    assert bad.status_code == 422 and "50100" not in bad.text


def test_health_and_readiness(boot, monkeypatch):
    api = boot()
    c = TestClient(api.app)
    assert c.get("/healthz").json() == {"status": "ok"}
    r = c.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"] == {"database": True, "event_store": True}
    monkeypatch.setattr(api.copilot.state_store, "rule_weights", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    r = c.get("/readyz")
    assert r.status_code == 503 and r.json()["checks"]["database"] is False and "db down" not in r.text


def test_data_dir_keeps_cases_events_and_audit(boot, tmp_path):
    api = boot(DATA_DIR=str(tmp_path), AUDIT_KEY=A32)
    c = TestClient(api.app)
    assert c.get("/health").json()["storage"] == "disk" and c.get("/incidents").json()["count"] == 0  # nothing seeded
    assert c.post("/reset").status_code == 409
    login = {"event_id": "EVT-P1", "source_type": "auth", "ts": 1_790_000_000, "action": "login_success",
             "user": "dev.kulkarni", "ip": "49.36.1.1", "message": "login"}
    assert c.post("/ingest", json={"events": [login]}).status_code == 200
    assert {"events.duckdb", "state.db", "audit.jsonl"} <= {p.name for p in tmp_path.iterdir()}
    api.copilot.event_store.conn.close()
    api.copilot.state_store.db.dispose()

    again = TestClient(boot(DATA_DIR=str(tmp_path), AUDIT_KEY=A32).app)  # a restart
    assert again.get("/health").json()["events_stored"] == 1
    assert again.get("/audit").json()["verified"]


def test_json_logs_carry_request_ids(capsys):
    ops.setup_logging("INFO")
    token = ops.request_id.set("rid-1")
    ops.log.info("hello", extra={"fields": {"n": 1}})
    ops.request_id.reset(token)
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["msg"] == "hello" and line["request_id"] == "rid-1" and line["n"] == 1 and line["level"] == "INFO"


def test_state_store_survives_a_restart(tmp_path):
    url = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'state.db'}"
    StateStore(url).save_feedback("INC-P1", "true_positive", "confirmed", "meera", 1.0,
                                  {"updated_rule_weights": {"R-TEST-P": 0.8}})
    StateStore(url).save_feedback("INC-P1", "true_positive", "again", "meera", 2.0,
                                  {"updated_rule_weights": {"R-TEST-P": 0.9}})  # upsert, not a duplicate key
    again = StateStore(url)
    assert again.rule_weights()["R-TEST-P"] == 0.9
    again.save_approval("ACT-P1", "INC-P1", "pending", 1.0, {"action_id": "ACT-P1", "status": "pending"})
    again.save_approval("ACT-P1", "INC-P1", "executed", 1.0, {"action_id": "ACT-P1", "status": "executed"})
    assert [a["status"] for a in StateStore(url).list_approvals("INC-P1")] == ["executed"]


def test_migrations_apply_once(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    eng = db.engine(url)
    assert db.migrate(eng) == ["001_init.sql"]
    assert db.migrate(eng) == []
    with eng.connect() as c:
        assert [r[0] for r in c.execute(text("SELECT version FROM schema_migrations"))] == [1]
        tables = {r[0] for r in c.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'"))}
    assert {"incidents", "reports", "approvals", "feedback", "rule_weights"} <= tables
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("SOCCOPILOT_")}, "SOCCOPILOT_DATABASE_URL": url}
    out = subprocess.run([sys.executable, "-m", "soccopilot", "migrate"], env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0 and "up to date" in out.stdout


def test_a_state_db_from_before_migrations_upgrades_in_place(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript("""
        CREATE TABLE rule_weights (rule_id TEXT PRIMARY KEY, weight REAL);
        CREATE TABLE feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, verdict TEXT, reason TEXT,
                               analyst TEXT, created_at REAL, payload_json TEXT);
        INSERT INTO rule_weights VALUES ('R-OLD', 0.5);
    """)
    old.close()
    s = StateStore(path)
    s.save_feedback("INC-1", "false_positive", "noise", "ravi", 1.0, {})
    assert s.rule_weights() == {"R-OLD": 0.5}
