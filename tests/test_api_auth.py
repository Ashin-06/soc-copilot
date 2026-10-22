import importlib
import json

import pytest
from fastapi.testclient import TestClient

KEYS = {
    "k-view": {"user": "vera", "role": "viewer"},
    "k-ana": {"user": "meera", "role": "analyst"},
    "k-appr": {"user": "ravi", "role": "approver"},
    "k-admin": {"user": "root.admin", "role": "admin"},
}


@pytest.fixture()
def api(monkeypatch):
    monkeypatch.setenv("SOCCOPILOT_API_KEYS", json.dumps(KEYS))
    import soccopilot.api as mod

    importlib.reload(mod)
    yield mod
    monkeypatch.delenv("SOCCOPILOT_API_KEYS")
    importlib.reload(mod)


def _h(key):
    return {"x-api-key": key}


def test_keys_decide_identity_and_permissions(api):
    c = TestClient(api.app)
    assert c.get("/incidents").status_code == 401
    assert c.get("/incidents", headers=_h("wrong")).status_code == 401
    q = c.get("/incidents", headers=_h("k-view")).json()
    inc = q["incidents"][0]
    assert c.get("/health", headers=_h("k-view")).json()["auth"] == "api keys"

    fb = {"verdict": "true_positive", "reason": "confirmed", "analyst": "someone.else"}
    assert c.post(f"/incidents/{inc['incident_id']}/feedback", json=fb, headers=_h("k-view")).status_code == 403
    r = c.post(f"/incidents/{inc['incident_id']}/feedback", json=fb, headers=_h("k-ana"))
    assert r.status_code == 200 and r.json()["feedback"]["analyst"] == "meera"  # body name ignored

    assert c.post("/reset", headers=_h("k-ana")).status_code == 403
    assert c.get("/evaluate", headers=_h("k-appr")).status_code == 403
    assert c.post("/reset", headers=_h("k-admin")).status_code == 200


def test_manual_actions_need_a_target_in_the_case_and_a_second_person(api):
    c = TestClient(api.app)
    incs = c.get("/incidents", headers=_h("k-ana")).json()["incidents"]
    inc = next(i for i in incs if any(e.startswith("customer:") for e in i["entities"]))
    target = next(e.split(":", 1)[1] for e in inc["entities"] if e.startswith("customer:"))
    base = {"incident_id": inc["incident_id"], "action_type": "end_sessions", "rationale": "manual review"}

    bad = c.post("/actions", json={**base, "target": "CUST-NOT-IN-CASE"}, headers=_h("k-ana"))
    assert bad.status_code == 400 and "not an entity" in bad.json()["detail"]

    # the copilot already queued this exact call; an approver declines it so a manual one can be raised
    for a in c.get("/actions", params={"incident_id": inc["incident_id"]}, headers=_h("k-view")).json()["actions"]:
        if (a["action_type"], a["target"], a["status"]) == ("end_sessions", target, "pending"):
            assert c.post(f"/actions/{a['action_id']}/decide", json={"approve": False}, headers=_h("k-appr")).json()["status"] == "declined"
    act = c.post("/actions", json={**base, "target": target}, headers=_h("k-appr")).json()
    assert act["proposed_by"] == "ravi"
    own = c.post(f"/actions/{act['action_id']}/decide", json={"approve": True}, headers=_h("k-appr"))
    assert own.status_code == 403
    assert c.post(f"/actions/{act['action_id']}/decide", json={"approve": True}, headers=_h("k-ana")).status_code == 403
    ok = c.post(f"/actions/{act['action_id']}/decide", json={"approve": True}, headers=_h("k-admin")).json()
    assert ok["status"] == "executed" and ok["decided_by"] == "root.admin"
    detail = c.get(f"/incidents/{inc['incident_id']}", headers=_h("k-view")).json()
    assert detail["incident"]["status"] == "contained"
