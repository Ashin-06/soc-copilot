import pytest

from soccopilot.audit import AuditLog
from soccopilot.playbooks import PlaybookEngine
from soccopilot.store import StateStore


def test_targets_are_validated_before_anything_is_queued():
    pb = PlaybookEngine(audit=AuditLog(), allowed_actions=["block_ip", "freeze_account"])
    for action, target in [("block_ip", "10.0.0.5"), ("block_ip", "192.168.1.1"), ("block_ip", "not-an-ip"),
                           ("freeze_account", ""), ("freeze_account", "x" * 200), ("disable_cloud_key", "AKIA1"),
                           ("delete_database", "prod")]:
        with pytest.raises(ValueError):
            pb.propose("INC-1", action, target, "r")
    assert pb.items == {}
    assert pb.propose("INC-1", "block_ip", "185.220.101.42", "r").status == "pending"


def test_four_eyes_for_actions_raised_by_hand():
    pb = PlaybookEngine(audit=AuditLog())
    act = pb.propose("INC-1", "end_sessions", "CUST-1042", "manual", proposed_by="meera")
    with pytest.raises(PermissionError):
        pb.decide(act.action_id, approve=True, analyst="meera")
    assert pb.decide_and_run(act.action_id, approve=True, analyst="ravi").status == "executed"


def test_approvals_survive_a_restart_and_expiry_is_recorded(tmp_path):
    store = StateStore(tmp_path / "s.db")
    pb = PlaybookEngine(audit=AuditLog(), state_store=store, ttl=0.0)
    act = pb.propose("INC-1", "freeze_account", "50100984512011", "r")

    reloaded = PlaybookEngine(audit=AuditLog(), state_store=store, ttl=0.0)
    assert reloaded.items[act.action_id].target == "50100984512011"
    with pytest.raises(ValueError, match="expired"):
        reloaded.decide(act.action_id, approve=True, analyst="ravi")
    assert store.list_approvals()[0]["status"] == "expired"
