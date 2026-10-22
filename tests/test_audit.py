import json

import pytest

from soccopilot.audit import AuditLog


def test_fields_cannot_overwrite_chain_keys():
    log = AuditLog()
    with pytest.raises(ValueError):
        log.append("x", prev="0" * 64)
    with pytest.raises(ValueError):
        log.append("x", hash="forged")


def test_damaged_or_truncated_logs_are_reported(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p, key=b"k")
    for i in range(3):
        log.append("step", n=i)

    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")  # last entry cut off
    ok, msg = log.verify()
    assert not ok and "missing" in msg

    p.write_text("\n".join(lines[:1] + ["{not json"] + lines[2:]) + "\n", encoding="utf-8")
    ok, msg = log.verify()
    assert not ok and "line 2" in msg
    with pytest.raises(ValueError, match="damaged"):
        AuditLog(p, key=b"k")

    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    entry = json.loads(lines[0])
    assert AuditLog(p, key=b"k").verify() == (True, "3 entries, chain intact") and entry["seq"] == 0
