"""Tamper-evident hash-chained audit log (shared pattern with projects 04 and 10).

Every ingestion batch, alert correlation, privacy-scrubbed AI triage run, analyst
approval/rejection, playbook execution, and feedback event is recorded in an
append-only hash chain (optionally HMAC-SHA256 keyed). Editing, deleting, or
reordering any entry breaks verification.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from pathlib import Path


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path: str | Path | None = None, key: bytes | str | None = None, previous_keys: tuple[bytes, ...] = ()):
        self.path = Path(path) if path else None
        self.key = key.encode("utf-8") if isinstance(key, str) else key  # the service passes SOCCOPILOT_AUDIT_KEY
        self.previous_keys = tuple(previous_keys)  # entries signed before a key rotation still verify
        self._lock = threading.Lock()
        self.entries, problem = self._read()
        if problem:
            # fail closed: appending after a damaged line would hide where the damage is
            raise ValueError(f"audit log {self.path} is damaged ({problem}); investigate before restarting")

    def _read(self) -> tuple[list[dict], str]:
        if not (self.path and self.path.exists()):
            return [], ""
        entries: list[dict] = []
        for i, line in enumerate(self.path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                return entries, f"line {i + 1} is not valid JSON"
        return entries, ""

    def _digest(self, body: dict, key: bytes | None = None) -> str:
        data = _canon(body)
        key = key or self.key
        if key:
            return hmac.new(key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    RESERVED = ("seq", "ts", "event", "prev", "hash")

    def append(self, event: str, **fields) -> dict:
        clash = [k for k in fields if k in self.RESERVED]
        if clash:
            raise ValueError(f"audit fields {clash} would overwrite the chain's own keys")
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else self.GENESIS
            body = {
                "seq": len(self.entries),
                "ts": round(time.time(), 4),
                "event": event,
                "prev": prev,
                **fields,
            }
            entry = {**body, "hash": self._digest(body)}
            self.entries.append(entry)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            return entry

    def verify(self) -> tuple[bool, str]:
        entries = list(self.entries)
        if self.path:
            entries, problem = self._read()
            if problem:
                return False, problem
            if len(entries) < len(self.entries):
                return False, f"{len(self.entries) - len(entries)} entries missing from the end of the file"
        prev = self.GENESIS
        for i, e in enumerate(entries):
            body = {k: v for k, v in e.items() if k != "hash"}
            if e.get("seq") != i:
                return False, f"entry {i}: sequence number {e.get('seq')} out of order"
            if e.get("prev") != prev:
                return False, f"entry {i}: chain broken (previous hash mismatch)"
            canon = json.loads(_canon(body))
            if not any(hmac.compare_digest(self._digest(canon, k), str(e.get("hash", ""))) for k in (self.key, *self.previous_keys)):
                return False, f"entry {i}: contents were modified"
            prev = e["hash"]
        return True, f"{len(entries)} entries, chain intact"
