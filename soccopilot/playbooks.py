"""Stage 7 Respond: Containment playbooks, call-hash-bound analyst approvals
(following the exact pattern of project 04), and connectors to firewall, identity,
core banking, and cloud IAM.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .audit import AuditLog
from .store import StateStore

APPROVAL_TTL_S = 3600.0

PLAYBOOK_SPECS: dict[str, dict[str, str]] = {
    "freeze_account": {
        "connector": "core_banking",
        "description": "Freeze outbound transfers on customer bank account",
    },
    "end_sessions": {
        "connector": "identity",
        "description": "Revoke all active web, mobile, and OAuth tokens for user/customer",
    },
    "block_ip": {
        "connector": "firewall",
        "description": "Block malicious source IP address at perimeter WAF and firewall",
    },
    "disable_cloud_key": {
        "connector": "cloud_iam",
        "description": "Deactivate compromised cloud IAM access key and active STS sessions",
    },
    "require_password_reset": {
        "connector": "identity",
        "description": "Force credential rotation and MFA re-enrollment on next login",
    },
    "notify_customer": {
        "connector": "core_banking",
        "description": "Send verified out-of-band fraud alert and confirmation prompt to customer",
    },
}


def action_hash(action_type: str, incident_id: str, target: str, params: dict[str, Any] | None = None) -> str:
    payload = {
        "action_type": action_type,
        "incident_id": incident_id,
        "target": target,
        "params": params or {},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass
class PendingAction:
    action_id: str
    incident_id: str
    action_type: str
    target: str
    rationale: str
    connector: str
    params: dict[str, Any]
    digest: str
    created_at: float = field(default_factory=time.time)
    status: str = "pending"          # pending | approved | declined | executed | expired | failed
    proposed_by: str = "copilot"     # "copilot" or the analyst who raised it by hand
    decided_by: str | None = None
    decided_at: float | None = None
    execution_result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ConnectorSuite:
    """Simulated enterprise connectors for firewall, identity, core banking, and cloud IAM."""

    def __init__(self):
        self.blocked_ips: set[str] = set()
        self.frozen_accounts: set[str] = set()
        self.revoked_sessions: set[str] = set()
        self.password_resets: set[str] = set()
        self.disabled_cloud_keys: set[str] = set()
        self.notified_customers: list[dict[str, Any]] = []

    def reset(self) -> None:
        self.blocked_ips.clear()
        self.frozen_accounts.clear()
        self.revoked_sessions.clear()
        self.password_resets.clear()
        self.disabled_cloud_keys.clear()
        self.notified_customers.clear()

    def execute(self, action_type: str, target: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        ts = round(time.time(), 3)
        if action_type == "block_ip":
            self.blocked_ips.add(target)
            return {"connector": "firewall", "action": "block_ip", "target": target, "rule": "WAF-DROP-INGRESS", "ts": ts}
        if action_type == "freeze_account":
            self.frozen_accounts.add(target)
            return {"connector": "core_banking", "action": "freeze_account", "target": target, "debit_hold": True, "ts": ts}
        if action_type == "end_sessions":
            self.revoked_sessions.add(target)
            return {"connector": "identity", "action": "end_sessions", "target": target, "tokens_revoked": True, "ts": ts}
        if action_type == "require_password_reset":
            self.password_resets.add(target)
            return {"connector": "identity", "action": "require_password_reset", "target": target, "mfa_rebind": True, "ts": ts}
        if action_type == "disable_cloud_key":
            self.disabled_cloud_keys.add(target)
            return {"connector": "cloud_iam", "action": "disable_cloud_key", "target": target, "key_status": "Inactive", "ts": ts}
        if action_type == "notify_customer":
            rec = {"target": target, "channel": params.get("channel", "SMS+InApp"), "ts": ts}
            self.notified_customers.append(rec)
            return {"connector": "core_banking", "action": "notify_customer", **rec}
        raise ValueError(f"unsupported playbook action: {action_type}")


class PlaybookEngine:
    """Manages proposed containment actions with call-bound analyst approvals and audit logging."""

    def __init__(
        self,
        audit: AuditLog,
        state_store: StateStore | None = None,
        connectors: ConnectorSuite | None = None,
        ttl: float = APPROVAL_TTL_S,
        allowed_actions: list[str] | None = None,
    ):
        self.audit = audit
        self.state_store = state_store
        self.connectors = connectors or ConnectorSuite()
        self.ttl = ttl
        self.allowed_actions = set(allowed_actions or PLAYBOOK_SPECS) & set(PLAYBOOK_SPECS)
        self._lock = threading.Lock()
        # approvals outlive the process: pending ones can still be decided after a restart
        self.items: dict[str, PendingAction] = {
            p["action_id"]: PendingAction(**p) for p in (state_store.list_approvals() if state_store else [])
        }

    def _save(self, act: PendingAction) -> None:
        if self.state_store:
            self.state_store.save_approval(act.action_id, act.incident_id, act.status, act.created_at, act.to_dict())

    def validate(self, action_type: str, target: str) -> None:
        if action_type not in self.allowed_actions:
            raise ValueError(f"playbook action {action_type!r} is not enabled")
        if not target or len(target) > 128 or not target.isprintable():
            raise ValueError("target must be 1-128 printable characters")
        if action_type == "block_ip":
            try:
                ip = ipaddress.ip_address(target)
            except ValueError as e:
                raise ValueError(f"block_ip needs an IP address, got {target!r}") from e
            if not ip.is_global:
                # blocking an internal or reserved range at the perimeter would cut off the bank itself
                raise ValueError(f"refusing to block non-public address {target}")

    def reset(self) -> None:
        with self._lock:
            self.items.clear()
            self.connectors.reset()

    def propose(
        self,
        incident_id: str,
        action_type: str,
        target: str,
        rationale: str,
        params: dict[str, Any] | None = None,
        proposed_by: str = "copilot",
    ) -> PendingAction:
        self.validate(action_type, target)
        params = dict(params or {})
        digest = action_hash(action_type, incident_id, target, params)
        with self._lock:
            # Avoid duplicate proposals for the exact same call digest
            for existing in self.items.values():
                if existing.digest == digest and existing.status in ("pending", "approved", "executed"):
                    return existing
            act = PendingAction(
                action_id=f"ACT-{secrets.token_hex(6).upper()}",
                incident_id=incident_id,
                action_type=action_type,
                target=target,
                rationale=rationale[:1000],
                connector=PLAYBOOK_SPECS[action_type]["connector"],
                params=params,
                digest=digest,
                proposed_by=proposed_by,
            )
            self.items[act.action_id] = act
            self._save(act)
            self.audit.append(
                "playbook_proposed",
                action_id=act.action_id,
                incident_id=incident_id,
                action_type=action_type,
                target=target,
                digest=digest,
                proposed_by=proposed_by,
            )
            return act

    def decide(self, action_id: str, approve: bool, analyst: str = "soc.analyst") -> PendingAction:
        with self._lock:
            if action_id not in self.items:
                raise KeyError(f"unknown action_id: {action_id}")
            act = self.items[action_id]
            if act.status != "pending":
                raise ValueError(f"action {action_id} is already {act.status}")
            if time.time() - act.created_at > self.ttl:
                act.status = "expired"
                self._save(act)
                self.audit.append("playbook_expired", action_id=act.action_id, incident_id=act.incident_id)
                raise ValueError(f"action {action_id} approval expired")
            if approve and analyst == act.proposed_by:
                # four eyes: whoever raised an action by hand cannot also approve it
                raise PermissionError("an action must be approved by someone other than the analyst who proposed it")
            act.status = "approved" if approve else "declined"
            act.decided_by = analyst
            act.decided_at = round(time.time(), 3)
            self.audit.append(
                "playbook_decision",
                action_id=act.action_id,
                incident_id=act.incident_id,
                approved=approve,
                analyst=analyst,
                digest=act.digest,
            )
            self._save(act)
            return act

    def consume_and_execute(
        self,
        action_id: str,
        action_type: str | None = None,
        incident_id: str | None = None,
        target: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> PendingAction:
        """Execute an approved action after verifying its call-bound SHA-256 digest (single-use)."""
        with self._lock:
            act = self.items.get(action_id)
            if act is None or act.status != "approved":
                raise PermissionError(f"action {action_id} is not in approved state")
            check_type = action_type if action_type is not None else act.action_type
            check_inc = incident_id if incident_id is not None else act.incident_id
            check_target = target if target is not None else act.target
            check_params = params if params is not None else act.params
            if action_hash(check_type, check_inc, check_target, check_params) != act.digest:
                self.audit.append(
                    "playbook_tamper_blocked",
                    action_id=action_id,
                    expected_digest=act.digest,
                )
                raise PermissionError("execution parameters differ from what the analyst approved")
            try:
                res = self.connectors.execute(act.action_type, act.target, act.params)
            except Exception as e:
                act.status = "failed"
                act.execution_result = {"error": f"{type(e).__name__}: {e}"}
                self._save(act)
                self.audit.append("playbook_failed", action_id=act.action_id, incident_id=act.incident_id,
                                  error=act.execution_result["error"])
                raise
            act.status = "executed"
            act.execution_result = res
            self.audit.append(
                "playbook_executed",
                action_id=act.action_id,
                incident_id=act.incident_id,
                action_type=act.action_type,
                target=act.target,
                connector=act.connector,
                digest=act.digest,
            )
            self._save(act)
            return act

    def decide_and_run(self, action_id: str, approve: bool, analyst: str = "soc.analyst") -> PendingAction:
        act = self.decide(action_id, approve=approve, analyst=analyst)
        if not approve:
            return act
        return self.consume_and_execute(action_id)

    def list_actions(self, incident_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            vals = list(self.items.values())
        if incident_id:
            vals = [a for a in vals if a.incident_id == incident_id]
        return [a.to_dict() for a in sorted(vals, key=lambda x: x.created_at)]
