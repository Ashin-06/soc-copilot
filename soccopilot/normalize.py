"""Stage 2 Normalise: Map every source onto an Elastic ECS-modelled common schema
and extract canonical entities (user, customer, IP, device, host, customer account, cloud key).
"""
from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field
from typing import Any

from .ingest.connectors import IngestedEnvelope


@dataclass
class NormalizedEvent:
    event_id: str
    raw_hash: str
    timestamp: float
    iso_timestamp: str
    source: str
    event_category: str     # authentication | iam | network | api | process | database | payment | account_change | storage
    event_action: str       # e.g. login_failed, AssumeRole, beneficiary_added, wire_transfer, sudo_exec
    event_outcome: str      # success | failure | unknown
    user: str | None = None
    customer_id: str | None = None
    source_ip: str | None = None
    host: str | None = None
    device_id: str | None = None
    url: str | None = None
    account: str | None = None
    counterparty_account: str | None = None
    amount: float = 0.0
    cloud_key: str | None = None
    bytes_out: int = 0
    message: str = ""
    entities: list[str] = field(default_factory=list)
    enrichment: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def extract_entities(
    user: str | None = None,
    customer_id: str | None = None,
    source_ip: str | None = None,
    device_id: str | None = None,
    host: str | None = None,
    account: str | None = None,
    cloud_key: str | None = None,
) -> list[str]:
    out: list[str] = []
    if user:
        out.append(f"user:{user}")
    if customer_id:
        out.append(f"customer:{customer_id}")
    if source_ip:
        out.append(f"ip:{source_ip}")
    if device_id:
        out.append(f"device:{device_id}")
    if host:
        out.append(f"host:{host}")
    if account:
        out.append(f"account:{account}")
    if cloud_key:
        out.append(f"cloud_key:{cloud_key}")
    return out


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()


def normalize_envelope(env: IngestedEnvelope, seq: int | None = None) -> NormalizedEvent:
    raw = env.raw
    src = env.source
    ev_id = str(raw.get("event_id") or (f"EVT-{seq:04d}" if seq is not None else f"EVT-{env.event_hash[:8].upper()}"))

    user: str | None = None
    customer_id: str | None = None
    source_ip: str | None = None
    host: str | None = None
    device_id: str | None = None
    url: str | None = None
    account: str | None = None
    counterparty_account: str | None = None
    amount: float = 0.0
    cloud_key: str | None = None
    bytes_out: int = int(raw.get("bytes_out") or 0)
    category = "security"
    action = "unknown"
    outcome = "unknown"
    message = str(raw.get("message") or "")
    details: dict[str, Any] = {}

    if src == "wazuh":
        rule = raw.get("rule", {})
        data = raw.get("data", {})
        agent = raw.get("agent", {})
        host = agent.get("name") or raw.get("host")
        source_ip = data.get("srcip") or raw.get("source_ip")
        user = data.get("dstuser") or data.get("srcuser") or raw.get("user")
        action = str(data.get("action") or rule.get("id") or "wazuh_alert")
        category = str(data.get("category") or ("database" if "db" in (host or "") else "process"))
        outcome = str(data.get("outcome") or "success")
        bytes_out = int(data.get("bytes_out") or bytes_out)
        message = str(rule.get("description") or raw.get("full_log") or action)
        details = {"rule_id": rule.get("id"), "rule_level": rule.get("level"), "command": data.get("command")}

    elif src == "ecs":
        ev = raw.get("event", {})
        u = raw.get("user", {})
        s = raw.get("source", {})
        h = raw.get("host", {})
        u_obj = raw.get("url", {})
        category = str(ev.get("category") or "network")
        if isinstance(category, list):
            category = str(category[0])
        action = str(ev.get("action") or "ecs_event")
        outcome = str(ev.get("outcome") or "success")
        user = u.get("name") if isinstance(u, dict) else str(u or "") or None
        customer_id = raw.get("customer_id") or (u.get("id") if isinstance(u, dict) else None)
        source_ip = s.get("ip") if isinstance(s, dict) else raw.get("source_ip")
        host = h.get("name") if isinstance(h, dict) else raw.get("host")
        url = u_obj.get("path") if isinstance(u_obj, dict) else raw.get("url")
        device_id = raw.get("device_id")
        account = raw.get("account")
        amount = float(raw.get("amount") or 0.0)
        bytes_out = int(raw.get("bytes_out") or 0)
        message = message or f"ECS {category}/{action} ({outcome})"
        details = {k: v for k, v in raw.items() if k not in ("@timestamp", "event", "user", "source", "host", "url")}

    elif src == "cloudtrail":
        ident = raw.get("userIdentity", {})
        req = raw.get("requestParameters", {}) or {}
        resp = raw.get("responseElements", {}) or {}
        action = str(raw.get("eventName") or "cloud_api")
        ev_source = str(raw.get("eventSource") or "")
        category = "storage" if "s3" in ev_source else "iam"
        outcome = "failure" if raw.get("errorCode") else "success"
        user = ident.get("userName") or ident.get("principalId") or raw.get("user")
        source_ip = raw.get("sourceIPAddress")
        host = ev_source or "aws.cloudtrail"
        cloud_key = (
            (resp.get("accessKey", {}) or {}).get("accessKeyId")
            or ident.get("accessKeyId")
            or raw.get("cloud_key")
        )
        bytes_out = int(raw.get("bytesTransferredOut") or req.get("bytes_out") or bytes_out)
        message = message or f"CloudTrail {action} by {user or 'unknown'} on {host}"
        details = {
            "eventSource": ev_source,
            "requestParameters": req,
            "responseElements": resp,
            "errorCode": raw.get("errorCode"),
        }

    elif src == "auth":
        category = "authentication"
        action = str(raw.get("action") or "login")
        outcome = str(raw.get("outcome") or ("failure" if "fail" in action or "denied" in action else "success"))
        user = raw.get("user")
        customer_id = raw.get("customer_id")
        source_ip = raw.get("ip") or raw.get("source_ip")
        device_id = raw.get("device_id")
        host = raw.get("host") or "auth-service-prod"
        account = raw.get("account")
        message = message or f"Auth {action} ({outcome}) for {customer_id or user or 'unknown'}"
        details = {
            "mfa_method": raw.get("mfa_method"),
            "user_agent": raw.get("user_agent"),
            "customer_name": raw.get("customer_name"),
            "phone": raw.get("phone"),
            "email": raw.get("email"),
        }

    elif src == "api_gateway":
        category = "api"
        url = str(raw.get("path") or raw.get("url") or "/")
        status_code = int(raw.get("status_code") or 200)
        action = str(raw.get("action") or ("api_account_lookup" if "/accounts/" in url else "api_request"))
        outcome = "failure" if status_code >= 400 else "success"
        user = raw.get("user")
        customer_id = raw.get("customer_id")
        source_ip = raw.get("client_ip") or raw.get("ip") or raw.get("source_ip")
        device_id = raw.get("device_id")
        host = raw.get("host") or "prod-api-gw-01"
        account = raw.get("account") or raw.get("target_account")
        bytes_out = int(raw.get("bytes_out") or 0)
        message = message or f"{raw.get('method', 'GET')} {url} -> {status_code}"
        details = {
            "method": raw.get("method", "GET"),
            "status_code": status_code,
            "latency_ms": raw.get("latency_ms", 12),
            "target_account": raw.get("target_account"),
        }

    elif src == "payments":
        action = str(raw.get("action") or "transfer")
        category = "account_change" if action in ("beneficiary_added", "device_changed", "phone_changed", "limit_updated") else "payment"
        outcome = str(raw.get("outcome") or "success")
        user = raw.get("user")
        customer_id = raw.get("customer_id")
        source_ip = raw.get("ip") or raw.get("source_ip")
        device_id = raw.get("device_id")
        host = raw.get("host") or "core-payments-engine"
        account = raw.get("account")
        counterparty_account = raw.get("counterparty_account") or raw.get("beneficiary_account")
        amount = float(raw.get("amount") or 0.0)
        message = message or (
            f"Payment {action}: ₹{amount:,.0f} from {account or customer_id} to {counterparty_account or 'N/A'}"
            if amount > 0
            else f"Account event {action} for {customer_id or account}"
        )
        details = {
            "channel": raw.get("channel", "IMPS"),
            "ifsc": raw.get("ifsc"),
            "beneficiary_name": raw.get("beneficiary_name"),
            "customer_name": raw.get("customer_name"),
            "pan": raw.get("pan"),
            "phone": raw.get("phone"),
            "utr": raw.get("utr"),
        }

    if "campaign_id" in raw:
        details["campaign_id"] = raw["campaign_id"]

    entities = extract_entities(
        user=user,
        customer_id=customer_id,
        source_ip=source_ip,
        device_id=device_id,
        host=host,
        account=account,
        cloud_key=cloud_key,
    )

    return NormalizedEvent(
        event_id=ev_id,
        raw_hash=env.event_hash,
        timestamp=env.timestamp,
        iso_timestamp=_iso(env.timestamp),
        source=src,
        event_category=category,
        event_action=action,
        event_outcome=outcome,
        user=user,
        customer_id=customer_id,
        source_ip=source_ip,
        host=host,
        device_id=device_id,
        url=url,
        account=account,
        counterparty_account=counterparty_account,
        amount=amount,
        cloud_key=cloud_key,
        bytes_out=bytes_out,
        message=message,
        entities=entities,
        details=details,
    )
