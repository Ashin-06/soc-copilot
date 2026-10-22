"""Stage 2 Normalise: Map every source onto an Elastic ECS-modelled common schema
and extract canonical entities (user, customer, IP, device, host, customer account, cloud key).

Raw logs are untrusted: every field is coerced to the type the schema expects, and
anything that is not a plain scalar (a nested object where a name should be, NaN, a
negative byte count) is dropped rather than allowed to crash the pipeline.
"""
from __future__ import annotations

import datetime as dt
import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .ingest.connectors import IngestedEnvelope

# Event IDs are cited in reports as [EVT-...], so only IDs in that shape are kept as-is.
SAFE_EVENT_ID = re.compile(r"^EVT-[A-Za-z0-9_-]{1,60}$")
MAX_FIELD = 256
MAX_MESSAGE = 2000


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

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NormalizedEvent":
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})


def _s(v: Any, limit: int = MAX_FIELD) -> str | None:
    """A scalar as a trimmed string, or None for empty / structured / boolean values."""
    if v is None or isinstance(v, bool) or not isinstance(v, (str, int, float)):
        return None
    if isinstance(v, float) and not math.isfinite(v):
        return None
    out = str(v).strip()[:limit]
    return out or None


def _num(v: Any) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.0
    return f if math.isfinite(f) and f >= 0 else 0.0


def _int(v: Any) -> int:
    return int(_num(v))


def _obj(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


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


def event_id_for(env: IngestedEnvelope) -> str:
    """The source's own ID when it is safe to cite, otherwise one derived from the content hash
    (stable across restarts, unlike a counter)."""
    raw_id = env.raw.get("event_id")
    if isinstance(raw_id, str) and SAFE_EVENT_ID.match(raw_id):
        return raw_id
    return f"EVT-{env.event_hash[:12].upper()}"


def normalize_envelope(env: IngestedEnvelope) -> NormalizedEvent:
    raw = env.raw
    src = env.source

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
    bytes_out: int = _int(raw.get("bytes_out"))
    category = "security"
    action = "unknown"
    outcome = "unknown"
    message = _s(raw.get("message"), MAX_MESSAGE) or ""
    details: dict[str, Any] = {}

    if src == "wazuh":
        rule = _obj(raw.get("rule"))
        data = _obj(raw.get("data"))
        agent = _obj(raw.get("agent"))
        host = _s(agent.get("name")) or _s(raw.get("host"))
        source_ip = _s(data.get("srcip")) or _s(raw.get("source_ip"))
        user = _s(data.get("dstuser")) or _s(data.get("srcuser")) or _s(raw.get("user"))
        action = _s(data.get("action")) or _s(rule.get("id")) or "wazuh_alert"
        category = _s(data.get("category")) or ("database" if "db" in (host or "") else "process")
        outcome = _s(data.get("outcome")) or "success"
        bytes_out = _int(data.get("bytes_out")) or bytes_out
        message = _s(rule.get("description"), MAX_MESSAGE) or _s(raw.get("full_log"), MAX_MESSAGE) or action
        details = {"rule_id": _s(rule.get("id")), "rule_level": _s(rule.get("level")), "command": _s(data.get("command"), MAX_MESSAGE)}

    elif src == "ecs":
        ev = _obj(raw.get("event"))
        u = raw.get("user")
        s = raw.get("source")
        h = raw.get("host")
        u_obj = raw.get("url")
        cat = ev.get("category")
        category = _s(cat[0] if isinstance(cat, list) and cat else cat) or "network"  # ECS allows a list
        action = _s(ev.get("action")) or "ecs_event"
        outcome = _s(ev.get("outcome")) or "success"
        user = _s(u.get("name")) if isinstance(u, dict) else _s(u)
        customer_id = _s(raw.get("customer_id")) or (_s(u.get("id")) if isinstance(u, dict) else None)
        source_ip = _s(s.get("ip")) if isinstance(s, dict) else _s(raw.get("source_ip"))
        host = _s(h.get("name")) if isinstance(h, dict) else _s(h)
        url = _s(u_obj.get("path"), MAX_MESSAGE) if isinstance(u_obj, dict) else _s(u_obj, MAX_MESSAGE)
        device_id = _s(raw.get("device_id"))
        account = _s(raw.get("account"))
        amount = _num(raw.get("amount"))
        message = message or f"ECS {category}/{action} ({outcome})"
        details = {k: v for k, v in raw.items() if k not in ("@timestamp", "event", "user", "source", "host", "url")}

    elif src == "cloudtrail":
        ident = _obj(raw.get("userIdentity"))
        req = _obj(raw.get("requestParameters"))
        resp = _obj(raw.get("responseElements"))
        action = _s(raw.get("eventName")) or "cloud_api"
        ev_source = _s(raw.get("eventSource")) or ""
        category = "storage" if "s3" in ev_source else "iam"
        outcome = "failure" if raw.get("errorCode") else "success"
        user = _s(ident.get("userName")) or _s(ident.get("principalId")) or _s(raw.get("user"))
        source_ip = _s(raw.get("sourceIPAddress"))
        host = ev_source or "aws.cloudtrail"
        cloud_key = (
            _s(_obj(resp.get("accessKey")).get("accessKeyId"))
            or _s(ident.get("accessKeyId"))
            or _s(raw.get("cloud_key"))
        )
        bytes_out = _int(raw.get("bytesTransferredOut")) or _int(req.get("bytes_out")) or bytes_out
        message = message or f"CloudTrail {action} by {user or 'unknown'} on {host}"
        details = {
            "eventSource": ev_source,
            "requestParameters": req,
            "responseElements": resp,
            "errorCode": _s(raw.get("errorCode")),
        }

    elif src == "auth":
        category = "authentication"
        action = _s(raw.get("action")) or "login"
        outcome = _s(raw.get("outcome")) or ("failure" if "fail" in action or "denied" in action else "success")
        user = _s(raw.get("user"))
        customer_id = _s(raw.get("customer_id"))
        source_ip = _s(raw.get("ip")) or _s(raw.get("source_ip"))
        device_id = _s(raw.get("device_id"))
        host = _s(raw.get("host")) or "auth-service-prod"
        account = _s(raw.get("account"))
        message = message or f"Auth {action} ({outcome}) for {customer_id or user or 'unknown'}"
        details = {
            "mfa_method": _s(raw.get("mfa_method")),
            "user_agent": _s(raw.get("user_agent"), MAX_MESSAGE),
            "customer_name": _s(raw.get("customer_name")),
            "phone": _s(raw.get("phone")),
            "email": _s(raw.get("email")),
        }

    elif src == "api_gateway":
        category = "api"
        url = _s(raw.get("path"), MAX_MESSAGE) or _s(raw.get("url"), MAX_MESSAGE) or "/"
        status_code = _int(raw.get("status_code")) or 200
        method = _s(raw.get("method")) or "GET"
        action = _s(raw.get("action")) or ("api_account_lookup" if "/accounts/" in url else "api_request")
        outcome = "failure" if status_code >= 400 else "success"
        user = _s(raw.get("user"))
        customer_id = _s(raw.get("customer_id"))
        source_ip = _s(raw.get("client_ip")) or _s(raw.get("ip")) or _s(raw.get("source_ip"))
        device_id = _s(raw.get("device_id"))
        host = _s(raw.get("host")) or "prod-api-gw-01"
        account = _s(raw.get("account")) or _s(raw.get("target_account"))
        bytes_out = _int(raw.get("bytes_out"))
        message = message or f"{method} {url} -> {status_code}"
        details = {
            "method": method,
            "status_code": status_code,
            "latency_ms": _num(raw.get("latency_ms")),
            "target_account": _s(raw.get("target_account")),
        }

    elif src == "payments":
        action = _s(raw.get("action")) or "transfer"
        category = "account_change" if action in ("beneficiary_added", "device_changed", "phone_changed", "limit_updated") else "payment"
        outcome = _s(raw.get("outcome")) or "success"
        user = _s(raw.get("user"))
        customer_id = _s(raw.get("customer_id"))
        source_ip = _s(raw.get("ip")) or _s(raw.get("source_ip"))
        device_id = _s(raw.get("device_id"))
        host = _s(raw.get("host")) or "core-payments-engine"
        account = _s(raw.get("account"))
        counterparty_account = _s(raw.get("counterparty_account")) or _s(raw.get("beneficiary_account"))
        amount = _num(raw.get("amount"))
        message = message or (
            f"Payment {action}: ₹{amount:,.0f} from {account or customer_id} to {counterparty_account or 'N/A'}"
            if amount > 0
            else f"Account event {action} for {customer_id or account}"
        )
        details = {
            "channel": _s(raw.get("channel")) or "IMPS",
            "ifsc": _s(raw.get("ifsc")),
            "beneficiary_name": _s(raw.get("beneficiary_name")),
            "customer_name": _s(raw.get("customer_name")),
            "pan": _s(raw.get("pan")),
            "phone": _s(raw.get("phone")),
            "utr": _s(raw.get("utr")),
        }

    if "campaign_id" in raw:
        details["campaign_id"] = _s(raw["campaign_id"])
    ev_id = event_id_for(env)
    if raw.get("event_id") is not None and _s(raw.get("event_id")) != ev_id:
        details["source_event_id"] = _s(raw.get("event_id"))

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
