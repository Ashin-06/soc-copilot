"""Stage 4 Detect: Sigma-compatible YAML rule engine, per-user/service behaviour
baselines, and payment-system fraud signal detectors.
"""
from __future__ import annotations

import datetime as dt
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .normalize import NormalizedEvent

RULES_DIR = Path(__file__).resolve().parent / "rules"

TACTIC_ORDER = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    title: str
    severity: str               # low | medium | high | critical
    domain: str                 # security | fraud
    timestamp: float
    tactics: list[str]
    techniques: list[str]
    event_ids: list[str]
    entities: list[str]
    money_at_risk: float = 0.0
    host: str | None = None
    asset_criticality: int = 2
    customer_id: str | None = None
    user: str | None = None
    source_ip: str | None = None
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_timeframe(tf: str | None) -> float:
    if not tf:
        return 300.0
    m = re.match(r"^\s*(\d+)\s*([smhd])\s*$", str(tf).lower())
    if not m:
        return 300.0
    val = int(m.group(1))
    unit = m.group(2)
    return float(val * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit])


def _get_field(ev: NormalizedEvent, field_path: str) -> Any:
    if field_path == "actor":
        return ev.customer_id or ev.user or ev.source_ip
    parts = field_path.split(".")
    cur: Any = ev
    for p in parts:
        if isinstance(cur, NormalizedEvent):
            cur = getattr(cur, p, None)
        elif isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def _match_value(actual: Any, expected: Any, modifier: str | None) -> bool:
    if actual is None:
        return False
    if modifier is None:
        if isinstance(expected, list):
            return actual in expected
        return actual == expected
    if modifier == "in":
        return actual in (expected if isinstance(expected, (list, tuple, set)) else [expected])
    if modifier == "contains":
        targets = expected if isinstance(expected, list) else [expected]
        return any(str(t).lower() in str(actual).lower() for t in targets)
    if modifier == "startswith":
        targets = expected if isinstance(expected, list) else [expected]
        return any(str(actual).lower().startswith(str(t).lower()) for t in targets)
    if modifier == "endswith":
        targets = expected if isinstance(expected, list) else [expected]
        return any(str(actual).lower().endswith(str(t).lower()) for t in targets)
    if modifier == "re":
        return bool(re.search(str(expected), str(actual)))
    try:
        a_num = float(actual)
        e_num = float(expected)
    except (TypeError, ValueError):
        return False
    if modifier == "gte":
        return a_num >= e_num
    if modifier == "gt":
        return a_num > e_num
    if modifier == "lte":
        return a_num <= e_num
    if modifier == "lt":
        return a_num < e_num
    return False


def _match_block(ev: NormalizedEvent, block: dict[str, Any]) -> bool:
    for raw_key, expected in block.items():
        if "|" in raw_key:
            field_path, modifier = raw_key.split("|", 1)
        else:
            field_path, modifier = raw_key, None
        actual = _get_field(ev, field_path)
        if not _match_value(actual, expected, modifier):
            return False
    return True


@dataclass
class SigmaRule:
    id: str
    title: str
    description: str
    level: str
    tags: list[str]
    tactics: list[str]
    techniques: list[str]
    domain: str
    selection: dict[str, Any]
    filter_block: dict[str, Any] | None
    timeframe_s: float | None
    agg_group_by: str | None
    agg_op: str | None
    agg_threshold: int | None

    @classmethod
    def from_yaml(cls, data: dict[str, Any]) -> "SigmaRule":
        tags = [str(t).lower() for t in data.get("tags", [])]
        tactics: list[str] = []
        techniques: list[str] = []
        domain = "fraud" if "domain.fraud" in tags else "security"
        for t in tags:
            if t.startswith("attack.t") and len(t) > 8 and t[8].isdigit():
                techniques.append(t.split(".", 1)[1].upper())
            elif t.startswith("attack."):
                tac = t.split(".", 1)[1]
                if tac in TACTIC_ORDER and tac not in tactics:
                    tactics.append(tac)

        det = data.get("detection", {})
        selection = det.get("selection", {})
        filter_block = det.get("filter")
        cond = str(det.get("condition", "selection"))
        tf = _parse_timeframe(det["timeframe"]) if "timeframe" in det else None

        agg_group_by = None
        agg_op = None
        agg_threshold = None
        if "|" in cond:
            _, pipe_part = cond.split("|", 1)
            m = re.search(r"count\(\)\s+by\s+([a-zA-Z0-9_.]+)\s*(>=|>|==)\s*(\d+)", pipe_part.strip())
            if m:
                agg_group_by = m.group(1)
                agg_op = m.group(2)
                agg_threshold = int(m.group(3))

        return cls(
            id=str(data.get("id", "SIGMA-UNKNOWN")),
            title=str(data.get("title", "Unnamed Sigma Rule")),
            description=str(data.get("description", "")),
            level=str(data.get("level", "medium")).lower(),
            tags=tags,
            tactics=tactics or ["discovery"],
            techniques=techniques or ["T1078"],
            domain=domain,
            selection=selection,
            filter_block=filter_block,
            timeframe_s=tf,
            agg_group_by=agg_group_by,
            agg_op=agg_op,
            agg_threshold=agg_threshold,
        )

    def matches_event(self, ev: NormalizedEvent) -> bool:
        if not _match_block(ev, self.selection):
            return False
        if self.filter_block and _match_block(ev, self.filter_block):
            return False
        return True


class BehaviorBaseline:
    """Tracks per-user and per-service behaviour baselines (login hours, impossible travel,
    and data egress volumes) and flags anomalous deviations.
    """

    def __init__(self, egress_limit_bytes: int = 50_000_000):
        self.egress_limit_bytes = egress_limit_bytes

    def evaluate(self, ev: NormalizedEvent, seq: int) -> list[Alert]:
        alerts: list[Alert] = []
        crit = int(ev.enrichment.get("asset_criticality", 2))

        # 1. Off-hours staff authentication baseline
        usual_hours = ev.enrichment.get("staff_usual_hours")
        if (
            ev.event_category == "authentication"
            and ev.event_action == "login_success"
            and ev.event_outcome == "success"
            and usual_hours
            and ev.enrichment.get("staff_privilege_tier") in ("privileged_admin", "dba", "standard")
        ):
            start_h, end_h = int(usual_hours[0]), int(usual_hours[1])
            if not (start_h == 0 and end_h == 24):
                hour = dt.datetime.fromtimestamp(ev.timestamp, tz=dt.timezone.utc).hour
                if hour < start_h or hour >= end_h:
                    alerts.append(
                        Alert(
                            alert_id=f"ALT-BL-{seq:04d}-A",
                            rule_id="BASELINE-OFFHOURS-001",
                            title="Anomalous Off-Hours Staff Login",
                            severity="medium",
                            domain="security",
                            timestamp=ev.timestamp,
                            tactics=["initial_access"],
                            techniques=["T1078"],
                            event_ids=[ev.event_id],
                            entities=list(ev.entities),
                            host=ev.host,
                            asset_criticality=crit,
                            user=ev.user,
                            source_ip=ev.source_ip,
                            summary=f"Staff user {ev.user} logged in at {hour:02d}:00 UTC outside usual window {start_h:02d}:00-{end_h:02d}:00.",
                        )
                    )

        # 2. Impossible travel baseline
        if ev.enrichment.get("impossible_travel"):
            speed = ev.enrichment.get("travel_speed_kmh", 0.0)
            prev_c = ev.enrichment.get("previous_country", "IN")
            cur_c = ev.enrichment.get("geo_country", "UNKNOWN")
            alerts.append(
                Alert(
                    alert_id=f"ALT-BL-{seq:04d}-B",
                    rule_id="BASELINE-GEO-002",
                    title="Impossible Geographic Travel Detected",
                    severity="high",
                    domain="security",
                    timestamp=ev.timestamp,
                    tactics=["initial_access"],
                    techniques=["T1078"],
                    event_ids=[ev.event_id],
                    entities=list(ev.entities),
                    host=ev.host,
                    asset_criticality=crit,
                    customer_id=ev.customer_id,
                    user=ev.user,
                    source_ip=ev.source_ip,
                    summary=f"Actor {ev.customer_id or ev.user} shifted from {prev_c} to {cur_c} at {speed:.0f} km/h.",
                )
            )

        # 3. Unusual data volume / egress baseline
        if ev.bytes_out >= self.egress_limit_bytes and ev.user != "svc-backup-nightly":
            mb = ev.bytes_out / (1024 * 1024)
            alerts.append(
                Alert(
                    alert_id=f"ALT-BL-{seq:04d}-C",
                    rule_id="BASELINE-EGRESS-003",
                    title="Anomalous Bulk Data Egress Volume",
                    severity="critical",
                    domain="security",
                    timestamp=ev.timestamp,
                    tactics=["exfiltration"],
                    techniques=["T1041"],
                    event_ids=[ev.event_id],
                    entities=list(ev.entities),
                    host=ev.host,
                    asset_criticality=crit,
                    customer_id=ev.customer_id,
                    user=ev.user,
                    source_ip=ev.source_ip,
                    summary=f"Host {ev.host} transferred {mb:.1f} MB out (baseline threshold {self.egress_limit_bytes / (1024 * 1024):.0f} MB).",
                )
            )

        # 4. Payment fraud baseline: SIM/device change + high transfer ratio or risky account modification
        if ev.source == "payments":
            if ev.event_action in ("device_changed", "phone_changed") and (
                ev.enrichment.get("ip_malicious") or ev.enrichment.get("geo_country") not in ("IN", "UNKNOWN", "INTERNAL")
            ):
                alerts.append(
                    Alert(
                        alert_id=f"ALT-FRD-{seq:04d}-A",
                        rule_id="FRAUD-ATO-DEVICE-001",
                        title="Suspicious Device or Phone Change from High-Risk Network",
                        severity="high",
                        domain="fraud",
                        timestamp=ev.timestamp,
                        tactics=["persistence", "credential_access"],
                        techniques=["T1098"],
                        event_ids=[ev.event_id],
                        entities=list(ev.entities),
                        host=ev.host,
                        asset_criticality=crit,
                        customer_id=ev.customer_id,
                        user=ev.user,
                        source_ip=ev.source_ip,
                        summary=f"Customer {ev.customer_id} registered {ev.event_action} from {ev.source_ip} ({ev.enrichment.get('geo_country')}).",
                    )
                )
            elif (
                ev.event_category == "payment"
                and ev.amount >= 50000
                and (
                    ev.enrichment.get("recent_device_change")
                    or ev.enrichment.get("recent_phone_change")
                    or ev.enrichment.get("amount_to_avg_ratio", 0.0) >= 6.0
                )
            ):
                alerts.append(
                    Alert(
                        alert_id=f"ALT-FRD-{seq:04d}-B",
                        rule_id="FRAUD-DRAIN-002",
                        title="Anomalous High-Ratio Outbound Transfer After Account Modification",
                        severity="critical",
                        domain="fraud",
                        timestamp=ev.timestamp,
                        tactics=["impact"],
                        techniques=["T1657"],
                        event_ids=[ev.event_id],
                        entities=list(ev.entities),
                        money_at_risk=ev.amount,
                        host=ev.host,
                        asset_criticality=crit,
                        customer_id=ev.customer_id,
                        user=ev.user,
                        source_ip=ev.source_ip,
                        summary=(
                            f"Transfer of ₹{ev.amount:,.0f} ({ev.enrichment.get('amount_to_avg_ratio', 1.0):.1f}x customer average) "
                            f"from {ev.customer_id} following recent account/device change."
                        ),
                    )
                )

        return alerts


class DetectionEngine:
    """Runs Sigma YAML rules (single-event and time-windowed thresholds) plus behaviour baselines."""

    def __init__(self, rules_dir: str | Path = RULES_DIR):
        self.rules_dir = Path(rules_dir)
        self.rules: list[SigmaRule] = self._load_rules()
        self.baseline = BehaviorBaseline()
        self._window_buffers: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        self._window_fired: set[tuple[str, str, int]] = set()
        self._seq = 0

    def _load_rules(self) -> list[SigmaRule]:
        loaded: list[SigmaRule] = []
        if not self.rules_dir.exists():
            return loaded
        for p in sorted(self.rules_dir.glob("*.yml")):
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                loaded.append(SigmaRule.from_yaml(data))
        return loaded

    def reset(self) -> None:
        self._window_buffers.clear()
        self._window_fired.clear()
        self._seq = 0

    def evaluate_event(self, ev: NormalizedEvent) -> list[Alert]:
        self._seq += 1
        out: list[Alert] = []
        crit = int(ev.enrichment.get("asset_criticality", 2))

        for rule in self.rules:
            if not rule.matches_event(ev):
                continue

            if rule.agg_group_by and rule.agg_threshold and rule.timeframe_s:
                group_val = str(_get_field(ev, rule.agg_group_by) or "global")
                key = (rule.id, group_val)
                buf = self._window_buffers[key]
                buf.append(ev)
                cutoff = ev.timestamp - rule.timeframe_s
                buf[:] = [x for x in buf if x.timestamp >= cutoff]
                bucket_id = int(ev.timestamp // rule.timeframe_s)
                if len(buf) >= rule.agg_threshold and (rule.id, group_val, bucket_id) not in self._window_fired:
                    self._window_fired.add((rule.id, group_val, bucket_id))
                    ent_set: list[str] = []
                    for item in buf:
                        for e in item.entities:
                            if e not in ent_set:
                                ent_set.append(e)
                    money = sum(x.amount for x in buf if x.event_category == "payment")
                    out.append(
                        Alert(
                            alert_id=f"ALT-{self._seq:04d}-{rule.id[-3:]}",
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.level,
                            domain=rule.domain,
                            timestamp=ev.timestamp,
                            tactics=list(rule.tactics),
                            techniques=list(rule.techniques),
                            event_ids=[x.event_id for x in buf],
                            entities=ent_set,
                            money_at_risk=money,
                            host=ev.host,
                            asset_criticality=max(int(x.enrichment.get("asset_criticality", 2)) for x in buf),
                            customer_id=ev.customer_id,
                            user=ev.user,
                            source_ip=ev.source_ip,
                            summary=f"{rule.title}: {len(buf)} events for {rule.agg_group_by}={group_val} within {int(rule.timeframe_s)}s.",
                        )
                    )
            else:
                money = ev.amount if ev.event_category == "payment" else 0.0
                out.append(
                    Alert(
                        alert_id=f"ALT-{self._seq:04d}-{rule.id[-3:]}",
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.level,
                        domain=rule.domain,
                        timestamp=ev.timestamp,
                        tactics=list(rule.tactics),
                        techniques=list(rule.techniques),
                        event_ids=[ev.event_id],
                        entities=list(ev.entities),
                        money_at_risk=money,
                        host=ev.host,
                        asset_criticality=crit,
                        customer_id=ev.customer_id,
                        user=ev.user,
                        source_ip=ev.source_ip,
                        summary=f"{rule.title} on {ev.host or ev.source} ({ev.event_action}).",
                    )
                )

        out.extend(self.baseline.evaluate(ev, self._seq))
        return out
