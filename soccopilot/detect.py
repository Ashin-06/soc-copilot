"""Stage 4 Detect: Sigma-compatible YAML rule engine, per-user/service behaviour
baselines, and payment-system fraud signal detectors.
"""
from __future__ import annotations

import datetime as dt
import operator
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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


SEVERITIES = ("low", "medium", "high", "critical")
MODIFIERS = {None, "in", "contains", "startswith", "endswith", "re", "gte", "gt", "lte", "lt"}
EVENT_FIELDS = set(NormalizedEvent.__dataclass_fields__) | {"actor"}
CONDITION = re.compile(
    r"^selection(?P<filter> and not filter)?"
    r"(?: ?\| ?count\(\) by (?P<by>[A-Za-z0-9_.]+) ?(?P<op>>=|>|==) ?(?P<n>\d+))?$"
)
OPS = {">=": operator.ge, ">": operator.gt, "==": operator.eq}
MAX_WINDOW_EVENTS = 500  # per rule and group; enough evidence for a report, bounded under a flood


class RuleError(ValueError):
    """A rule file uses syntax this engine does not support. Raised at load time so a typo
    cannot silently turn a rule into one that never fires."""


def _parse_timeframe(tf: Any) -> float:
    m = re.match(r"^\s*(\d+)\s*([smhd])\s*$", str(tf).lower())
    if not m or int(m.group(1)) == 0:
        raise RuleError(f"unsupported timeframe {tf!r} (use e.g. 30s, 5m, 2h, 1d)")
    return float(int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)])


def _check_field(path: str) -> None:
    head = path.split(".", 1)[0]
    if head not in EVENT_FIELDS:
        raise RuleError(f"unknown field {path!r}")
    if "." in path and head not in ("enrichment", "details"):
        raise RuleError(f"only enrichment.* and details.* can be nested, got {path!r}")


def _compile_block(block: Any, name: str) -> list[tuple[str, str | None, Any]]:
    if not isinstance(block, dict) or not block:
        raise RuleError(f"detection.{name} must be a non-empty mapping")
    out: list[tuple[str, str | None, Any]] = []
    for raw_key, expected in block.items():
        path, _, mod = str(raw_key).partition("|")
        if (mod or None) not in MODIFIERS:
            raise RuleError(f"unsupported modifier {mod!r} in {raw_key!r}")
        _check_field(path)
        if mod == "re":
            try:
                expected = re.compile(str(expected))
            except re.error as e:
                raise RuleError(f"bad regex in {raw_key!r}: {e}") from e
        out.append((path, mod or None, expected))
    return out


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
        return bool(expected.search(str(actual)))
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


def _match_block(ev: NormalizedEvent, block: list[tuple[str, str | None, Any]]) -> bool:
    return all(_match_value(_get_field(ev, path), expected, mod) for path, mod, expected in block)


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
    selection: list[tuple[str, str | None, Any]]
    filter_block: list[tuple[str, str | None, Any]] | None
    timeframe_s: float | None
    agg_group_by: str | None
    agg_op: str | None
    agg_threshold: int | None

    @classmethod
    def from_yaml(cls, data: dict[str, Any]) -> "SigmaRule":
        if not isinstance(data, dict) or not data.get("id"):
            raise RuleError("a rule must be a mapping with an id")
        level = str(data.get("level", "medium")).lower()
        if level not in SEVERITIES:
            raise RuleError(f"unsupported level {level!r}")
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

        det = data.get("detection")
        if not isinstance(det, dict):
            raise RuleError("missing detection block")
        cond = " ".join(str(det.get("condition", "selection")).split())
        m = CONDITION.match(cond)
        if not m:
            raise RuleError(f"unsupported condition {cond!r}; expected 'selection [and not filter] [| count() by FIELD >= N]'")
        if bool(m["filter"]) != ("filter" in det):
            raise RuleError("the condition and the filter block disagree")
        if bool(m["by"]) != ("timeframe" in det):
            raise RuleError("count() aggregation and timeframe must be used together")
        if m["by"]:
            _check_field(m["by"])

        return cls(
            id=str(data["id"]),
            title=str(data.get("title", "Unnamed Sigma Rule")),
            description=str(data.get("description", "")),
            level=level,
            tags=tags,
            tactics=tactics or ["discovery"],
            techniques=techniques or ["T1078"],
            domain=domain,
            selection=_compile_block(det.get("selection"), "selection"),
            filter_block=_compile_block(det["filter"], "filter") if m["filter"] else None,
            timeframe_s=_parse_timeframe(det["timeframe"]) if m["by"] else None,
            agg_group_by=m["by"],
            agg_op=m["op"],
            agg_threshold=int(m["n"]) if m["n"] else None,
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

    def evaluate(self, ev: NormalizedEvent) -> list[Alert]:
        alerts: list[Alert] = []
        crit = int(ev.enrichment.get("asset_criticality", 2))

        # 1. Off-hours staff authentication baseline (usual hours are local to the staff member)
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
                tz_name = str(ev.enrichment.get("staff_timezone") or "UTC")
                try:
                    tz = ZoneInfo(tz_name)
                except (ZoneInfoNotFoundError, ValueError):
                    tz, tz_name = dt.timezone.utc, "UTC"
                hour = dt.datetime.fromtimestamp(ev.timestamp, tz=tz).hour
                if hour < start_h or hour >= end_h:
                    alerts.append(
                        Alert(
                            alert_id=f"ALT-{ev.event_id}-BASELINE-OFFHOURS-001",
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
                            summary=f"Staff user {ev.user} logged in at {hour:02d}:00 {tz_name} outside usual window {start_h:02d}:00-{end_h:02d}:00.",
                        )
                    )

        # 2. Impossible travel baseline
        if ev.enrichment.get("impossible_travel"):
            speed = ev.enrichment.get("travel_speed_kmh", 0.0)
            prev_c = ev.enrichment.get("previous_country", "IN")
            cur_c = ev.enrichment.get("geo_country", "UNKNOWN")
            alerts.append(
                Alert(
                    alert_id=f"ALT-{ev.event_id}-BASELINE-GEO-002",
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
                    alert_id=f"ALT-{ev.event_id}-BASELINE-EGRESS-003",
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
                        alert_id=f"ALT-{ev.event_id}-FRAUD-ATO-DEVICE-001",
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
                        alert_id=f"ALT-{ev.event_id}-FRAUD-DRAIN-002",
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
        self._timeframes = {r.id: r.timeframe_s for r in self.rules if r.timeframe_s}
        self._window_buffers: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        self._window_fired: set[tuple[str, str, int]] = set()
        self._evaluated = 0

    def _load_rules(self) -> list[SigmaRule]:
        loaded: list[SigmaRule] = []
        if not self.rules_dir.exists():
            raise RuleError(f"rules directory {self.rules_dir} does not exist")
        for p in sorted(self.rules_dir.glob("*.yml")):
            try:
                rule = SigmaRule.from_yaml(yaml.safe_load(p.read_text(encoding="utf-8")))
            except (RuleError, yaml.YAMLError) as e:
                raise RuleError(f"{p.name}: {e}") from e
            if any(r.id == rule.id for r in loaded):
                raise RuleError(f"{p.name}: duplicate rule id {rule.id}")
            loaded.append(rule)
        return loaded

    def reset(self) -> None:
        self._window_buffers.clear()
        self._window_fired.clear()
        self._evaluated = 0

    def _sweep(self, now: float) -> None:
        """Forget windows that have gone quiet, so per-IP / per-actor state does not grow forever."""
        for key in [k for k, buf in self._window_buffers.items() if not buf or buf[-1].timestamp < now - self._timeframes[k[0]]]:
            del self._window_buffers[key]
        self._window_fired = {k for k in self._window_fired if k[2] >= int(now // self._timeframes[k[0]]) - 1}

    def evaluate_event(self, ev: NormalizedEvent) -> list[Alert]:
        self._evaluated += 1
        if self._evaluated % 1000 == 0:
            self._sweep(ev.timestamp)
        out: list[Alert] = []
        crit = int(ev.enrichment.get("asset_criticality", 2))

        for rule in self.rules:
            if not rule.matches_event(ev):
                continue

            if rule.agg_group_by:
                group = _get_field(ev, rule.agg_group_by)
                if group is None or group == "":
                    continue  # pooling events without a key would merge unrelated actors into one count
                group_val = str(group)
                key = (rule.id, group_val)
                buf = self._window_buffers[key]
                buf.append(ev)
                cutoff = ev.timestamp - rule.timeframe_s
                buf[:] = [x for x in buf if x.timestamp >= cutoff][-MAX_WINDOW_EVENTS:]
                bucket_id = int(ev.timestamp // rule.timeframe_s)
                if OPS[rule.agg_op](len(buf), rule.agg_threshold) and (rule.id, group_val, bucket_id) not in self._window_fired:
                    self._window_fired.add((rule.id, group_val, bucket_id))
                    ent_set: list[str] = []
                    for item in buf:
                        for e in item.entities:
                            if e not in ent_set:
                                ent_set.append(e)
                    money = sum(x.amount for x in buf if x.event_category == "payment")
                    out.append(
                        Alert(
                            alert_id=f"ALT-{ev.event_id}-{rule.id}",
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
                        alert_id=f"ALT-{ev.event_id}-{rule.id}",
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

        out.extend(self.baseline.evaluate(ev))
        return out
