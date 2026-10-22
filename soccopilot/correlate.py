"""Stage 5 Correlate: Build an entity graph linking alerts across tools, form connected
incidents ordered along the MITRE ATT&CK tactic sequence, compute composite risk scores
(joining security and fraud signals), and tune rule weights from analyst feedback.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

from .detect import TACTIC_ORDER, Alert
from .normalize import NormalizedEvent

SHARED_INFRA_HOSTS = {
    "auth-service-prod",
    "core-payments-engine",
    "prod-api-gw-01",
    "aws.cloudtrail",
    "iam.amazonaws.com",
    "sts.amazonaws.com",
    "s3.amazonaws.com",
}

SEVERITY_BASE = {"low": 12.0, "medium": 24.0, "high": 38.0, "critical": 52.0}


@dataclass
class GraphEdge:
    source: str
    target: str
    shared_entity: str
    Relation: str = "shares_entity"


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str
    risk_score: float
    status: str                         # open | triaged | contained | false_positive | suppressed
    created_at: float
    updated_at: float
    tactics: list[str]
    techniques: list[str]
    domains: list[str]                  # ["security"], ["fraud"], or ["security", "fraud"]
    security_fraud_joined: bool
    money_at_risk: float
    max_asset_criticality: int
    entities: list[str]
    alert_ids: list[str]
    event_ids: list[str]
    alerts: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    entity_graph: dict[str, Any] = field(default_factory=dict)
    score_breakdown: dict[str, float] = field(default_factory=dict)
    feedback: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _correlation_entities(entities: list[str]) -> set[str]:
    """Return strong linking entities (exclude shared multi-tenant service hostnames)."""
    out: set[str] = set()
    for ent in entities:
        if ent.startswith("host:"):
            h = ent.split(":", 1)[1]
            if h in SHARED_INFRA_HOSTS:
                continue
        out.add(ent)
    return out


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _anchor(entity: str) -> bool:
    """Entities specific enough to pull surrounding context events into an incident."""
    if entity.startswith(("customer:", "user:", "account:", "cloud_key:")):
        return True
    return entity.startswith("ip:") and _is_public_ip(entity[3:])


def _tactic_rank(tactics: list[str]) -> int:
    if not tactics:
        return len(TACTIC_ORDER)
    ranks = [TACTIC_ORDER.index(t) for t in tactics if t in TACTIC_ORDER]
    return min(ranks) if ranks else len(TACTIC_ORDER)


class Correlator:
    """Groups related alerts into incidents via an entity graph, orders timelines by
    ATT&CK tactic sequence, scores risk, and tunes weights from analyst feedback.
    """

    def __init__(
        self,
        time_window_s: float = 3600.0,
        security_fraud_bonus: float = 18.0,
        min_incident_score: float = 25.0,
        suppressed_ips: set[str] | list[str] | None = None,
        suppressed_users: set[str] | list[str] | None = None,
        severity_weights: dict[str, float] | None = None,
        tactic_bonus_per_stage: float = 7.5,
        asset_criticality_weight: float = 3.0,
        money_at_risk_scale: float = 10000.0,
        money_at_risk_max_bonus: float = 20.0,
    ):
        self.time_window_s = time_window_s
        self.security_fraud_bonus = security_fraud_bonus
        self.min_incident_score = min_incident_score
        # an explicitly empty list in policy means "suppress nothing", not "use the demo defaults"
        self.suppressed_ips = set(suppressed_ips) if suppressed_ips is not None else {"10.250.0.99"}
        self.suppressed_users = set(suppressed_users) if suppressed_users is not None else {"svc-vuln-scanner"}
        self.severity_weights = {**SEVERITY_BASE, **(severity_weights or {})}
        self.tactic_bonus_per_stage = tactic_bonus_per_stage
        self.asset_criticality_weight = asset_criticality_weight
        self.money_at_risk_scale = money_at_risk_scale
        self.money_at_risk_max_bonus = money_at_risk_max_bonus
        self.rule_weights: dict[str, float] = defaultdict(lambda: 1.0)
        self.feedback_history: list[dict[str, Any]] = []

    def is_suppressed(self, alert: Alert) -> bool:
        if alert.source_ip and alert.source_ip in self.suppressed_ips:
            return True
        if alert.user and alert.user in self.suppressed_users:
            return True
        # Feedback may silence a noisy low/medium rule, but never a high or critical one:
        # a few false-positive clicks must not be able to switch off ransomware or fraud detection.
        return alert.severity in ("low", "medium") and self.rule_weights[alert.rule_id] <= 0.2

    def score_group(
        self,
        alerts: list[Alert],
        events: list[NormalizedEvent],
    ) -> tuple[float, str, dict[str, float]]:
        weighted_vals = [
            self.severity_weights.get(a.severity, 20.0) * self.rule_weights[a.rule_id]
            for a in alerts
        ]
        max_sev = max(weighted_vals) if weighted_vals else 0.0
        extra_alerts_bonus = min(14.0, 4.0 * math.log1p(max(0, len(alerts) - 1)))
        rule_component = round(max_sev + extra_alerts_bonus, 2)

        distinct_tactics = {t for a in alerts for t in a.tactics}
        tactic_component = round(max(0, len(distinct_tactics) - 1) * self.tactic_bonus_per_stage, 2)

        max_crit = max((a.asset_criticality for a in alerts), default=2)
        asset_component = round(max_crit * self.asset_criticality_weight, 2)

        # Sum unique payment amounts across correlated events
        payment_events = {
            e.event_id: e.amount
            for e in events
            if e.event_category == "payment" and e.amount > 0
        }
        money_at_risk = sum(payment_events.values()) if payment_events else max((a.money_at_risk for a in alerts), default=0.0)
        # one point per `money_at_risk_scale` rupees, capped
        money_component = round(min(self.money_at_risk_max_bonus, money_at_risk / self.money_at_risk_scale), 2) if money_at_risk > 0 else 0.0

        domains = {a.domain for a in alerts}
        # Also detect when security alerts link to payment/account_change events for the same customer
        has_security = "security" in domains
        has_fraud = "fraud" in domains or any(e.source == "payments" and e.amount > 0 for e in events)
        cross_domain_bonus = self.security_fraud_bonus if (has_security and has_fraud) else 0.0

        raw_score = rule_component + tactic_component + asset_component + money_component + cross_domain_bonus
        final_score = round(min(100.0, max(0.0, raw_score)), 1)

        if final_score >= 80.0:
            sev = "critical"
        elif final_score >= 60.0:
            sev = "high"
        elif final_score >= 38.0:
            sev = "medium"
        else:
            sev = "low"

        breakdown = {
            "rule_severity": rule_component,
            "tactic_diversity": tactic_component,
            "asset_criticality": asset_component,
            "money_at_risk_bonus": money_component,
            "security_fraud_bonus": cross_domain_bonus,
            "total": final_score,
        }
        return final_score, sev, breakdown

    def correlate(
        self,
        alerts: list[Alert],
        all_events: dict[str, NormalizedEvent] | list[NormalizedEvent],
        previous: dict[str, Incident] | None = None,
    ) -> list[Incident]:
        """Group alerts into incidents. Pass the previous incidents so that IDs, analyst
        status and feedback survive re-correlation when new alerts arrive."""
        if isinstance(all_events, list):
            event_map = {e.event_id: e for e in all_events}
        else:
            event_map = dict(all_events)

        active_alerts = [a for a in alerts if not self.is_suppressed(a)]
        if not active_alerts:
            return []

        # Two alerts are linked when they share a strong entity within the time window.
        # Per entity, sorting by time and joining neighbours gives the same components as
        # comparing every pair, in O(n log n) instead of O(n^2).
        n = len(active_alerts)
        parent = list(range(n))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        by_entity: dict[str, list[int]] = defaultdict(list)
        for i, a in enumerate(active_alerts):
            for ent in _correlation_entities(a.entities):
                by_entity[ent].append(i)
        for members in by_entity.values():
            members.sort(key=lambda i: active_alerts[i].timestamp)
            for a, b in zip(members, members[1:]):
                if active_alerts[b].timestamp - active_alerts[a].timestamp <= self.time_window_s:
                    parent[find(a)] = find(b)
        groups: dict[int, list[int]] = defaultdict(list)
        for i in range(n):
            groups[find(i)].append(i)
        components = list(groups.values())

        events_by_anchor: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for ev in event_map.values():
            for ent in _correlation_entities(ev.entities):
                if _anchor(ent):
                    events_by_anchor[ent].append(ev)

        incidents: list[Incident] = []
        for comp in components:
            comp_alerts = [active_alerts[i] for i in comp]
            # Order alerts along ATT&CK tactic sequence, then timestamp
            comp_alerts.sort(key=lambda a: (_tactic_rank(a.tactics), a.timestamp))

            # Collect all strong entities in this component
            strong_ents: set[str] = set()
            all_ents: list[str] = []
            for a in comp_alerts:
                strong_ents |= _correlation_entities(a.entities)
                for e in a.entities:
                    if e not in all_ents:
                        all_ents.append(e)

            min_ts = min(a.timestamp for a in comp_alerts) - 600.0
            max_ts = max(a.timestamp for a in comp_alerts) + 600.0

            # Pull alert events + related context events sharing a primary actor/account/IP in window
            ev_ids_set: set[str] = {eid for a in comp_alerts for eid in a.event_ids}
            for anchor in sorted(e for e in strong_ents if _anchor(e)):
                for ev in events_by_anchor.get(anchor, []):
                    if min_ts <= ev.timestamp <= max_ts and ev.event_id not in ev_ids_set:
                        ev_ids_set.add(ev.event_id)
                        for ent in ev.entities:
                            if ent not in all_ents:
                                all_ents.append(ent)

            comp_events = sorted(
                [event_map[eid] for eid in ev_ids_set if eid in event_map],
                key=lambda e: e.timestamp,
            )

            score, sev, breakdown = self.score_group(comp_alerts, comp_events)
            if score < self.min_incident_score:
                continue

            # Ordered tactics & techniques
            tactics_ordered: list[str] = []
            for t in TACTIC_ORDER:
                if any(t in a.tactics for a in comp_alerts):
                    tactics_ordered.append(t)
            techniques: list[str] = []
            for a in comp_alerts:
                for tech in a.techniques:
                    if tech not in techniques:
                        techniques.append(tech)

            payment_totals = {
                e.event_id: e.amount
                for e in comp_events
                if e.event_category == "payment" and e.amount > 0
            }
            money_at_risk = sum(payment_totals.values()) if payment_totals else max((a.money_at_risk for a in comp_alerts), default=0.0)

            domains = sorted({a.domain for a in comp_alerts} | ({"fraud"} if money_at_risk > 0 else set()))
            sec_fraud_joined = "security" in domains and "fraud" in domains

            # Build entity graph representation (nodes: entities + alerts; edges: relationships)
            nodes: list[dict[str, Any]] = []
            edges: list[dict[str, Any]] = []
            seen_nodes: set[str] = set()
            for ent in all_ents:
                kind, val = ent.split(":", 1) if ":" in ent else ("entity", ent)
                nodes.append({"id": ent, "label": val, "type": kind})
                seen_nodes.add(ent)
            for a in comp_alerts:
                aid = a.alert_id
                nodes.append({"id": aid, "label": a.title, "type": "alert", "severity": a.severity, "domain": a.domain})
                seen_nodes.add(aid)
                for ent in a.entities:
                    if ent in seen_nodes:
                        edges.append({"source": aid, "target": ent, "relation": "involves"})

            # Build ATT&CK storyline timeline
            event_tactic_map: dict[str, tuple[str, str]] = {}
            for a in comp_alerts:
                tac = a.tactics[0] if a.tactics else "discovery"
                tech = a.techniques[0] if a.techniques else "T1078"
                for eid in a.event_ids:
                    event_tactic_map.setdefault(eid, (tac, tech))

            timeline: list[dict[str, Any]] = []
            for ev in comp_events:
                tac, tech = event_tactic_map.get(
                    ev.event_id,
                    ("impact" if ev.event_category == "payment" else "persistence" if ev.event_category == "account_change" else "initial_access", "T1078"),
                )
                timeline.append(
                    {
                        "event_id": ev.event_id,
                        "timestamp": ev.timestamp,
                        "iso_timestamp": ev.iso_timestamp,
                        "source": ev.source,
                        "category": ev.event_category,
                        "action": ev.event_action,
                        "outcome": ev.event_outcome,
                        "tactic": tac,
                        "technique": tech,
                        "tactic_rank": TACTIC_ORDER.index(tac) if tac in TACTIC_ORDER else 99,
                        "actor": ev.customer_id or ev.user or ev.source_ip,
                        "source_ip": ev.source_ip,
                        "host": ev.host,
                        "amount": ev.amount,
                        "message": ev.message,
                    }
                )
            timeline.sort(key=lambda item: (item["timestamp"], item["tactic_rank"]))

            # Construct concise human-readable incident title
            primary_actor = next(
                (e.split(":", 1)[1] for e in all_ents if e.startswith(("customer:", "user:"))),
                comp_alerts[0].source_ip or comp_alerts[0].host or "Unknown",
            )
            # Titles state what was observed; whether it is account takeover is the analyst's call.
            if sec_fraud_joined:
                inc_title = f"Security alerts linked to ₹{money_at_risk:,.0f} in payments ({primary_actor})"
            elif len(comp_alerts) > 1:
                inc_title = f"{comp_alerts[0].title} → {comp_alerts[-1].title} ({primary_actor})"
            else:
                inc_title = f"{comp_alerts[0].title} ({primary_actor})"

            first = min(comp_alerts, key=lambda a: (a.timestamp, a.alert_id))
            incidents.append(
                Incident(
                    incident_id="INC-" + hashlib.sha256(first.alert_id.encode()).hexdigest()[:10].upper(),
                    title=inc_title,
                    severity=sev,
                    risk_score=score,
                    status="open",
                    created_at=min(a.timestamp for a in comp_alerts),
                    updated_at=max(a.timestamp for a in comp_alerts),
                    tactics=tactics_ordered,
                    techniques=techniques,
                    domains=domains,
                    security_fraud_joined=sec_fraud_joined,
                    money_at_risk=round(money_at_risk, 2),
                    max_asset_criticality=max((a.asset_criticality for a in comp_alerts), default=2),
                    entities=all_ents,
                    alert_ids=[a.alert_id for a in comp_alerts],
                    event_ids=[e.event_id for e in comp_events],
                    alerts=[a.to_dict() for a in comp_alerts],
                    timeline=timeline,
                    entity_graph={"nodes": nodes, "edges": edges},
                    score_breakdown=breakdown,
                )
            )

        incidents.sort(key=lambda inc: (-inc.risk_score, inc.created_at))
        if previous:
            self._carry_over(incidents, previous)
        return incidents

    @staticmethod
    def _carry_over(incidents: list[Incident], previous: dict[str, Incident]) -> None:
        """Keep the ID, status and feedback of the earlier incident that shares the most alerts,
        so approvals, reports and analyst verdicts stay attached to the right case."""
        claimed: set[str] = set()
        for inc in incidents:
            alert_ids = set(inc.alert_ids)
            best = max(
                (p for p in previous.values() if p.incident_id not in claimed and alert_ids & set(p.alert_ids)),
                key=lambda p: (len(alert_ids & set(p.alert_ids)), -p.created_at),
                default=None,
            )
            if best is None:
                continue
            claimed.add(best.incident_id)
            inc.incident_id = best.incident_id
            inc.feedback = list(best.feedback)
            grew = not alert_ids <= set(best.alert_ids)
            # new alerts reopen a case that was closed as a false positive
            inc.status = "open" if grew and best.status == "false_positive" else best.status

    def record_feedback(
        self,
        incident: Incident,
        verdict: str,  # "true_positive" | "false_positive"
        reason: str,
        analyst: str = "soc.analyst",
    ) -> dict[str, Any]:
        """Adjust rule weights based on analyst feedback and recompute the incident risk score."""
        if verdict not in ("true_positive", "false_positive"):
            raise ValueError("verdict must be 'true_positive' or 'false_positive'")
        delta = 0.15 if verdict == "true_positive" else -0.35
        updated_rules: dict[str, float] = {}
        for a in incident.alerts:
            rid = a["rule_id"]
            new_w = round(min(2.0, max(0.1, self.rule_weights[rid] + delta)), 2)
            self.rule_weights[rid] = new_w
            updated_rules[rid] = new_w

        fb_entry = {
            "incident_id": incident.incident_id,
            "verdict": verdict,
            "reason": reason,
            "analyst": analyst,
            "updated_rule_weights": updated_rules,
        }
        incident.feedback.append(fb_entry)
        self.feedback_history.append(fb_entry)
        if verdict == "false_positive":
            incident.status = "false_positive"
            incident.risk_score = round(max(0.0, incident.risk_score * 0.45), 1)
        else:
            incident.risk_score = round(min(100.0, incident.risk_score * 1.08), 1)
        return fb_entry
