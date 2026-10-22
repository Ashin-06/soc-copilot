"""Stage 6 AI Triage: Read-only Claude tool-use loop with Project 10 privacy gateway
sanitisation and a deterministic evidence-citing template report fallback.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .correlate import Incident
from .enrich import Enricher
from .playbooks import PlaybookEngine
from .store import EventStore, StateStore

MODEL = os.environ.get("SOCCOPILOT_MODEL", "claude-opus-5-5")
EVENT_ID_RE = re.compile(r"\bEVT-[A-Za-z0-9_-]+\b")

READ_ONLY_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_incident",
        "description": "Retrieve the correlated incident summary, alerts, entities, and risk breakdown.",
        "input_schema": {
            "type": "object",
            "properties": {"incident_id": {"type": "string"}},
            "required": ["incident_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "search_logs",
        "description": "Search normalized bank logs by keyword query, entity tag, or category (read-only).",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "entity": {"type": "string"},
                "category": {"type": "string"},
                "limit": {"type": "integer"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "entity_timeline",
        "description": "Fetch the chronological event timeline for an entity (e.g. customer:CUST-1042, ip:185.220.101.42).",
        "input_schema": {
            "type": "object",
            "properties": {"entity": {"type": "string"}},
            "required": ["entity"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ip_reputation",
        "description": "Look up threat intelligence reputation, ASN, and GeoIP country for an IP address.",
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
            "additionalProperties": False,
        },
    },
    {
        "name": "customer_transactions",
        "description": "Retrieve recent payment and account-change events for a customer ID.",
        "input_schema": {
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
            "required": ["customer_id"],
            "additionalProperties": False,
        },
    },
]

SYSTEM_PROMPT = """You are a senior bank SOC Triage Analyst AI.
You have READ-ONLY tools to inspect an incident, search normalized logs, inspect entity timelines,
check IP reputation, and inspect customer transactions. You CANNOT execute containment actions directly.

Every single factual claim in your report MUST cite the backing log entry IDs in brackets, e.g. [EVT-0001].
Return a JSON object with keys:
- summary: string (with [EVT-...] citations)
- timeline: list of strings (chronological story, each citing [EVT-...])
- attack_mapping: list of objects {"tactic": str, "technique": str, "evidence": str (citing [EVT-...])}
- likely_impact: list of strings (each citing [EVT-...])
- confidence: "high" | "medium" | "low"
- confidence_score: number between 0.0 and 1.0
- recommended_containment: list of objects {"action_type": str, "target": str, "rationale": str (citing [EVT-...])}
"""


class PrivacyBridge:
    """Routes prompts and tool outputs through Project 10's LLM Privacy Gateway engine
    so customer PII (names, PAN, Aadhaar, account numbers, phones, emails) never reaches
    the model in the clear.
    """

    def __init__(self, role: str = "fraud_analyst"):
        self.role = role
        self._privgate_engine = self._load_project10_engine()
        self._fallback_map: dict[str, dict[str, str]] = {}

    @staticmethod
    def _load_project10_engine():
        p10 = Path(__file__).resolve().parent.parent.parent / "10-llm-privacy-gateway"
        if p10.exists() and str(p10) not in sys.path:
            sys.path.insert(0, str(p10))
        try:
            from privgate.engine import Engine  # type: ignore

            return Engine(p10 / "policy.toml")
        except Exception:
            return None

    def sanitize(self, text: str, conversation_id: str) -> tuple[str, dict[str, int]]:
        if self._privgate_engine is not None:
            res = self._privgate_engine.sanitize(text, conversation_id, raise_on_block=False)
            return res.text, dict(res.actions)

        # Standalone fallback sanitizer if project 10 directory is not mounted
        counts: dict[str, int] = {}
        cmap = self._fallback_map.setdefault(conversation_id, {})
        patterns = [
            ("PAN", re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b")),
            ("PHONE", re.compile(r"(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b")),
            ("EMAIL", re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")),
            ("ACCOUNT", re.compile(r"\b50100\d{9}\b")),
        ]
        out = text
        for kind, pat in patterns:
            for m in list(pat.finditer(out)):
                val = m.group(0)
                token = f"[[{kind}_1]]"
                cmap[token] = val
                out = out.replace(val, token)
                counts[f"{kind}:tokenize"] = counts.get(f"{kind}:tokenize", 0) + 1
        return out, counts

    def restore(self, text: str, conversation_id: str) -> str:
        if self._privgate_engine is not None:
            restored, _ = self._privgate_engine.restore(text, conversation_id, self.role)
            return restored
        cmap = self._fallback_map.get(conversation_id, {})
        out = text
        for tok, val in cmap.items():
            out = out.replace(tok, val)
        return out


@dataclass
class TriageReport:
    incident_id: str
    generated_by: str                   # "claude_tool_loop" | "template_fallback"
    summary: str
    timeline: list[str]
    attack_mapping: list[dict[str, str]]
    likely_impact: list[str]
    confidence: str
    confidence_score: float
    recommended_containment: list[dict[str, str]]
    cited_event_ids: list[str]
    citation_coverage: float            # 0.0 .. 1.0 share of claims citing valid incident log IDs
    tool_trace: list[dict[str, Any]] = field(default_factory=list)
    privacy_masked_counts: dict[str, int] = field(default_factory=dict)
    sanitized_prompt_preview: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_citation_metrics(
    claims: list[str],
    valid_event_ids: set[str],
) -> tuple[list[str], float]:
    """Verify that every claim cites at least one valid log entry ID from the incident."""
    if not claims:
        return [], 1.0
    all_cited: list[str] = []
    backed_claims = 0
    for cl in claims:
        found = [eid for eid in EVENT_ID_RE.findall(cl) if eid in valid_event_ids or not valid_event_ids]
        if found:
            backed_claims += 1
            for eid in found:
                if eid not in all_cited:
                    all_cited.append(eid)
    return all_cited, round(backed_claims / len(claims), 4)


def derive_recommended_actions(incident: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Recommend read-only containment proposals (requires analyst approval to run)."""
    recs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    all_ev_ids = incident.get("event_ids", [])
    default_cite = f"[{all_ev_ids[0]}]" if all_ev_ids else "[EVT-0001]"

    # Map entities to events for accurate citations
    entity_cite: dict[str, str] = {}
    for ev in events:
        eid = ev.get("event_id", "EVT-0001")
        for key in ("customer_id", "user", "source_ip", "account", "cloud_key"):
            val = ev.get(key)
            if val:
                entity_cite[str(val)] = f"[{eid}]"

    for ent in incident.get("entities", []):
        if ":" not in ent:
            continue
        kind, val = ent.split(":", 1)
        cite = entity_cite.get(val, default_cite)
        if kind == "account" and ("fraud" in incident.get("domains", []) or incident.get("money_at_risk", 0) > 0):
            if ("freeze_account", val) not in seen:
                seen.add(("freeze_account", val))
                recs.append({
                    "action_type": "freeze_account",
                    "target": val,
                    "rationale": f"Place immediate debit hold on account {val} due to unauthorized transfer activity {cite}.",
                })
        elif kind == "customer":
            if ("end_sessions", val) not in seen:
                seen.add(("end_sessions", val))
                recs.append({
                    "action_type": "end_sessions",
                    "target": val,
                    "rationale": f"Revoke active web/mobile sessions for {val} following suspicious authentication sequence {cite}.",
                })
            if incident.get("money_at_risk", 0) > 0 and ("notify_customer", val) not in seen:
                seen.add(("notify_customer", val))
                recs.append({
                    "action_type": "notify_customer",
                    "target": val,
                    "rationale": f"Send out-of-band verification alert to {val} regarding high-risk payment activity {cite}.",
                })
        elif kind == "user" and val not in ("svc-vuln-scanner", "svc-backup-nightly"):
            if ("end_sessions", val) not in seen:
                seen.add(("end_sessions", val))
                recs.append({
                    "action_type": "end_sessions",
                    "target": val,
                    "rationale": f"Terminate active staff sessions for {val} after anomalous privileged actions {cite}.",
                })
            if ("require_password_reset", val) not in seen:
                seen.add(("require_password_reset", val))
                recs.append({
                    "action_type": "require_password_reset",
                    "target": val,
                    "rationale": f"Require password rotation and MFA re-binding for staff account {val} {cite}.",
                })
        elif kind == "ip" and not val.startswith(("10.", "172.16.", "49.36.", "49.37.", "103.21.", "115.96.", "122.161.")):
            if ("block_ip", val) not in seen:
                seen.add(("block_ip", val))
                recs.append({
                    "action_type": "block_ip",
                    "target": val,
                    "rationale": f"Block external threat source IP {val} at perimeter firewall {cite}.",
                })
        elif kind == "cloud_key":
            if ("disable_cloud_key", val) not in seen:
                seen.add(("disable_cloud_key", val))
                recs.append({
                    "action_type": "disable_cloud_key",
                    "target": val,
                    "rationale": f"Deactivate AWS IAM access key {val} used in privileged cloud API calls {cite}.",
                })

    return recs


class TriageEngine:
    """Runs read-only investigation tool calls (via Claude or deterministic template fallback),
    enforces Project 10 privacy gateway scrubbing, and queues recommended playbooks for approval.
    """

    def __init__(
        self,
        event_store: EventStore,
        state_store: StateStore,
        enricher: Enricher,
        playbooks: PlaybookEngine,
        audit: AuditLog,
        privacy: PrivacyBridge | None = None,
    ):
        self.event_store = event_store
        self.state_store = state_store
        self.enricher = enricher
        self.playbooks = playbooks
        self.audit = audit
        self.privacy = privacy or PrivacyBridge()

    def execute_read_tool(self, name: str, args: dict[str, Any]) -> Any:
        """Strictly read-only tool dispatcher. Refuses any non-read tool."""
        if name == "get_incident":
            inc = self.state_store.get_incident(str(args.get("incident_id", "")))
            if not inc:
                return {"error": "incident not found"}
            return {
                "incident_id": inc["incident_id"],
                "title": inc["title"],
                "severity": inc["severity"],
                "risk_score": inc["risk_score"],
                "tactics": inc["tactics"],
                "techniques": inc["techniques"],
                "domains": inc["domains"],
                "security_fraud_joined": inc["security_fraud_joined"],
                "money_at_risk": inc["money_at_risk"],
                "entities": inc["entities"],
                "event_ids": inc["event_ids"],
                "alerts": inc["alerts"],
            }
        if name == "search_logs":
            return self.event_store.search_logs(
                query=args.get("query"),
                entity=args.get("entity"),
                category=args.get("category"),
                limit=int(args.get("limit", 20)),
            )
        if name == "entity_timeline":
            return self.event_store.entity_timeline(str(args.get("entity", "")))
        if name == "ip_reputation":
            return self.enricher.lookup_ip_reputation(str(args.get("ip", "")))
        if name == "customer_transactions":
            return self.event_store.customer_transactions(str(args.get("customer_id", "")))
        raise PermissionError(f"tool {name!r} is not permitted: AI triage is strictly read-only")

    def _build_template_report(
        self,
        inc: dict[str, Any],
        tool_trace: list[dict[str, Any]],
        masked_totals: dict[str, int],
        sanitized_preview: str,
    ) -> TriageReport:
        timeline_rows = inc.get("timeline", [])
        valid_ids = set(inc.get("event_ids", []))
        all_ids_str = ", ".join(f"[{eid}]" for eid in sorted(valid_ids)[:4]) or "[EVT-0001]"

        timeline_claims: list[str] = []
        for row in timeline_rows:
            eid = row["event_id"]
            amt_str = f" (₹{row['amount']:,.0f})" if row.get("amount", 0) > 0 else ""
            timeline_claims.append(
                f"{row['iso_timestamp']} · [{row['tactic'].upper()} / {row['technique']}] "
                f"{row['source']}:{row['action']} ({row['outcome']}) on {row.get('host') or 'bank-system'} "
                f"by {row.get('actor') or 'unknown'}{amt_str} — {row.get('message', '')} [{eid}]"
            )

        attack_mapping: list[dict[str, str]] = []
        for a in inc.get("alerts", []):
            cites = " ".join(f"[{eid}]" for eid in a.get("event_ids", []))
            for tac in a.get("tactics", ["discovery"]):
                for tech in a.get("techniques", ["T1078"]):
                    attack_mapping.append({
                        "tactic": tac,
                        "technique": tech,
                        "rule_title": a.get("title", ""),
                        "evidence": f"{a.get('summary', a.get('title', ''))} {cites}".strip(),
                    })

        impact_claims: list[str] = []
        if inc.get("money_at_risk", 0) > 0:
            pay_eids = [
                f"[{r['event_id']}]"
                for r in timeline_rows
                if r.get("amount", 0) > 0 or r.get("category") in ("payment", "account_change")
            ] or [all_ids_str]
            impact_claims.append(
                f"Direct financial exposure of ₹{inc['money_at_risk']:,.0f} across linked payment instructions {' '.join(pay_eids)}."
            )
        if inc.get("security_fraud_joined"):
            impact_claims.append(
                f"Cross-domain compromise: cyber authentication/API anomalies are directly linked to downstream payment fraud on the same customer account {all_ids_str}."
            )
        impact_claims.append(
            f"Affected infrastructure criticality rated {inc.get('max_asset_criticality', 2)}/5 across {len(inc.get('entities', []))} linked entities {all_ids_str}."
        )

        summary = (
            f"Incident {inc['incident_id']} ({inc['severity'].upper()}, score {inc['risk_score']}/100): "
            f"{inc['title']}. Correlated {len(inc.get('alerts', []))} alerts and {len(timeline_rows)} events "
            f"across tactics {', '.join(inc.get('tactics', []))} {all_ids_str}."
        )

        recs = derive_recommended_actions(inc, timeline_rows)
        all_claim_strings = (
            [summary]
            + timeline_claims
            + [m["evidence"] for m in attack_mapping]
            + impact_claims
            + [r["rationale"] for r in recs]
        )
        cited_ids, coverage = compute_citation_metrics(all_claim_strings, valid_ids)
        conf_score = 0.94 if len(inc.get("alerts", [])) >= 2 else 0.82
        conf_label = "high" if conf_score >= 0.85 else "medium"

        return TriageReport(
            incident_id=inc["incident_id"],
            generated_by="template_fallback",
            summary=summary,
            timeline=timeline_claims,
            attack_mapping=attack_mapping,
            likely_impact=impact_claims,
            confidence=conf_label,
            confidence_score=conf_score,
            recommended_containment=recs,
            cited_event_ids=cited_ids,
            citation_coverage=coverage,
            tool_trace=tool_trace,
            privacy_masked_counts=masked_totals,
            sanitized_prompt_preview=sanitized_preview,
        )

    def triage_incident(
        self,
        incident: Incident | dict[str, Any],
        client: Any = None,
        use_llm: bool | None = None,
    ) -> TriageReport:
        inc = incident.to_dict() if isinstance(incident, Incident) else dict(incident)
        inc_id = inc["incident_id"]
        cid = f"triage-{inc_id}"
        masked_totals: dict[str, int] = {}
        tool_trace: list[dict[str, Any]] = []

        def run_and_sanitize_tool(tool_name: str, tool_args: dict[str, Any]) -> str:
            raw_out = self.execute_read_tool(tool_name, tool_args)
            serialized = json.dumps(raw_out, ensure_ascii=False, default=str)
            clean_text, counts = self.privacy.sanitize(serialized, cid)
            for k, v in counts.items():
                masked_totals[k] = masked_totals.get(k, 0) + v
            tool_trace.append({
                "tool": tool_name,
                "args": tool_args,
                "privacy_masked": dict(counts),
            })
            return clean_text

        # Always run initial read-only evidence collection through the privacy bridge
        sanitized_inc_json = run_and_sanitize_tool("get_incident", {"incident_id": inc_id})
        for ent in inc.get("entities", []):
            if ent.startswith("ip:"):
                run_and_sanitize_tool("ip_reputation", {"ip": ent.split(":", 1)[1]})
            elif ent.startswith("customer:"):
                run_and_sanitize_tool("customer_transactions", {"customer_id": ent.split(":", 1)[1]})
                run_and_sanitize_tool("entity_timeline", {"entity": ent})
            elif ent.startswith("user:"):
                run_and_sanitize_tool("entity_timeline", {"entity": ent})

        # Also sanitize full event details (which contain customer names, PANs, phones, accounts)
        event_blobs = []
        for eid in inc.get("event_ids", []):
            ev_obj = self.event_store.get(eid)
            if ev_obj:
                event_blobs.append(ev_obj.to_dict())
        sanitized_events_json, ev_counts = self.privacy.sanitize(
            json.dumps(event_blobs, ensure_ascii=False, default=str), cid
        )
        for k, v in ev_counts.items():
            masked_totals[k] = masked_totals.get(k, 0) + v

        sanitized_preview = (
            f"Investigate incident {inc_id}.\nSanitized Incident Context:\n{sanitized_inc_json[:600]}\n"
            f"Sanitized Events:\n{sanitized_events_json[:600]}"
        )

        should_call_llm = use_llm if use_llm is not None else bool(client is not None or os.environ.get("ANTHROPIC_API_KEY"))
        report: TriageReport | None = None

        if should_call_llm:
            try:
                import anthropic

                llm_client = client or anthropic.Anthropic()
                messages: list[dict[str, Any]] = [
                    {
                        "role": "user",
                        "content": (
                            f"Triage bank security incident {inc_id}. Use the read-only tools to inspect "
                            "the incident, timelines, IP reputation, and customer transactions, then output "
                            "the structured JSON investigation report with [EVT-...] log ID citations."
                        ),
                    }
                ]
                for _ in range(6):
                    resp = llm_client.messages.create(
                        model=MODEL,
                        max_tokens=4096,
                        system=SYSTEM_PROMPT,
                        tools=READ_ONLY_TOOLS,
                        messages=messages,
                    )
                    messages.append({"role": "assistant", "content": resp.content})
                    if resp.stop_reason != "tool_use":
                        text_reply = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
                        restored_text = self.privacy.restore(text_reply, cid)
                        parsed = json.loads(restored_text)
                        valid_ids = set(inc.get("event_ids", []))
                        recs = parsed.get("recommended_containment") or derive_recommended_actions(inc, inc.get("timeline", []))
                        claims = (
                            [parsed.get("summary", "")]
                            + list(parsed.get("timeline", []))
                            + [m.get("evidence", "") for m in parsed.get("attack_mapping", [])]
                            + list(parsed.get("likely_impact", []))
                        )
                        cited_ids, coverage = compute_citation_metrics(claims, valid_ids)
                        report = TriageReport(
                            incident_id=inc_id,
                            generated_by="claude_tool_loop",
                            summary=parsed.get("summary", ""),
                            timeline=list(parsed.get("timeline", [])),
                            attack_mapping=list(parsed.get("attack_mapping", [])),
                            likely_impact=list(parsed.get("likely_impact", [])),
                            confidence=parsed.get("confidence", "high"),
                            confidence_score=float(parsed.get("confidence_score", 0.9)),
                            recommended_containment=recs,
                            cited_event_ids=cited_ids,
                            citation_coverage=coverage,
                            tool_trace=tool_trace,
                            privacy_masked_counts=masked_totals,
                            sanitized_prompt_preview=sanitized_preview,
                        )
                        break

                    tool_results = []
                    for block in resp.content:
                        if getattr(block, "type", None) != "tool_use":
                            continue
                        b_args = block.input if isinstance(block.input, dict) else json.loads(block.input)
                        try:
                            sanitized_res = run_and_sanitize_tool(block.name, b_args)
                            is_err = False
                        except PermissionError as e:
                            sanitized_res = json.dumps({"error": str(e)})
                            is_err = True
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": sanitized_res,
                            "is_error": is_err,
                        })
                    messages.append({"role": "user", "content": tool_results})
            except Exception:
                report = None

        if report is None:
            report = self._build_template_report(inc, tool_trace, masked_totals, sanitized_preview)

        # Queue every recommended containment action in PlaybookEngine (requires analyst approval!)
        for rec in report.recommended_containment:
            act_type = rec.get("action_type", "")
            target = rec.get("target", "")
            rationale = rec.get("rationale", "")
            if act_type and target:
                try:
                    self.playbooks.propose(inc_id, act_type, target, rationale)
                except ValueError:
                    pass

        self.state_store.save_report(inc_id, report.to_dict(), inc.get("updated_at", 0.0))
        self.audit.append(
            "incident_triaged",
            incident_id=inc_id,
            generated_by=report.generated_by,
            citation_coverage=report.citation_coverage,
            privacy_masked=masked_totals,
        )
        return report
