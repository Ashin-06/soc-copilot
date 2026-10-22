"""Command-line interface for SOC Copilot.

    python -m soccopilot evaluate [--benign 240] [--json out.json]
    python -m soccopilot ingest path/to/events.jsonl [--source wazuh|ecs|cloudtrail|auth|api_gateway|payments]
    python -m soccopilot triage [INC-0001] [--live]
    python -m soccopilot serve [--port 8011] [--host 127.0.0.1]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluate import run_evaluation, seed_demo_copilot
from .pipeline import SOCCopilot


def main(argv: list[str] | None = None) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    ap = argparse.ArgumentParser(prog="soccopilot", description="SOC Copilot for a digital bank")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ev_p = sub.add_parser("evaluate", aliases=["bench"], help="run detection, correlation, and triage benchmark")
    ev_p.add_argument("--benign", type=int, default=240, help="number of benign baseline events")
    ev_p.add_argument("--json", help="optional path to write JSON benchmark report")

    in_p = sub.add_parser("ingest", help="ingest a JSON/JSONL file through the 8-stage pipeline")
    in_p.add_argument("file", help="path to JSON or JSONL log file")
    in_p.add_argument("--source", default=None, help="optional explicit log source")

    tr_p = sub.add_parser("triage", help="triage a correlated incident from the demo queue")
    tr_p.add_argument("incident_id", nargs="?", default="INC-0001")
    tr_p.add_argument("--live", action="store_true", help="run live Claude tool-use loop if ANTHROPIC_API_KEY is set")

    sv_p = sub.add_parser("serve", help="start FastAPI server + Analyst Console UI")
    sv_p.add_argument("--port", type=int, default=8011)
    sv_p.add_argument("--host", default="127.0.0.1")

    args = ap.parse_args(argv)

    if args.cmd in ("evaluate", "bench"):
        res = run_evaluation(benign_count=args.benign)
        print("SOC Copilot Benchmark (6 Multi-Stage Campaigns + Normal Banking Traffic)")
        print("-" * 92)
        for c in res["campaigns"]:
            mark = "DETECTED" if c["detected"] else "MISSED"
            sf = " [SEC+FRAUD]" if c["security_fraud_joined"] else ""
            print(
                f"{c['campaign_id']}  {c['title'][:46]:46s}  {mark:8s}  "
                f"{str(c['incident_id']):8s}  score={c['risk_score']:5.1f}  "
                f"events={c['events_correlated']:5s}  cited={c['citation_coverage']:.0%}{sf}"
            )
        print("-" * 92)
        print(
            f"Detection recall:          {res['detection_recall']:.0%} "
            f"({res['campaigns_detected']}/{res['campaigns_total']} campaigns)"
        )
        print(f"Security+Fraud join rate:  {res['security_fraud_join_rate']:.0%}")
        print(f"False-positive noise/day:  {res['false_positive_incidents_per_day']} incidents ({res['benign_events_tested']} benign events)")
        print(f"Time to first alert:       {res['mean_time_to_first_alert_ms']:.2f} ms mean ({res['max_time_to_first_alert_ms']:.2f} ms max)")
        print(f"Report citation coverage:  {res['report_citation_coverage']:.0%} of claims backed by log IDs")
        if args.json:
            Path(args.json).write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")

    elif args.cmd == "ingest":
        cp = SOCCopilot()
        res = cp.process_file(args.file, source=args.source)
        print(
            f"Accepted: {res['accepted']} · Duplicates: {res['duplicates']} · "
            f"Rejected: {len(res['rejected'])} · Alerts: {res['new_alerts']} · Incidents: {res['incidents']}"
        )
        for r in res["rejected"][:20]:
            print(f"  rejected {r}")
        for inc in sorted(cp.incidents.values(), key=lambda i: -i.risk_score):
            print(f"  {inc.incident_id} [{inc.severity.upper()} {inc.risk_score}] {inc.title}")

    elif args.cmd == "triage":
        cp = seed_demo_copilot()
        inc = cp.incidents.get(args.incident_id)
        if not inc:
            print(f"Incident {args.incident_id} not found. Available: {', '.join(cp.incidents)}", file=sys.stderr)
            sys.exit(1)
        rep = cp.triage_engine.triage_incident(inc, use_llm=args.live)
        print(f"=== {rep.incident_id}: {inc.title} ===")
        print(f"Mode: {rep.generated_by} | Confidence: {rep.confidence} ({rep.confidence_score:.2f}) | Citations: {rep.citation_coverage:.0%}")
        print(f"\nSummary:\n  {rep.summary}")
        print("\nTimeline:")
        for step in rep.timeline:
            print(f"  - {step}")
        print("\nRecommended Containment (Pending Analyst Approval):")
        for r in rep.recommended_containment:
            print(f"  - {r['action_type']} -> {r['target']}: {r['rationale']}")

    elif args.cmd == "serve":
        import uvicorn

        uvicorn.run("soccopilot.api:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
