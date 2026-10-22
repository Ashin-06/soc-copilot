"""Command-line interface for SOC Copilot.

    python -m soccopilot evaluate [--benign 240] [--json out.json]
    python -m soccopilot evaluate --labelled my_events.jsonl
    python -m soccopilot ingest path/to/events.jsonl [--source wazuh|ecs|cloudtrail|auth|api_gateway|payments]
    python -m soccopilot triage [INCIDENT_ID] [--live]
    python -m soccopilot serve [--port 8011] [--host 127.0.0.1]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluate import evaluate_labelled_file, run_evaluation, seed_demo_copilot
from .pipeline import SOCCopilot


def main(argv: list[str] | None = None) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    ap = argparse.ArgumentParser(prog="soccopilot", description="SOC Copilot for a digital bank")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ev_p = sub.add_parser("evaluate", aliases=["bench"], help="run detection, correlation, and triage benchmark")
    ev_p.add_argument("--benign", type=int, default=240, help="number of benign baseline events")
    ev_p.add_argument("--json", help="optional path to write JSON benchmark report")
    ev_p.add_argument("--labelled", help="score your own JSONL events (event_id + optional label per line) instead")

    in_p = sub.add_parser("ingest", help="ingest a JSON/JSONL file through the 8-stage pipeline")
    in_p.add_argument("file", help="path to JSON or JSONL log file")
    in_p.add_argument("--source", default=None, help="optional explicit log source")

    tr_p = sub.add_parser("triage", help="triage a correlated incident from the demo queue")
    tr_p.add_argument("incident_id", nargs="?", help="defaults to the highest-risk incident")
    tr_p.add_argument("--live", action="store_true", help="run live Claude tool-use loop if ANTHROPIC_API_KEY is set")

    sv_p = sub.add_parser("serve", help="start FastAPI server + Analyst Console UI")
    sv_p.add_argument("--port", type=int, default=8011)
    sv_p.add_argument("--host", default="127.0.0.1")

    args = ap.parse_args(argv)

    if args.cmd in ("evaluate", "bench") and args.labelled:
        res = evaluate_labelled_file(args.labelled)
        for c in res["campaigns"]:
            print(f"{c['campaign_id'][:30]:30s}  {'DETECTED' if c['detected'] else 'MISSED':8s}  "
                  f"{str(c['incident_id']):14s}  events={c['events_correlated']}")
        print(f"Detection recall:     {res['detection_recall']:.0%} ({res['campaigns_detected']}/{res['campaigns_total']} labelled incidents)")
        print(f"False-positive cases: {res['false_positive_incidents']} over {res['events']} events")
        if args.json:
            Path(args.json).write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")

    elif args.cmd in ("evaluate", "bench"):
        res = run_evaluation(benign_count=args.benign)
        print("SOC Copilot Benchmark (6 Multi-Stage Campaigns + Normal Banking Traffic)")
        print("-" * 98)
        for c in res["campaigns"]:
            mark = "DETECTED" if c["detected"] else "MISSED"
            sf = " [SEC+FRAUD]" if c["security_fraud_joined"] else ""
            print(
                f"{c['campaign_id']}  {c['title'][:46]:46s}  {mark:8s}  "
                f"{str(c['incident_id']):14s}  score={c['risk_score']:5.1f}  "
                f"events={c['events_correlated']:5s}  cited={c['citation_coverage']:.0%}{sf}"
            )
        print("-" * 98)
        print(
            f"Detection recall:          {res['detection_recall']:.0%} "
            f"({res['campaigns_detected']}/{res['campaigns_total']} campaigns)"
        )
        print(f"Security+Fraud join rate:  {res['security_fraud_join_rate']:.0%}")
        print(f"False-positive noise/day:  {res['false_positive_incidents_per_day']} incidents ({res['benign_events_tested']} benign events)")
        print(f"Batch latency:             {res['mean_batch_latency_ms']:.0f} ms mean ({res['max_batch_latency_ms']:.0f} ms max, ingest to incident)")
        print(f"Report citation coverage:  {res['report_citation_coverage']:.0%} of claims backed by log IDs")
        print("Note: the rules were tuned on these campaigns, so this is a regression check. Use --labelled for your own data.")
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
        top = max(cp.incidents.values(), key=lambda i: i.risk_score, default=None)
        inc = cp.incidents.get(args.incident_id) if args.incident_id else top
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
