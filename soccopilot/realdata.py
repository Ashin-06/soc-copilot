"""Run the copilot on real AWS CloudTrail logs.

flaws.cloud CloudTrail logs (Scott Piper / Summit Route): 1.9 million anonymised real events
from the flaws.cloud AWS security challenge, 2017-2020, most of them from people attacking
the account with leaked keys. https://summitroute.com/downloads/flaws_cloudtrail_logs.tar
Unlabelled, so what is measured is volume (alerts and incidents per 10,000 events) and speed.

OTRF Security-Datasets (MIT):
- `ec2_proxy_s3_exfiltration`: a recorded attack in which an EC2 instance's role credentials
  are used from outside AWS to list and download S3 objects (CloudTrail shipped by Logstash).
- `aws_s3_honeybucketlogs`: 301 requests to a decoy bucket that nobody should touch, 2022,
  exported as CSV. Every row is a probe.

    python -m soccopilot realdata --flaws flaws_cloudtrail_logs/ --otrf ec2_proxy_s3_exfiltration.json \
        --honeybucket AWS_S3_HoneyBucketLogs.csv
"""
from __future__ import annotations

import ast
import csv
import gzip
import json
import time
from collections import Counter
from pathlib import Path

from .pipeline import SOCCopilot

BATCH = 5000


def _replay(records: list[dict]) -> dict:
    cp = SOCCopilot()
    t0 = time.perf_counter()
    for i in range(0, len(records), BATCH):
        cp.process_raw_events(records[i : i + BATCH], source="cloudtrail", transport="file_drop")
    secs = time.perf_counter() - t0
    stored = cp.event_store.count()
    top = sorted(cp.incidents.values(), key=lambda x: -x.risk_score)[:5]
    return {
        "events": len(records), "events_stored": stored, "seconds": round(secs, 1),
        "events_per_second": round(len(records) / secs),
        "alerts": len(cp.alerts), "alerts_per_10k_events": round(len(cp.alerts) / max(stored, 1) * 10_000, 1),
        "alerts_by_rule": dict(Counter(a.rule_id for a in cp.alerts).most_common()),
        "repeats_suppressed": dict(cp.detector.suppressed),
        "incidents": len(cp.incidents),
        "top_incidents": [{"title": i.title, "risk": i.risk_score, "alerts": len(i.alert_ids), "tactics": i.tactics} for i in top],
    }


def flaws(folder: str | Path, limit: int = 100_000) -> dict:
    records: list[dict] = []
    for f in sorted(Path(folder).glob("*.json.gz")):
        with gzip.open(f, "rt", encoding="utf-8") as fh:
            records += json.load(fh)["Records"]
        if len(records) >= limit:
            break
    return {"dataset": "flaws.cloud CloudTrail (real, unlabelled)", **_replay(records[:limit])}


def otrf_exfiltration(path: str | Path) -> dict:
    records = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    res = _replay(records)
    res["dataset"] = "OTRF ec2_proxy_s3_exfiltration (recorded attack)"
    res["detected"] = res["incidents"] > 0
    return res


def otrf_honeybucket(path: str | Path) -> dict:
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    # back to CloudTrail shape; the export wrote the nested objects as Python literals
    records = [{
        "eventTime": r["Event DateTime"], "eventName": r["Event Name"], "eventSource": "s3.amazonaws.com",
        "eventID": r["Event ID"], "userIdentity": ast.literal_eval(r["User ID"] or "{}"),
        "requestParameters": ast.literal_eval(r["Request Parameters"] or "{}"),
        "sourceIPAddress": r["Source IP"], "userAgent": r["Request User Agent"],
    } for r in rows]
    res = _replay(records)
    res["dataset"] = "OTRF aws_s3_honeybucketlogs (every request is a probe)"
    res["probes"] = len(records)
    res["anonymous_probes"] = sum(r["userIdentity"].get("accountId") == "ANONYMOUS_PRINCIPAL" for r in records)
    return res


def main(flaws_dir=None, otrf=None, honeybucket=None, limit=100_000, out="results/real_data.json") -> dict:
    res = {}
    if flaws_dir:
        res["flaws_cloudtrail"] = flaws(flaws_dir, limit)
    if otrf:
        res["otrf_s3_exfiltration"] = otrf_exfiltration(otrf)
    if honeybucket:
        res["otrf_s3_honeybucket"] = otrf_honeybucket(honeybucket)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(res, indent=2))
    return res
