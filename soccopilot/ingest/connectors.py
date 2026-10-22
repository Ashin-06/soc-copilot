"""Stage 1 Ingest connectors: Wazuh, ECS, AWS CloudTrail, Auth, API Gateway, and Payments.

Supports three transports:
1. File drop (JSON / JSONL batch files)
2. Near-real-time HTTP webhook (`POST /ingest`)
3. Kafka-compatible topic record batches for bank-scale streaming
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .validator import EventValidator, IngestValidationError, SourceHealthMonitor


@dataclass
class IngestedEnvelope:
    source: str
    event_hash: str
    timestamp: float
    raw: dict
    transport: str = "webhook"


@dataclass
class IngestBatchResult:
    accepted: list[IngestedEnvelope] = field(default_factory=list)
    duplicates: int = 0
    rejected: list[dict] = field(default_factory=list)


class IngestService:
    """Validates, deduplicates, and monitors health across all bank log sources."""

    def __init__(
        self,
        max_event_bytes: int = 65536,
        max_batch_size: int = 5000,
        silence_thresholds: dict[str, float] | None = None,
    ):
        self.validator = EventValidator(max_event_bytes=max_event_bytes, max_batch_size=max_batch_size)
        self.health = SourceHealthMonitor(thresholds=silence_thresholds)

    def ingest_event(
        self,
        raw: dict,
        source: str | None = None,
        transport: str = "webhook",
    ) -> tuple[IngestedEnvelope | None, str]:
        """Ingest a single raw dict. Returns (envelope_or_none, status) where status is
        'accepted', 'duplicate', or 'rejected:<reason>'.
        """
        inferred_src = source
        try:
            src, ev_hash, ts = self.validator.validate(raw, source=source)
            inferred_src = src
        except IngestValidationError as e:
            self.health.record_rejected(inferred_src or "unknown")
            return None, f"rejected:{e}"

        if not self.validator.check_and_mark_dedup(ev_hash, ts):
            self.health.record_deduped(src)
            return None, "duplicate"

        self.health.record_accepted(src, ts)
        return IngestedEnvelope(source=src, event_hash=ev_hash, timestamp=ts, raw=dict(raw), transport=transport), "accepted"

    def ingest_batch(
        self,
        events: list[dict],
        source: str | None = None,
        transport: str = "webhook",
    ) -> IngestBatchResult:
        if len(events) > self.validator.max_batch_size:
            raise IngestValidationError(
                f"batch size {len(events)} exceeds limit of {self.validator.max_batch_size}"
            )
        res = IngestBatchResult()
        for idx, ev in enumerate(events):
            env, status = self.ingest_event(ev, source=source, transport=transport)
            if status == "accepted" and env is not None:
                res.accepted.append(env)
            elif status == "duplicate":
                res.duplicates += 1
            else:
                res.rejected.append({"index": idx, "reason": status.removeprefix("rejected:")})
        return res

    def ingest_file(self, path: str | Path, source: str | None = None) -> IngestBatchResult:
        """File-drop connector supporting JSON array, CloudTrail {'Records': [...]}, or JSONL."""
        p = Path(path)
        text = p.read_text(encoding="utf-8").strip()
        if not text:
            return IngestBatchResult()
        if text.startswith("["):
            records = json.loads(text)
        elif text.startswith("{"):
            first_lines = [ln for ln in text.splitlines() if ln.strip()]
            if len(first_lines) == 1:
                parsed = json.loads(text)
                if isinstance(parsed, dict) and isinstance(parsed.get("Records"), list):
                    records = parsed["Records"]
                    source = source or "cloudtrail"
                elif isinstance(parsed, dict) and isinstance(parsed.get("events"), list):
                    records = parsed["events"]
                else:
                    records = [parsed]
            else:
                records = [json.loads(ln) for ln in first_lines]
        else:
            records = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
        return self.ingest_batch(records, source=source, transport="file_drop")

    def ingest_kafka_records(self, records: Iterable[dict]) -> IngestBatchResult:
        """Kafka topic batch adapter where each record has {'topic': ..., 'value': dict|bytes|str}."""
        topic_map = {
            "soc.wazuh": "wazuh",
            "soc.ecs": "ecs",
            "soc.cloudtrail": "cloudtrail",
            "soc.auth": "auth",
            "soc.api": "api_gateway",
            "soc.payments": "payments",
        }
        res = IngestBatchResult()
        for idx, rec in enumerate(records):
            topic = rec.get("topic", "")
            src = rec.get("source") or topic_map.get(topic)
            val = rec.get("value", rec)
            if isinstance(val, (bytes, bytearray)):
                val = json.loads(val.decode("utf-8"))
            elif isinstance(val, str):
                val = json.loads(val)
            env, status = self.ingest_event(val, source=src, transport="kafka")
            if status == "accepted" and env is not None:
                res.accepted.append(env)
            elif status == "duplicate":
                res.duplicates += 1
            else:
                res.rejected.append({"index": idx, "reason": status.removeprefix("rejected:")})
        return res
