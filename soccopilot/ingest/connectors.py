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

    TOPICS = {
        "soc.wazuh": "wazuh",
        "soc.ecs": "ecs",
        "soc.cloudtrail": "cloudtrail",
        "soc.auth": "auth",
        "soc.api": "api_gateway",
        "soc.payments": "payments",
    }

    def __init__(
        self,
        max_event_bytes: int = 65536,
        max_batch_size: int = 5000,
        silence_thresholds: dict[str, float] | None = None,
        dedup_window_s: float = 86400.0,
    ):
        self.validator = EventValidator(
            max_event_bytes=max_event_bytes, max_batch_size=max_batch_size, dedup_window_s=dedup_window_s
        )
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
            # unknown or caller-supplied names are pooled so they cannot grow the health table
            self.health.record_rejected(inferred_src if inferred_src in self.TOPICS.values() else "unknown")
            return None, f"rejected:{e}"

        if not self.validator.check_and_mark_dedup(ev_hash, ts):
            self.health.record_deduped(src)
            return None, "duplicate"

        self.health.record_accepted(src, ts)
        return IngestedEnvelope(source=src, event_hash=ev_hash, timestamp=ts, raw=dict(raw), transport=transport), "accepted"

    def _check_batch(self, n: int) -> None:
        if n > self.validator.max_batch_size:
            raise IngestValidationError(f"batch size {n} exceeds limit of {self.validator.max_batch_size}")

    @staticmethod
    def _collect(res: IngestBatchResult, idx: int, env: IngestedEnvelope | None, status: str) -> None:
        if status == "accepted" and env is not None:
            res.accepted.append(env)
        elif status == "duplicate":
            res.duplicates += 1
        else:
            res.rejected.append({"index": idx, "reason": status.removeprefix("rejected:")})

    def ingest_batch(
        self,
        events: list[dict],
        source: str | None = None,
        transport: str = "webhook",
    ) -> IngestBatchResult:
        self._check_batch(len(events))
        res = IngestBatchResult()
        for idx, ev in enumerate(events):
            self._collect(res, idx, *self.ingest_event(ev, source=source, transport=transport))
        return res

    def ingest_file(self, path: str | Path, source: str | None = None) -> IngestBatchResult:
        """File-drop connector supporting a JSON array, CloudTrail {'Records': [...]}, a single
        object, or JSONL. In JSONL a malformed line is rejected on its own; the rest still load."""
        text = Path(path).read_text(encoding="utf-8").strip()
        if not text:
            return IngestBatchResult()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None  # not one JSON document: treat as JSONL
        if parsed is not None:
            if isinstance(parsed, dict) and isinstance(parsed.get("Records"), list):
                records, source = parsed["Records"], source or "cloudtrail"
            elif isinstance(parsed, dict) and isinstance(parsed.get("events"), list):
                records = parsed["events"]
            else:
                records = parsed if isinstance(parsed, list) else [parsed]
            return self.ingest_batch(records, source=source, transport="file_drop")

        lines = [ln for ln in text.splitlines() if ln.strip()]
        self._check_batch(len(lines))
        res = IngestBatchResult()
        for idx, ln in enumerate(lines):
            try:
                rec = json.loads(ln)
            except json.JSONDecodeError as e:
                self._collect(res, idx, None, f"rejected:line {idx + 1} is not valid JSON ({e.msg})")
                continue
            self._collect(res, idx, *self.ingest_event(rec, source=source, transport="file_drop"))
        return res

    def ingest_kafka_records(self, records: Iterable[dict]) -> IngestBatchResult:
        """Kafka topic batch adapter where each record has {'topic': ..., 'value': dict|bytes|str}.
        A record that cannot be decoded is rejected without failing the rest of the batch."""
        records = list(records)
        self._check_batch(len(records))
        res = IngestBatchResult()
        for idx, rec in enumerate(records):
            if not isinstance(rec, dict):
                self._collect(res, idx, None, "rejected:record must be an object")
                continue
            src = rec.get("source") or self.TOPICS.get(str(rec.get("topic", "")))
            val = rec.get("value", rec)
            try:
                if isinstance(val, (bytes, bytearray)):
                    val = json.loads(val.decode("utf-8"))
                elif isinstance(val, str):
                    val = json.loads(val)
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                self._collect(res, idx, None, f"rejected:value is not valid JSON ({e})")
                continue
            self._collect(res, idx, *self.ingest_event(val, source=src, transport="kafka"))
        return res
