"""Stage 1 validation, size limits, SHA-256 event deduplication, and source health monitoring."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
from dataclasses import dataclass, field


class IngestValidationError(ValueError):
    """Raised when a raw log event fails schema or size validation."""


def parse_timestamp(val: str | int | float | None) -> float:
    if val is None:
        raise IngestValidationError("missing timestamp")
    if isinstance(val, (int, float)):
        if val <= 0:
            raise IngestValidationError(f"invalid numeric timestamp: {val}")
        return float(val)
    if isinstance(val, str):
        s = val.strip()
        if not s:
            raise IngestValidationError("empty timestamp string")
        try:
            return float(s)
        except ValueError:
            pass
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            parsed = dt.datetime.fromisoformat(s)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.timestamp()
        except ValueError as e:
            raise IngestValidationError(f"unparseable ISO timestamp: {val!r}") from e
    raise IngestValidationError(f"unsupported timestamp type: {type(val).__name__}")


def compute_event_hash(source: str, payload: dict) -> str:
    body = {k: v for k, v in payload.items() if k not in ("_ingested_at", "_raw_hash")}
    canonical = json.dumps({"source": source, "payload": body}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class SourceStats:
    source: str
    events_accepted: int = 0
    events_deduped: int = 0
    events_rejected: int = 0
    last_event_ts: float | None = None
    last_ingested_at: float | None = None
    silence_threshold_s: float = 600.0


@dataclass
class HealthAlert:
    source: str
    status: str  # "silent" | "never_seen" | "healthy"
    silence_seconds: float
    threshold_seconds: float
    message: str


class SourceHealthMonitor:
    """Tracks per-source heartbeat and raises health alerts when a log source goes quiet."""

    DEFAULT_THRESHOLDS = {
        "wazuh": 600.0,
        "ecs": 600.0,
        "cloudtrail": 900.0,
        "auth": 300.0,
        "api_gateway": 300.0,
        "payments": 300.0,
    }

    def __init__(self, thresholds: dict[str, float] | None = None):
        merged = dict(self.DEFAULT_THRESHOLDS)
        if thresholds:
            merged.update(thresholds)
        self.sources: dict[str, SourceStats] = {
            src: SourceStats(source=src, silence_threshold_s=thresh)
            for src, thresh in merged.items()
        }

    def record_accepted(self, source: str, event_ts: float, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        st = self.sources.setdefault(source, SourceStats(source=source))
        st.events_accepted += 1
        if st.last_event_ts is None or event_ts > st.last_event_ts:
            st.last_event_ts = event_ts
        st.last_ingested_at = now

    def record_deduped(self, source: str) -> None:
        st = self.sources.setdefault(source, SourceStats(source=source))
        st.events_deduped += 1

    def record_rejected(self, source: str) -> None:
        st = self.sources.setdefault(source, SourceStats(source=source))
        st.events_rejected += 1

    def check_health(self, reference_ts: float | None = None) -> dict[str, dict]:
        """Evaluate all monitored sources against their silence thresholds."""
        if reference_ts is None:
            observed = [s.last_event_ts for s in self.sources.values() if s.last_event_ts is not None]
            reference_ts = max(observed) if observed else time.time()

        report: dict[str, dict] = {}
        for src, st in self.sources.items():
            if st.last_event_ts is None:
                status = "never_seen"
                silence_s = -1.0
                msg = f"Source '{src}' has not delivered any events yet."
            else:
                silence_s = max(0.0, reference_ts - st.last_event_ts)
                if silence_s > st.silence_threshold_s:
                    status = "silent"
                    msg = (
                        f"ALERT: Source '{src}' has been silent for {int(silence_s)}s "
                        f"(threshold {int(st.silence_threshold_s)}s)."
                    )
                else:
                    status = "healthy"
                    msg = f"Source '{src}' active ({int(silence_s)}s since last event)."
            report[src] = {
                "source": src,
                "status": status,
                "events_accepted": st.events_accepted,
                "events_deduped": st.events_deduped,
                "events_rejected": st.events_rejected,
                "last_event_ts": st.last_event_ts,
                "silence_seconds": round(silence_s, 1) if silence_s >= 0 else None,
                "threshold_seconds": st.silence_threshold_s,
                "message": msg,
            }
        return report

    def quiet_sources(self, reference_ts: float | None = None) -> list[HealthAlert]:
        health = self.check_health(reference_ts)
        alerts: list[HealthAlert] = []
        for src, info in health.items():
            if info["status"] == "silent":
                alerts.append(
                    HealthAlert(
                        source=src,
                        status="silent",
                        silence_seconds=info["silence_seconds"] or 0.0,
                        threshold_seconds=info["threshold_seconds"],
                        message=info["message"],
                    )
                )
        return alerts


class EventValidator:
    """Enforces payload size limits, per-source required schema fields, and SHA-256 deduplication."""

    REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
        "wazuh": ("timestamp", "rule"),
        "ecs": ("@timestamp", "event"),
        "cloudtrail": ("eventTime", "eventName"),
        "auth": ("ts", "action"),
        "api_gateway": ("ts", "path"),
        "payments": ("ts", "action"),
    }

    def __init__(self, max_event_bytes: int = 65536, max_batch_size: int = 5000):
        self.max_event_bytes = max_event_bytes
        self.max_batch_size = max_batch_size
        self.seen_hashes: dict[str, float] = {}

    def detect_source(self, raw: dict) -> str:
        if "source_type" in raw and raw["source_type"] in self.REQUIRED_FIELDS:
            return str(raw["source_type"])
        if "eventTime" in raw and ("eventName" in raw or "eventSource" in raw):
            return "cloudtrail"
        if "@timestamp" in raw and "event" in raw:
            return "ecs"
        if "rule" in raw and ("agent" in raw or "full_log" in raw or "data" in raw):
            return "wazuh"
        if "path" in raw and ("method" in raw or "status_code" in raw):
            return "api_gateway"
        if raw.get("action") in (
            "beneficiary_added",
            "wire_transfer",
            "upi_transfer",
            "rtgs_transfer",
            "device_changed",
            "phone_changed",
            "limit_updated",
        ) or "counterparty_account" in raw or ("amount" in raw and "account" in raw):
            return "payments"
        if "action" in raw and "ts" in raw:
            return "auth"
        raise IngestValidationError("unable to determine log source; specify 'source' explicitly")

    def validate(self, raw: dict, source: str | None = None) -> tuple[str, str, float]:
        """Validate a single event dict. Returns (source, event_hash, timestamp)."""
        if not isinstance(raw, dict):
            raise IngestValidationError("event must be a JSON object")
        encoded = json.dumps(raw, default=str).encode("utf-8")
        if len(encoded) > self.max_event_bytes:
            raise IngestValidationError(
                f"event size {len(encoded)} bytes exceeds limit of {self.max_event_bytes} bytes"
            )
        src = source or self.detect_source(raw)
        if src not in self.REQUIRED_FIELDS:
            raise IngestValidationError(f"unsupported source '{src}'")
        for req in self.REQUIRED_FIELDS[src]:
            if req not in raw or raw[req] is None:
                raise IngestValidationError(f"source '{src}' missing required field '{req}'")

        ts_field = {"wazuh": "timestamp", "ecs": "@timestamp", "cloudtrail": "eventTime"}.get(src, "ts")
        ts = parse_timestamp(raw.get(ts_field))

        if src == "wazuh" and not isinstance(raw.get("rule"), dict):
            raise IngestValidationError("wazuh 'rule' field must be an object")
        if src == "ecs" and not isinstance(raw.get("event"), dict):
            raise IngestValidationError("ecs 'event' field must be an object")
        if src == "payments" and "amount" in raw and raw["amount"] is not None:
            try:
                amt = float(raw["amount"])
            except (TypeError, ValueError) as e:
                raise IngestValidationError(f"invalid payment amount: {raw['amount']!r}") from e
            if amt < 0:
                raise IngestValidationError("payment amount cannot be negative")

        ev_hash = compute_event_hash(src, raw)
        return src, ev_hash, ts

    def check_and_mark_dedup(self, ev_hash: str, ts: float) -> bool:
        """Returns True if the event is new, or False if it is a duplicate."""
        if ev_hash in self.seen_hashes:
            return False
        self.seen_hashes[ev_hash] = ts
        return True
