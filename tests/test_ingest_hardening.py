import json
import math

import pytest

from soccopilot.evaluate import BASE_TS
from soccopilot.ingest import IngestService, IngestValidationError, parse_timestamp
from soccopilot.ingest.validator import EventValidator


def test_timestamps_reject_garbage_and_accept_epoch_millis():
    assert parse_timestamp(BASE_TS * 1000) == pytest.approx(BASE_TS)
    assert parse_timestamp("2025-10-21T09:30:00Z") == pytest.approx(BASE_TS)
    for bad in (math.nan, math.inf, -5, True, "nan", "yesterday"):
        with pytest.raises(IngestValidationError):
            parse_timestamp(bad)


def test_cloudtrail_shipped_through_logstash_is_accepted():
    v = EventValidator()
    src, _, ts = v.validate({"@timestamp": "2025-10-21T09:30:00.000Z", "eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"})
    assert src == "cloudtrail" and ts == pytest.approx(BASE_TS)


def test_bad_values_are_rejected_not_crashing():
    svc = IngestService()
    far_future = {"source_type": "auth", "ts": 4102444800, "action": "login_success"}
    nan_amount = {"source_type": "payments", "ts": BASE_TS, "action": "upi_transfer", "amount": "NaN"}
    for ev in (far_future, nan_amount, {"source_type": ["auth"], "ts": BASE_TS}, "not an object"):
        env, status = svc.ingest_event(ev)
        assert env is None and status.startswith("rejected:")
    # a made-up source name does not create a new health entry
    svc.ingest_event({"ts": BASE_TS}, source="x" * 500)
    assert "x" * 500 not in svc.health.sources


def test_one_bad_record_does_not_sink_the_batch(tmp_path):
    svc = IngestService()
    good = {"source_type": "auth", "ts": BASE_TS, "action": "login_success", "user": "dev.kulkarni"}
    k = svc.ingest_kafka_records([
        {"topic": "soc.auth", "value": b"{not json"},
        "garbage",
        {"topic": "soc.auth", "value": json.dumps(good)},
    ])
    assert len(k.accepted) == 1 and [r["index"] for r in k.rejected] == [0, 1]

    f = tmp_path / "drop.jsonl"
    f.write_text(json.dumps({**good, "ts": BASE_TS + 1}) + "\n{oops\n" + json.dumps({**good, "ts": BASE_TS + 2}) + "\n")
    res = svc.ingest_file(f)
    assert len(res.accepted) == 2 and "line 2" in res.rejected[0]["reason"]

    with pytest.raises(IngestValidationError):
        IngestService(max_batch_size=2).ingest_kafka_records([{"value": good}] * 3)


def test_dedupe_memory_is_bounded_by_the_window():
    v = EventValidator(dedup_window_s=100)
    for i in range(10_000):
        assert v.check_and_mark_dedup(f"h{i}", BASE_TS + i)
    assert len(v.seen_hashes) < 5_000
    assert not v.check_and_mark_dedup("h9999", BASE_TS + 9999)  # recent ones are still caught


def test_an_outage_of_every_source_still_alarms():
    import time

    from soccopilot.ingest import SourceHealthMonitor

    mon = SourceHealthMonitor()
    for src in ("auth", "payments"):
        mon.record_accepted(src, BASE_TS, now=time.time() - 3600)  # last delivery an hour ago
    health = mon.check_health()
    assert health["auth"]["status"] == "silent" and health["payments"]["status"] == "silent"
    # replay mode measures in event time
    assert mon.check_health(reference_ts=BASE_TS + 10)["auth"]["status"] == "healthy"
