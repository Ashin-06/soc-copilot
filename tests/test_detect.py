import datetime as dt

import pytest

from soccopilot.detect import DetectionEngine, RuleError, SigmaRule
from soccopilot.enrich import Enricher
from soccopilot.evaluate import BASE_TS
from soccopilot.ingest import IngestService
from soccopilot.normalize import normalize_envelope

IST_10AM = BASE_TS - 5 * 3600  # BASE_TS is 15:00 IST


def _ev(raw, enricher=None):
    env, status = IngestService().ingest_event(raw)
    assert status == "accepted", status
    return (enricher or Enricher()).enrich(normalize_envelope(env))


def _rule(**detection):
    return {"id": "T-1", "title": "t", "level": "high", "detection": detection}


@pytest.mark.parametrize("detection", [
    {"selection": {"event_action|regex": "x"}, "condition": "selection"},        # unknown modifier
    {"selection": {"evnt_action": "x"}, "condition": "selection"},               # typo in field
    {"selection": {"event_action": "x"}, "condition": "selection or filter"},   # unsupported logic
    {"selection": {"event_action": "x"}, "filter": {"user": "a"}, "condition": "selection"},  # filter ignored
    {"selection": {"event_action": "x"}, "condition": "selection | count() by actor >= 3"},   # no timeframe
])
def test_unsupported_rule_syntax_fails_loudly(detection):
    with pytest.raises(RuleError):
        SigmaRule.from_yaml(_rule(**detection))


@pytest.mark.parametrize("suppression", [{"by": "usr", "for": "1h"}, {"by": "user"}, {"by": "user", "for": "soon"}])
def test_bad_suppression_fails_loudly(suppression):
    with pytest.raises(RuleError):
        SigmaRule.from_yaml({**_rule(selection={"event_action": "x"}, condition="selection"), "suppression": suppression})


def test_off_hours_uses_the_staff_members_local_time():
    eng = DetectionEngine()
    login = {"source_type": "auth", "action": "login_success", "outcome": "success", "user": "vikram.rao", "ip": "10.12.1.15"}
    # 10:00 IST is 04:30 UTC: inside working hours, so no alert
    assert not [a for a in eng.evaluate_event(_ev({**login, "ts": IST_10AM})) if a.rule_id == "BASELINE-OFFHOURS-001"]
    late = [a for a in eng.evaluate_event(_ev({**login, "ts": IST_10AM + 13 * 3600})) if a.rule_id == "BASELINE-OFFHOURS-001"]
    assert late and "23:00 Asia/Kolkata" in late[0].summary


def test_alert_ids_are_stable_and_unique():
    ev = _ev({"event_id": "EVT-D1", "source_type": "wazuh", "timestamp": BASE_TS, "rule": {"id": "x"},
              "agent": {"name": "prod-bastion-01"}, "data": {"action": "sudo_priv_esc", "dstuser": "root"}})
    ids_a = [a.alert_id for a in DetectionEngine().evaluate_event(ev)]
    ids_b = [a.alert_id for a in DetectionEngine().evaluate_event(ev)]
    assert ids_a == ids_b and len(set(ids_a)) == len(ids_a) and ids_a[0].startswith("ALT-EVT-D1-")


def test_events_without_a_grouping_key_are_not_pooled():
    eng = DetectionEngine()
    fired = []
    for i in range(6):  # account lookups with no client IP must not add up to one "enumeration"
        fired += eng.evaluate_event(_ev({"source_type": "api_gateway", "ts": BASE_TS + i, "method": "GET",
                                         "path": f"/api/v1/accounts/{i}", "status_code": 200}))
    assert not [a for a in fired if a.rule_id == "SIGMA-BANK-007"]


def test_a_scanner_assuming_the_same_role_alerts_once_a_day():
    eng = DetectionEngine()

    def assume(minute, role="SecurityAudit"):
        t = dt.datetime(2017, 2, 12, tzinfo=dt.timezone.utc) + dt.timedelta(minutes=minute)
        return [a for a in eng.evaluate_event(_ev({
            "eventTime": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventName": "AssumeRole", "eventSource": "sts.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": "scanner"}, "sourceIPAddress": "203.0.113.5",
            "requestParameters": {"roleArn": f"arn:aws:iam::111122223333:role/{role}"}})) if a.rule_id == "SIGMA-BANK-011"]

    assert assume(0) and not assume(5) and not assume(60)
    assert assume(65, role="ProdAdmin")      # a different privileged role is new
    assert assume(24 * 60 + 1)                # and the same one alerts again the next day
    assert eng.suppressed["SIGMA-BANK-011"] == 2


def test_anonymous_bucket_probes_alert_once_per_ip_and_bucket_a_day():
    eng = DetectionEngine()

    def probe(ip, account="ANONYMOUS_PRINCIPAL", hour=0):
        return [a for a in eng.evaluate_event(_ev({
            "eventTime": f"2022-02-18T{hour:02d}:00:00Z", "eventName": "HeadBucket", "eventSource": "s3.amazonaws.com",
            "userIdentity": {"type": "AWSAccount", "principalId": "", "accountId": account}, "sourceIPAddress": ip,
            "requestParameters": {"bucketName": "kyc-archive"}})) if a.rule_id == "SIGMA-BANK-013"]

    assert probe("198.51.100.7") and not probe("198.51.100.7", hour=3) and probe("198.51.100.8")
    assert not probe("198.51.100.9", account="111122223333")   # signed requests are someone else's rule


def test_quiet_windows_are_swept():
    eng, enr = DetectionEngine(), Enricher()
    for i in range(1000):
        eng.evaluate_event(_ev({"source_type": "auth", "ts": BASE_TS + i * 60, "action": "login_failed",
                                "outcome": "failure", "customer_id": f"C-{i}"}, enr))
    assert len(eng._window_buffers) < 50
