# Evaluation

## Built-in campaigns

`python -m soccopilot evaluate` replays six labelled multi-stage attacks mixed with 240 ordinary events, including nightly backup jobs and suppressed vulnerability scans:

1. Customer account takeover with MFA fatigue and a ₹1.85 lakh wire.
2. Cloud IAM escalation and KYC bucket exfiltration.
3. API account enumeration with structured transfers.
4. Bastion privilege escalation and a ledger database dump.
5. Impossible travel, device swap and an RTGS drain.
6. Insider off-hours export with audit tampering.

```
CAMP-01  Customer ATO via MFA Fatigue & ₹1.85L Wire Dra  DETECTED  INC-4AAB49B078  score=100.0  events=10/10  cited=100% [SEC+FRAUD]
CAMP-02  Cloud IAM Escalation & S3 KYC Vault Exfiltrati  DETECTED  INC-DAA617614E  score=100.0  events=5/5    cited=100%
CAMP-03  API IDOR Account Enumeration & Structured Smur  DETECTED  INC-7D60A1C04D  score=100.0  events=8/8    cited=100% [SEC+FRAUD]
CAMP-04  Bastion Privilege Escalation & Core Ledger DB   DETECTED  INC-085A432282  score=100.0  events=3/3    cited=100%
CAMP-05  Impossible Travel, Device Swap & ₹2.40L RTGS D  DETECTED  INC-46B3D7BF2C  score=100.0  events=5/5    cited=100% [SEC+FRAUD]
CAMP-06  Insider Off-Hours Bulk Statement Export & Audi  DETECTED  INC-ADFCE1D1BF  score= 95.0  events=3/3    cited=100%
Detection recall:          100% (6/6 campaigns)
Security+Fraud join rate:  100%
False-positive noise/day:  0 incidents (240 benign events)
Report citation coverage:  100% of claims backed by log IDs
```

The rules were written with these campaigns in view, so this is a regression check rather than a measure of recall. To score your own data, label a JSONL export: each line is a raw event with a unique `event_id`, plus a `label` naming the incident it belongs to (leave it out for normal events).

```jsonl
{"event_id": "EVT-90001", "label": "case-17", "source_type": "auth", "ts": 1761039000, "action": "login_failed", "customer_id": "C-88"}
{"event_id": "EVT-90002", "source_type": "payments", "ts": 1761039060, "action": "upi_transfer", "amount": 450, "account": "1234567890123"}
```

```bash
python -m soccopilot evaluate --labelled my_events.jsonl --json results.json
```

## Real AWS logs

`python -m soccopilot realdata` replays public AWS logs through every stage. They have no incident labels, so the measures are alert volume, speed, and whether the recorded attacks show up. Results go to `results/real_data.json`.

```bash
python -m soccopilot realdata --flaws flaws_cloudtrail_logs/ --otrf ec2_proxy_s3_exfiltration.json --honeybucket AWS_S3_HoneyBucketLogs.csv
```

### flaws.cloud CloudTrail

[flaws.cloud](https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/) published 1.9 million anonymised CloudTrail events from its AWS security challenge, most of them from strangers using deliberately leaked keys. The first 100,000 events (February 2017 to April 2018) were used.

The first run was unusable. On the first 50,000 events:

| | Before | After |
|---|---|---|
| Alerts | 7,962 | 51 |
| Incidents | 2,448 | 17 |
| Throughput | 42 events/s | 2,816 events/s |

What changed:
- The IAM rule treated every successful `AssumeRole` as escalation, but AWS services assume roles constantly. The rule now covers new access keys, login profiles and attached policies (SIGMA-BANK-005), and a separate rule (SIGMA-BANK-011) flags people, not services, assuming a role named admin, prod, security, owner, root or break-glass.
- One IAM user running a scanner assumed the same audit role 4,469 times in 17 hours. Rules can now have a `suppression` block that raises one alert per key per time window and counts the repeats. The scanner now produces 1 alert.
- Leaked-key abuse shows up as access-denied errors, so SIGMA-BANK-012 flags 20 or more denials by one user within 10 minutes.
- Events were written to DuckDB one row at a time; they now go in as one batch, which accounts for most of the speed-up.

On all 100,000 events: 99,857 stored (143 exact duplicates dropped), 130 alerts (13 per 10,000 events) and 32 incidents, at 2,600–3,700 events/s on a laptop. The alerts were 81 access-denied bursts, 26 key or policy changes, 22 bucket policy or ACL changes and 1 privileged role use. The top incident (risk 96.7) was new access keys followed by bucket policy changes in the same account.

### OTRF EC2 credential exfiltration

In this [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) recording (MIT), an EC2 instance's role credentials are used from outside AWS to list buckets and download objects. The recording was shipped through Logstash, which renames `eventTime` to `@timestamp`, so all 103 events were rejected at first; that format is accepted now.

The attack was not detected. Telling a stolen instance credential from the instance itself needs the instance's own IP addresses, which these logs don't contain, and the instance made no calls of its own to compare against.

### OTRF decoy S3 bucket

301 requests to a decoy bucket over 218 days, 284 of them anonymous. Nothing fired at first. SIGMA-BANK-013 (anonymous `HeadBucket`, `ListObjects` and bucket ACL or policy reads) now raises 216 alerts, one per source IP, bucket and day. That rule was written after looking at this data, so the result is in-sample, and flaws.cloud has no S3 data events to measure its noise on normal traffic.
