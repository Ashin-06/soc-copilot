# SOC Copilot for a Digital Bank

A bank's security team gets thousands of alerts a day from logins, APIs, servers, cloud infrastructure, and the payments switch. Most are noise; the real incidents are scattered across different tools. This copilot pulls those signals together, groups related alerts into incidents, links security events to payment fraud signals, drafts an evidence-cited investigation report through a privacy-scrubbed AI tool loop, and suggests containment steps that only run after an analyst approves them.

```
Log sources ──► 1 Ingest ──► 2 Normalise ──► 3 Enrich ──► 4 Detect ──► 5 Correlate ──► 6 Triage (Claude) ──► 7 Respond
(auth, API,       connectors    common schema    context       rules +       alerts →          report draft         playbooks,
 payments,        + validation  + entities       lookups       baselines     incidents         with evidence        analyst approval
 servers, cloud)                                                                                                    + audit
                                                                      ▲                                  │
                                                                      └──────── 8 Analyst console ◄──────┘
                                                                           (feedback tunes rules and scores)
```

## Pipeline Stages

| Stage | Module | What it does |
|---|---|---|
| **1. Ingest** | `soccopilot/ingest/` | Connectors for **Wazuh**, **Elastic ECS**, **AWS CloudTrail**, **Auth/SSO**, **API Gateway**, and **Payments** (`beneficiary_added`, `device_changed`, `phone_changed`, `wire_transfer`, `imps_transfer`, `rtgs_transfer`). Supports file drop (`JSON`/`JSONL`), HTTP webhook (`POST /ingest`), and Kafka topic record batches. Enforces schema validation, payload size limits, SHA-256 event hash deduplication, and per-source silence health monitoring (`SourceHealthMonitor`). |
| **2. Normalise** | `soccopilot/normalize.py` | Maps every source onto an Elastic ECS-modelled schema (`timestamp`, `event_category`, `event_action`, `event_outcome`, `user`, `customer_id`, `source_ip`, `host`, `device_id`, `url`, `account`, `counterparty_account`, `amount`, `cloud_key`, `bytes_out`) and extracts typed entities (`user:`, `customer:`, `ip:`, `device:`, `host:`, `account:`, `cloud_key:`). |
| **3. Enrich** | `soccopilot/enrich.py` | Adds server criticality (`1..5`) from asset inventory, staff role/department/shift hours from directory, customer account age and recent beneficiary/phone/device change flags, GeoIP country/city + Haversine impossible-travel speed, and threat intelligence IP/domain reputation scores. |
| **4. Detect** | `soccopilot/detect.py`, `soccopilot/rules/*.yml` | Sigma-compatible YAML rule engine supporting field modifiers (`\|contains`, `\|startswith`, `\|endswith`, `\|re`, `\|gte`, `\|lt`, `\|in`), exclusions (`not filter`), and sliding time-window thresholds (`count() by actor >= N` in `5m`/`15m`), tagged with MITRE ATT&CK tactic and technique IDs. Paired with per-user/service behaviour baselines (off-hours logins, impossible travel, bulk data egress) and payment fraud detectors. |
| **5. Correlate** | `soccopilot/correlate.py` | Builds an entity graph linking alerts across tools within a time window into connected incidents ordered along the MITRE ATT&CK kill-chain sequence. Composite risk score (`0–100`) combines rule severity, distinct tactics, asset criticality, ₹ money at risk, and a **+18 cross-domain bonus** when cyber security alerts and payment fraud signals involve the same customer. |
| **6. AI Triage** | `soccopilot/triage.py` | Claude runs a strictly **read-only** tool-use loop (`get_incident`, `search_logs`, `entity_timeline`, `ip_reputation`, `customer_transactions`). Prompts and tool results pass through the **Project 10 LLM Privacy Gateway** (`PrivacyBridge`) so customer PII (names, PAN, phone, account numbers) is tokenized before reaching the model. Every claim in the output report cites backing `[EVT-...]` log entry IDs. Falls back to a deterministic evidence-cited report when no API key is configured. |
| **7. Respond** | `soccopilot/playbooks.py`, `soccopilot/audit.py` | Six containment playbooks (`freeze_account`, `end_sessions`, `block_ip`, `disable_cloud_key`, `require_password_reset`, `notify_customer`). Every action requires explicit analyst approval bound to a single-use SHA-256 digest of the exact action and target (the Project 04 pattern), executes through connectors, and writes to a hash-chained, HMAC-verifiable audit log. |
| **8. Console** | `soccopilot/api.py`, `web/console.html`, `soccopilot/app.py` | FastAPI web console (`http://127.0.0.1:8011`) and Streamlit console (`streamlit run app.py`) showing the incident queue, storyline timeline, entity graph, privacy-scrubbed AI report with clickable `[EVT-...]` evidence badges, approve/decline buttons, and TP/FP analyst feedback that tunes rule weights. |

## Storage Architecture

| Data | Store |
|---|---|
| Normalised events | **DuckDB** (`soccopilot/store.py:EventStore`) for single-machine analytical SQL search and entity timelines (OpenSearch/Elastic compatible schema) |
| Incidents, reports, approvals, feedback & rule weights | **SQLite** (`soccopilot/store.py:StateStore`) |
| Audit trail | Append-only hash-chained (and optional HMAC-SHA256) JSONL log (`soccopilot/audit.py:AuditLog`) |

## Benchmark Results

`python -m soccopilot evaluate` replays **6 multi-stage attack campaigns** (spanning customer ATO + MFA fatigue + ₹1.85L wire drain, CloudTrail IAM escalation + S3 KYC vault exfiltration, API IDOR enumeration + structured smurfing transfers, bastion SSH privilege escalation + 120 MB core ledger DB dump, impossible travel + device swap + ₹2.40L RTGS drain, and insider off-hours bulk export + audit tamper) mixed with **240 benign day-in-the-life banking events** (including scheduled `svc-backup-nightly` snapshots and suppressed `svc-vuln-scanner` scans):

```
CAMP-01  Customer ATO via MFA Fatigue & ₹1.85L Wire Dra  DETECTED  INC-0001  score=100.0  events=10/10  cited=100% [SEC+FRAUD]
CAMP-02  Cloud IAM Escalation & S3 KYC Vault Exfiltrati  DETECTED  INC-0004  score= 93.1  events=5/5    cited=100%
CAMP-03  API IDOR Account Enumeration & Structured Smur  DETECTED  INC-0003  score= 99.3  events=8/8    cited=100% [SEC+FRAUD]
CAMP-04  Bastion Privilege Escalation & Core Ledger DB   DETECTED  INC-0006  score= 80.0  events=3/3    cited=100%
CAMP-05  Impossible Travel, Device Swap & ₹2.40L RTGS D  DETECTED  INC-0002  score=100.0  events=5/5    cited=100% [SEC+FRAUD]
CAMP-06  Insider Off-Hours Bulk Statement Export & Audi  DETECTED  INC-0005  score= 88.1  events=3/3    cited=100%
--------------------------------------------------------------------------------------------
Detection recall:          100% (6/6 campaigns)
Security+Fraud join rate:  100%
False-positive noise/day:  0 incidents (240 benign events)
Time to first alert:       < 15 ms mean
Report citation coverage:  100% of claims backed by log IDs
```

## Run It

```bash
pip install -r requirements.txt
python -m pytest -q                              # 7 end-to-end tests
python -m soccopilot evaluate                    # benchmark across 6 multi-stage campaigns + normal traffic
python -m soccopilot triage INC-0001             # inspect structured triage report & containment proposals
python -m soccopilot serve --port 8011           # FastAPI Analyst Console on http://127.0.0.1:8011
streamlit run app.py                             # Streamlit Analyst Console
```

## Package Layout

```
11-soc-copilot/
  soccopilot/
    ingest/
      connectors.py   Wazuh, ECS, CloudTrail, Auth, API Gateway, Payments (webhook, file drop, Kafka)
      validator.py    schema validation, size limits, SHA-256 deduplication, SourceHealthMonitor
    normalize.py      ECS common schema + entity extraction
    enrich.py         asset inventory, staff directory, GeoIP + impossible travel, threat intel, customer context
    rules/            10 Sigma-compatible YAML rules tagged with MITRE ATT&CK tactics & techniques
    detect.py         Sigma rule engine (modifiers, filters, sliding windows) + behaviour baselines
    correlate.py      entity graph, ATT&CK storyline ordering, composite risk score, feedback tuning
    triage.py         Claude read-only tool loop + Project 10 privacy bridge + template fallback
    playbooks.py      6 containment playbooks + single-use SHA-256 call-bound approvals + connectors
    audit.py          tamper-evident hash-chained audit log
    store.py          DuckDB analytical event store + SQLite incident/approval/feedback store
    api.py            FastAPI server (/ingest, /health, /incidents, /incidents/{id}/report, /actions, /audit)
    app.py            Streamlit analyst console
    evaluate.py       benchmark runner & 6 multi-stage labelled campaigns
  web/console.html    Interactive web analyst console
  policy.toml         Thresholds, scoring weights, suppression lists, and playbook configuration
  tests/test_soccopilot.py
```
