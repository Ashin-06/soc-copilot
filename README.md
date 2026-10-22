# SOC Copilot for a Digital Bank

A bank's security team gets thousands of alerts a day from logins, APIs, servers, cloud infrastructure and the payments switch. Most are noise, and the real incidents are scattered across different tools.

This copilot:
- pulls those signals together and groups related alerts into incidents;
- links security events to payment fraud on the same customer;
- drafts an evidence-cited investigation report with Claude, without showing it customer data;
- suggests containment steps that only run after an analyst approves them.

```
Log sources ──► 1 Ingest ──► 2 Normalise ──► 3 Enrich ──► 4 Detect ──► 5 Correlate ──► 6 Triage (Claude) ──► 7 Respond
(auth, API,       connectors    common schema    context       rules +       alerts →          report draft         playbooks,
 payments,        + validation  + entities       lookups       baselines     incidents         with evidence        analyst approval
 servers, cloud)                                                                                                    + audit
                                                                      ▲                                  │
                                                                      └──────── 8 Analyst console ◄──────┘
                                                                           (feedback tunes rules and scores)
```

## Stages

| Stage | Module | What it does |
|---|---|---|
| **1. Ingest** | `soccopilot/ingest/` | Connectors for **Wazuh**, **Elastic ECS**, **AWS CloudTrail**, **auth/SSO**, **API gateway** and **payments**, by HTTP webhook, file drop (JSON, JSONL, CloudTrail `Records`) or record batches handed over by your Kafka consumer. Each event is checked for size, required fields and a sane timestamp (epoch seconds or milliseconds, ISO 8601; NaN and far-future values are rejected). Events are deduplicated by SHA-256 inside a bounded window. A bad record is rejected on its own without failing the batch. Every source has a silence alarm. |
| **2. Normalise** | `normalize.py` | Maps every source onto one ECS-style schema and extracts typed entities (`user:`, `customer:`, `ip:`, `device:`, `host:`, `account:`, `cloud_key:`). Untrusted fields are coerced to the expected type or dropped. An event keeps its source ID when it is a citable `EVT-…` ID that is not taken yet. Otherwise it gets a hash-derived ID, and the original is kept in `details.source_event_id`. |
| **3. Enrich** | `enrich.py` | Adds asset criticality (1–5), the staff directory (role, privilege tier, working hours and time zone), customer context (account age, average transfer, recent beneficiary, device or phone changes), GeoIP with impossible-travel speed, and IP/domain threat intel. Addresses it cannot place are `UNKNOWN`, never guessed. The demo directories can be replaced with a JSON export of your own (see Settings). |
| **4. Detect** | `detect.py`, `rules/*.yml` | Sigma-style YAML rules with field modifiers (`contains`, `startswith`, `endswith`, `re`, `in`, `gt/gte/lt/lte`), `and not filter` exclusions, and windowed counts (`count() by actor >= 4` in `5m`), tagged with ATT&CK tactics and techniques. Unsupported syntax is refused when the rules load, instead of quietly never firing. Alongside the rules run behaviour baselines: off-hours staff logins in the employee's own time zone, impossible travel, bulk egress, and SIM/device swap before a large transfer. |
| **5. Correlate** | `correlate.py` | Alerts that share a strong entity within an hour become one incident. Each incident gets an ATT&CK-ordered storyline and a 0–100 risk score: rule severity, tactic spread, asset criticality, rupees at risk, plus a cross-domain bonus when security alerts and payments involve the same customer. Incident IDs are stable: as an incident grows, or after a restart, it keeps its ID, status and analyst feedback. Feedback tunes rule weights. It can quieten a noisy low or medium rule, but never switches off a high or critical one. |
| **6. Triage** | `triage.py` | Claude works through **read-only** tools (`get_incident`, `search_logs`, `entity_timeline`, `ip_reputation`, `customer_transactions`). Every tool result passes through the LLM Privacy Gateway engine (project 10), or a built-in masker when that project is not installed, so names, PAN, accounts, phones and emails reach the model only as placeholders. Every claim must cite `[EVT-…]` IDs, and coverage is measured. Without an API key, or if the model refuses or returns something unusable, a deterministic cited report is produced and the reason is recorded. |
| **7. Respond** | `playbooks.py`, `audit.py` | Six playbooks: `freeze_account`, `end_sessions`, `block_ip`, `disable_cloud_key`, `require_password_reset`, `notify_customer`. Each approval is bound to a single-use SHA-256 digest of the exact action and target. Every proposal, decision, execution, expiry and failure goes into a hash-chained, optionally HMAC-keyed audit log. |
| **8. Console** | `api.py`, `web/console.html`, `app.py` | FastAPI web console and a Streamlit console. Both show the queue, storyline, entity graph, cited report and approval buttons, and take TP/FP feedback. |

## What stops it doing damage

- **The model can't act.** It only has read tools. Containment it suggests is queued for a person to approve.
- **Suggestions are checked.** A suggested action is kept only if the action is enabled in policy and the target is an entity of the right kind in the same incident. That way, text planted in a log line can't steer a proposal at an unrelated account. `block_ip` is limited to public addresses that are known-bad or were the source of a security alert, so a customer's home connection or an internal range is never proposed.
- **Four eyes.** An analyst who raises an action by hand can't approve it. Approvals expire after an hour and can't be replayed or edited after approval.
- **Who did it is not self-declared.** With API keys configured, the key decides the user and role (`ingest`, `viewer`, `analyst`, `approver`, `admin`). A name in the request body is ignored.
- **Customer data stays masked.** The model sees `[[ACCOUNT_1:2011]]`, not the account number. Values are put back only in the stored report, for the configured role.
- **Log text is shown as text.** Both consoles escape or plain-render titles, entities, model output and rationales.
- **Tampering shows.** Editing, deleting, reordering or truncating the audit log fails verification, and the service won't start on a damaged log.

## Benchmark

`python -m soccopilot evaluate` replays six labelled multi-stage campaigns mixed with 240 benign day-in-the-life events. The benign events include `svc-backup-nightly` snapshots and suppressed `svc-vuln-scanner` scans. The six campaigns are:
1. Customer ATO with MFA fatigue and a ₹1.85L wire.
2. CloudTrail IAM escalation and KYC bucket exfiltration.
3. API account enumeration with structured transfers.
4. Bastion privilege escalation and a ledger DB dump.
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
Batch latency:             ~200-300 ms per campaign batch on a laptop (ingest to incident)
Report citation coverage:  100% of claims backed by log IDs
```

**Read this as a regression check, not a recall estimate.** The rules and baselines were written with these campaigns in view. To measure the copilot on your own data, label a JSONL export. Each line is a raw event with a unique `event_id`, plus a `label` naming the incident it belongs to; leave `label` out for benign events:

```jsonl
{"event_id": "EVT-90001", "label": "case-17", "source_type": "auth", "ts": 1761039000, "action": "login_failed", "customer_id": "C-88"}
{"event_id": "EVT-90002", "source_type": "payments", "ts": 1761039060, "action": "upi_transfer", "amount": 450, "account": "1234567890123"}
```

```bash
python -m soccopilot evaluate --labelled my_events.jsonl --json results.json
```

## Run it

```bash
pip install -r requirements.txt
python -m pytest -q                      # 47 tests
python -m soccopilot evaluate            # built-in benchmark
python -m soccopilot triage              # report and containment proposals for the top incident (--live uses Claude)
python -m soccopilot ingest events.jsonl # run a file through the whole pipeline
python -m soccopilot serve --port 8011   # web console on http://127.0.0.1:8011
streamlit run app.py                     # Streamlit console
```

### Web API and roles

| Endpoint | Needs |
|---|---|
| `GET /health`, `/incidents`, `/incidents/{id}`, `/incidents/{id}/report`, `/actions`, `/audit` | `viewer` and above |
| `POST /ingest` | `ingest`, `analyst`, `admin` |
| `POST /incidents/{id}/report` (`{"use_llm": true}` for Claude), `/incidents/{id}/feedback`, `/actions` | `analyst`, `approver`, `admin` |
| `POST /actions/{id}/decide` | `approver`, `admin` |
| `GET /evaluate`, `POST /reset` | `admin` |

Send the key as `x-api-key` or `Authorization: Bearer …`. **With no keys configured the API runs in demo mode:** every endpoint is open and the console's analyst name is trusted. `/health` says which mode is active.

## Settings

| Variable | Purpose |
|---|---|
| `SOCCOPILOT_API_KEYS` / `SOCCOPILOT_KEYS_FILE` | JSON `{"<key>": {"user": "meera", "role": "analyst"}, …}`; keys are held only as SHA-256 hashes |
| `SOCCOPILOT_DATA_DIR` | keep events (DuckDB), cases (SQLite) and the audit log on disk here, with no demo seeding; state is rebuilt on restart |
| `SOCCOPILOT_AUDIT_KEY` | HMAC key for the audit chain |
| `SOCCOPILOT_POLICY` | alternative to `policy.toml`: thresholds, suppressions, scoring weights, triage model, enabled playbooks |
| `SOCCOPILOT_CONTEXT` | JSON with `assets`, `staff`, `customers`, `geo_prefixes`, `threat_intel_ips` to replace the demo directories |
| `ANTHROPIC_API_KEY`, `SOCCOPILOT_MODEL` | live triage with Claude (default `claude-opus-5-5`) |
| `SOCCOPILOT_LLM_BASE_URL` | send triage traffic through a deployed privacy gateway |
| `SOCCOPILOT_PRIVGATE_DIR` | where project 10 is, if not next to this folder |

## Layout

```
soccopilot/
  ingest/        connectors (webhook, file drop, Kafka), validation, dedupe, source health
  normalize.py   common schema, entities, event IDs
  enrich.py      assets, staff, customers, GeoIP + impossible travel, threat intel
  rules/         10 Sigma-style rules tagged with ATT&CK
  detect.py      rule engine + behaviour baselines
  correlate.py   entity grouping, storyline, risk score, stable IDs, feedback tuning
  triage.py      read-only Claude loop, privacy bridge, recommendation checks, template report
  playbooks.py   containment playbooks, call-bound approvals, connectors
  pipeline.py    runs the stages; analyst actions shared by both consoles
  store.py       DuckDB event store, SQLite case store
  audit.py       hash-chained audit log
  api.py         FastAPI + auth
  app.py         Streamlit console
  evaluate.py    labelled campaigns, benchmark, labelled-file scoring
web/console.html
policy.toml
```

## Limits

- **Connectors are simulated.** `ConnectorSuite` records what it would do. Wire it to your firewall, IdP, core banking and cloud IAM APIs before relying on it.
- **One process.** State is guarded by a single lock, and every batch re-correlates all alerts. That is fine for a team's daily volume, not for a whole SIEM firehose. At that scale, window correlation by time and move the case store to Postgres.
- **The Streamlit console has no login.** Run it behind your SSO proxy, or use the web console with API keys.
- **No rate limiting** on the API. Put it behind your gateway.
- **The built-in masker covers fewer identifier types than project 10** (no Aadhaar, card or UPI checks), and restores values for every role. Install project 10 alongside this one for real use.
