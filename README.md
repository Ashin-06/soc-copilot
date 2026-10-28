# SOC Copilot for a Digital Bank

A bank's security team gets thousands of alerts a day from logins, APIs, servers, cloud accounts and the payments switch. Most are noise, and real incidents are spread across several tools.

This copilot:
- collects those signals and groups related alerts into incidents;
- links security events to payment fraud on the same customer;
- drafts an investigation report with an LLM, citing the log entries behind every statement, without showing the model customer data;
- suggests containment steps that only run after an analyst approves them.

```
Log sources ──► 1 Ingest ──► 2 Normalise ──► 3 Enrich ──► 4 Detect ──► 5 Correlate ──► 6 Triage ──► 7 Respond
                                                                            ▲                          │
                                                                            └──── 8 Analyst console ◄───┘
```

## Pipeline

| Stage | Module | What it does |
|---|---|---|
| 1. Ingest | `soccopilot/ingest/` | Reads Wazuh, Elastic ECS, AWS CloudTrail, login, API gateway and payment events by webhook, file drop or Kafka batches. Checks size, required fields and timestamps, removes duplicates, and raises an alarm when a source goes silent. |
| 2. Normalise | `normalize.py` | Maps every source to one schema and extracts users, customers, IPs, devices, hosts, accounts and cloud keys. |
| 3. Enrich | `enrich.py` | Adds asset importance, staff details (role, working hours, time zone), customer context, location with impossible-travel checks and threat intelligence. |
| 4. Detect | `detect.py`, `rules/*.yml` | Sigma-style YAML rules with filters, time-window counts and repeat suppression, tagged with MITRE ATT&CK, plus behaviour checks such as off-hours staff logins and a SIM or device swap before a large transfer. |
| 5. Correlate | `correlate.py` | Groups alerts that share an entity within an hour into one incident with a timeline and a 0–100 risk score. Incident IDs stay the same as an incident grows. Analyst feedback adjusts rule weights. |
| 6. Triage | `triage.py` | The LLM investigates through read-only tools. Customer identifiers are replaced with placeholders before it sees any data, and every claim in its report must cite log IDs. Without an API key, a template report is produced instead. |
| 7. Respond | `playbooks.py`, `audit.py` | Six playbooks (freeze account, end sessions, block IP, disable cloud key, force password reset, notify customer). Each approval is tied to one exact action and logged in a tamper-evident audit trail. |
| 8. Console | `api.py`, `web/console.html`, `app.py` | Web and Streamlit consoles with the incident queue, timeline, entity graph, report, approvals and feedback. |

## Safeguards

- The model can only read. Anything it suggests waits for a person to approve.
- A suggested action is kept only if it is enabled in the policy and targets an entity from the same incident, so text planted in a log line can't aim it at another account.
- An analyst who raises an action can't approve it. Approvals expire after an hour and can't be reused.
- With API keys configured, the key decides who the user is and what role they have; names in the request are ignored.
- The model sees `[[ACCOUNT_1:2011]]`, not the account number. Customer identifiers are masked by the LLM Privacy Gateway (project 10) when it is installed alongside, or by a simpler built-in masker.
- Editing, deleting or reordering the audit log is detected, and the service won't start on a damaged log.

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q
python -m soccopilot evaluate            # built-in benchmark
python -m soccopilot triage              # report for the top incident; --live uses the LLM
python -m soccopilot ingest events.jsonl # run a file through the pipeline
python -m soccopilot serve --port 8011   # web console on http://127.0.0.1:8011
streamlit run app.py                     # Streamlit console
```

## API and roles

| Endpoint | Roles |
|---|---|
| `GET /health`, `/incidents`, `/incidents/{id}`, `/incidents/{id}/report`, `/actions`, `/audit` | `viewer` and above |
| `POST /ingest` | `ingest`, `analyst`, `admin` |
| `POST /incidents/{id}/report`, `/incidents/{id}/feedback`, `/actions` | `analyst`, `approver`, `admin` |
| `POST /actions/{id}/decide` | `approver`, `admin` |
| `GET /evaluate`, `POST /reset` | `admin` |

Send the key as `x-api-key` or `Authorization: Bearer`. Without keys the API runs in demo mode and every endpoint is open.

## Results

| Test | Result |
|---|---|
| Six built-in attack campaigns with 240 normal events | all six detected, no false incidents (a regression check, since the rules were written with them in view) |
| Real AWS CloudTrail logs (flaws.cloud, first 50,000 events) | alerts cut from 7,962 to 51 and incidents from 2,448 to 17 after tuning; 42 → 2,816 events/s |
| Recorded EC2 credential theft (OTRF) | not detected; needs the instance's own IP addresses |

Details are in [docs/evaluation.md](docs/evaluation.md).

## Configuration

| Variable | Purpose |
|---|---|
| `SOCCOPILOT_API_KEYS` / `SOCCOPILOT_KEYS_FILE` | API keys with the user and role for each, stored as SHA-256 hashes |
| `SOCCOPILOT_DATA_DIR` | keep events, cases and the audit log on disk |
| `SOCCOPILOT_AUDIT_KEY` | HMAC key for the audit log |
| `SOCCOPILOT_POLICY` | alternative to `policy.toml`: thresholds, suppressions, scoring weights, model, enabled playbooks |
| `SOCCOPILOT_CONTEXT` | JSON with your own assets, staff, customers, network ranges and threat intelligence |
| `ANTHROPIC_API_KEY`, `SOCCOPILOT_MODEL` | LLM credentials and model for live triage |
| `SOCCOPILOT_LLM_BASE_URL` | send triage traffic through a deployed privacy gateway |

## Project layout

```
soccopilot/
  ingest/        connectors, validation, duplicates, source health
  normalize.py   common schema and entities
  enrich.py      context lookups
  rules/         13 detection rules
  detect.py      rule engine and behaviour checks
  correlate.py   incidents, timelines and risk scores
  triage.py      read-only LLM investigation and template report
  playbooks.py   containment playbooks and approvals
  pipeline.py    runs the stages
  store.py       event and case storage
  audit.py       audit log
  api.py         FastAPI service
  evaluate.py    benchmark and labelled-file scoring
  realdata.py    replay of public CloudTrail datasets
app.py           Streamlit console
web/console.html
policy.toml
```

## Limitations

- Connectors to firewalls, identity providers, core banking and cloud IAM are simulated; `ConnectorSuite` records what it would do.
- Everything runs in one process and each batch re-correlates all alerts, which suits a team's daily volume but not a full SIEM feed.
- Bulk S3 downloads and stolen instance credentials are not detected in real CloudTrail data yet.
- The Streamlit console has no login; run it behind single sign-on or use the web console with API keys.
- The API has no rate limiting yet; put it behind your gateway.
- The built-in masker covers fewer identifier types than project 10; install project 10 alongside for real use.
- With no live feed, the demo reports its sources as silent after a few minutes. That is the silence alarm working.
