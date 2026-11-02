# Model card: SOC copilot detection and triage

Rule-based detection (SIGMA-style YAML rules), graph correlation and LLM-drafted reports. Numbers come
from `docs/evaluation.md` and `results/real_data.json`.

## What it does

Normalises events from logins, APIs, servers, cloud accounts and the payments switch; runs 13
detection rules; groups alerts that share entities into incidents with a composite risk score; drafts
a report with an LLM (or a template) that must cite event IDs; proposes containment playbooks that
need an approver.

## Intended use

Helping a bank's security analysts sort and investigate alerts. Every action it proposes needs a
human approver; it is not meant to contain threats by itself or to replace a SIEM.

## Evaluation

| Test | Result |
|---|---|
| Six built-in multi-stage campaigns with 240 normal events | all six detected, no false incidents, 100% of report claims cite log IDs. The rules were written with these campaigns in view: a regression check, not recall. |
| flaws.cloud CloudTrail, first 50,000 events | alerts 7,962 → 51 and incidents 2,448 → 17 after tuning on this data; 42 → 2,816 events/s |
| flaws.cloud, first 100,000 events | 130 alerts (13 per 10,000 events) and 32 incidents |
| OTRF EC2 credential exfiltration | **not detected**: needs the instance's own IP addresses |
| OTRF decoy S3 bucket | 216 alerts from a rule written after looking at this data (in-sample) |

There are no incident labels for the real logs, so only alert volume, speed and the recorded attacks
can be checked.

## Known failure modes

- Stolen instance credentials and bulk S3 downloads are not detected in real CloudTrail.
- Rule thresholds were tuned on the same flaws.cloud data they are reported on.
- Each batch re-correlates all alerts: fine for a team's daily volume, not for a full SIEM feed.
- LLM reports can be wrong; the citation check only ensures each claim points at an event.

## Before relying on it

Run it on the bank's own labelled incidents (`evaluate --labelled`), measure recall and alert volume
per rule, and route triage through project 10's privacy gateway.
