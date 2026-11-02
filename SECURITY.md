# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, through GitHub's private vulnerability
reporting on this repository (Security → Report a vulnerability) or by contacting the
maintainer, [@Ashin-06](https://github.com/Ashin-06), directly. Do not open a public issue.

Include what you found, how to reproduce it and what an attacker could do with it. You should
get an acknowledgement within 5 working days. Please give us 90 days to fix an issue before
disclosing it, and don't test against anyone else's deployment.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| < 1.0 | no (prototype releases) |

## Scope

In scope: the ingest API and validators, normalisation, detection rules, correlation, the triage
step (including what reaches the LLM), the playbook approval flow, the case store, the audit
trail, the container image and the CI configuration. A way to get customer data to the model, to
run a containment action without a second analyst, or to alter the audit trail unnoticed is the
most serious class of report.

Out of scope: attacks the rules don't detect (see `docs/model-card.md`), the simulated
connectors, and findings that need an already-compromised host or a leaked API key.

This project has **not** had an independent security review or penetration test.
