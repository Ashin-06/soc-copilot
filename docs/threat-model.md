# Threat model

What the SOC copilot protects, from whom, and what is still open. Written for the 1.0.0 code;
nobody independent has reviewed it.

## What it protects

| Asset | Where it lives |
|---|---|
| Security and payment events (users, customers, IPs, accounts, amounts) | DuckDB event store in `SOCCOPILOT_DATA_DIR` |
| Incidents, proposed and approved actions, analyst feedback | case store (`SOCCOPILOT_DATABASE_URL`) |
| The audit trail of every decision | `audit.jsonl` in the data directory, HMAC-chained |
| What the LLM sees during triage | masked text only (project 10's gateway or the built-in masker) |
| API keys, the audit key, the LLM key | environment / secret store; API keys held only as hashes |

## Trust boundaries

```
log shippers (ingest) ──► API ──► event store, case store, audit trail
analysts / approvers  ──►  │
                           └──► LLM provider (masked text only) ;  connectors (simulated)
```

## Threats and what stops them

| Threat | Mitigation | Residual risk |
|---|---|---|
| Forged or flooded events hide an attack | `ingest` keys only submit; validators reject malformed events; per-client rate limit; 10 MB body cap | A compromised shipper can still send false events |
| Customer data reaches the LLM | Every prompt is masked; citations use event IDs, not values | The built-in masker covers fewer identifier types than project 10; deploy the gateway for real use |
| A containment action runs without review | Actions need a second analyst with the `approver` role; the decision is checked against the proposal's digest | Approvers can collude |
| The audit trail is edited | HMAC chain with a fixed key in production; rotation keeps old entries verifiable | Truncating the newest entries is only caught with an external copy of the head |
| Reading incidents without need | Roles on keys; no CORS unless listed | Every `viewer` sees every incident |
| Errors leak data | Validation errors don't echo input; unhandled errors return only a request ID | — |

## Not covered

- Real connectors (firewall, identity provider, core banking, cloud IAM): `ConnectorSuite` only
  records what it would do.
- The Streamlit console has no login.
- TLS (terminate it at the ingress).
