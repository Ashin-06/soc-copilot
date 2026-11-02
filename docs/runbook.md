# Runbook

How to deploy, configure and operate the SOC copilot. Commands assume the repository root.

## Deploy

```bash
docker build -t soc-copilot:1.0.0 .
python -m soccopilot.ops keygen              # API keys per shipper, analyst, approver and monitor, plus the audit key
docker run -d --name soccopilot -p 8011:8011 -v soccopilot-data:/data \
  -e SOCCOPILOT_KEYS_FILE=/run/secrets/soccopilot-keys.json \
  -e SOCCOPILOT_AUDIT_KEY=... -e ANTHROPIC_API_KEY=... \
  soc-copilot:1.0.0
curl -fsS http://127.0.0.1:8011/readyz
```

The image runs in production mode as a non-root user. Events (DuckDB), the case store (SQLite) and
the audit trail live in the `/data` volume. It refuses to start, and logs why, without keys, the
data directory or the audit key. Terminate TLS in front of it. Run one instance: the event store is
a local DuckDB file. To route triage through project 10's privacy gateway, set
`SOCCOPILOT_LLM_BASE_URL`.

Without Docker: `pip install -r requirements.lock && pip install -e .`, then `soccopilot serve`.

## Configure

| Variable | Required in production | Meaning |
|---|---|---|
| `SOCCOPILOT_ENV` | — | `development` (default) or `production` |
| `SOCCOPILOT_API_KEYS` / `SOCCOPILOT_KEYS_FILE` | yes | JSON `{"sha256:<hex>": {"user": "...", "role": "..."}}`. Roles: `ingest`, `viewer`, `analyst`, `approver`, `monitor`, `admin` |
| `SOCCOPILOT_DATA_DIR` | yes | events, the default case store and the audit trail |
| `SOCCOPILOT_AUDIT_KEY` | yes | base64, at least 32 bytes; `SOCCOPILOT_AUDIT_KEY_PREVIOUS` for rotation |
| `SOCCOPILOT_DATABASE_URL` | — | case store; default `state.db` in the data directory, or `postgresql://...` |
| `ANTHROPIC_API_KEY`, `SOCCOPILOT_MODEL`, `SOCCOPILOT_LLM_BASE_URL` | for live triage | LLM credentials, model and an optional gateway |
| `SOCCOPILOT_POLICY`, `SOCCOPILOT_CONTEXT` | — | thresholds and playbooks; your assets, staff, customers and network ranges |
| `SOCCOPILOT_HOST`, `SOCCOPILOT_PORT` | — | default `127.0.0.1:8011`; a non-loopback address needs API keys |
| `SOCCOPILOT_RATE_LIMIT`, `SOCCOPILOT_MAX_BODY_BYTES` | — | default 120/min per client (raise it for shippers), 10,000,000 bytes |

## Watch

- `GET /healthz`: process up. `GET /readyz`: case store and event store answer. `GET /health`
  (role `viewer`): per-source heartbeats, quiet sources and audit-chain status.
- `GET /metrics` (role `monitor`): request counts and latency, `errors_total`, decisions.
- Logs: JSON lines with `request_id`.

Suggested alerts: `/readyz` failing; a source going quiet (`/health` lists it); the audit chain
reported as broken; actions waiting for approval longer than your SLA.

## Rotate keys

**API keys.** Add the new hash, restart, hand over the key, remove the old hash, restart.
**Audit key.** Set `SOCCOPILOT_AUDIT_KEY_PREVIOUS` to the current key and `SOCCOPILOT_AUDIT_KEY` to a
new one, restart. Keep old keys as long as you keep the entries they signed.

## Back up and restore

Stop the container, copy the whole `/data` volume (events, case store, audit trail together), and
start it again. Restore the same way, then check `/readyz` and that `/health` reports the audit chain
as verified. With Postgres for the case store, also `pg_dump` / `pg_restore`.

## Incidents

1. **Audit chain broken.** Stop writes, copy the data directory, and compare with the last backup to
   find the first changed entry. Treat it as tampering until shown otherwise.
2. **Customer data seen in an LLM prompt.** Find the triage request by request ID, check whether the
   built-in masker or project 10 was used, add the missing pattern, and follow the bank's data-breach
   procedure.
3. **Leaked API key.** Remove its hash and restart; review that user's ingests, proposals and approvals.
