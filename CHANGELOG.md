# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## 1.0.0 — 2026-11-02

### Added
- `pyproject.toml` with a `soccopilot` console command, pinned `requirements.lock` /
  `requirements-dev.lock`, and a container image (slim Python 3.12, non-root, health check).
- Settings from `SOCCOPILOT_*` environment variables, checked at startup.
  `SOCCOPILOT_ENV=production` refuses to start without hashed API keys, `SOCCOPILOT_DATA_DIR` and
  `SOCCOPILOT_AUDIT_KEY`; a data directory also needs a fixed audit key, so the trail still verifies
  after a restart. Nothing listens on a public address without keys.
- The case store (incidents, actions, feedback) on SQLAlchemy: SQLite in the data directory by
  default, Postgres through `SOCCOPILOT_DATABASE_URL`, numbered migrations and
  `python -m soccopilot migrate`. An older `state.db` is upgraded in place.
- Audit key rotation: `SOCCOPILOT_AUDIT_KEY_PREVIOUS` keeps older entries verifiable.
- A `monitor` role for `/metrics`; per-client rate limit, body cap, security headers, CORS only for
  listed origins, validation errors that don't echo input; JSON logs with request IDs;
  `/healthz`, `/readyz` and Prometheus `/metrics`.
- CI now runs ruff, bandit, pip-audit and pytest with coverage from the lock file.
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`, `docs/model-card.md`, MIT licence.

### Changed
- The DuckDB event store consumes every query result. DuckDB 2.0 refuses `register` while a result
  is still open (a `fetchone()` left one open), which turned CI red; the lock now pins DuckDB 2.0.0
  and every test passes on it.

### Unchanged
- Detection rules, correlation, triage and the benchmark: all six campaigns detected, no false
  incidents on the 240 benign events, as in the README.
