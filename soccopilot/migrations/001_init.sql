-- Cases, triage reports, playbook approvals, analyst feedback and tuned rule weights.
-- IF NOT EXISTS lets a state.db made before migrations existed upgrade in place.
-- Payloads are JSON; times are epoch seconds. Events stay in DuckDB (store.py).
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    risk_score DOUBLE PRECISION,
    severity TEXT,
    status TEXT,
    created_at DOUBLE PRECISION,
    payload_json TEXT
);

CREATE TABLE IF NOT EXISTS reports (
    incident_id TEXT PRIMARY KEY,
    created_at DOUBLE PRECISION,
    payload_json TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
    action_id TEXT PRIMARY KEY,
    incident_id TEXT,
    status TEXT,
    created_at DOUBLE PRECISION,
    payload_json TEXT
);
CREATE INDEX IF NOT EXISTS approvals_incident ON approvals (incident_id, created_at);

-- Databases from before migrations also have an autoincrement id column here; nothing reads it.
CREATE TABLE IF NOT EXISTS feedback (
    incident_id TEXT,
    verdict TEXT,
    reason TEXT,
    analyst TEXT,
    created_at DOUBLE PRECISION,
    payload_json TEXT
);

CREATE TABLE IF NOT EXISTS rule_weights (
    rule_id TEXT PRIMARY KEY,
    weight DOUBLE PRECISION
);
