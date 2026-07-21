-- Agents detected and identified on this machine
CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,           -- "Cursor", "Claude Code"
    process_name TEXT,            -- actual OS process name
    pid INTEGER,                  -- current PID if active
    approved INTEGER DEFAULT 0,   -- 0=pending, 1=approved, 2=blocked
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_count INTEGER DEFAULT 0
);

-- Individual event log (aggregated, not raw)
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER REFERENCES agents(id),
    session_id TEXT NOT NULL,     -- groups events per agent session
    event_type TEXT NOT NULL,     -- file_read, file_write, file_delete,
                                  -- net_connect, proc_spawn, cred_access,
                                  -- mcp_connect
    path TEXT,                    -- file path or network destination
    detail TEXT,                  -- JSON: extra context per event type
    file_count INTEGER DEFAULT 1, -- for aggregated file events
    data_volume_bytes INTEGER,    -- for network events
    severity TEXT DEFAULT 'low',  -- low, medium, high, critical
    anomaly_score REAL DEFAULT 0, -- 0.0-1.0, from baseline layer
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Alerts generated from events
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER REFERENCES events(id),
    agent_id INTEGER REFERENCES agents(id),
    severity TEXT NOT NULL,       -- low, medium, high, critical
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT DEFAULT 'open',   -- open, investigating, dismissed,
                                  -- exception_approved, risk_accepted
    resolved_by TEXT,             -- username who resolved
    resolved_at TIMESTAMP,
    resolution_note TEXT,         -- required for exception/risk_accepted
    rule_type TEXT DEFAULT 'policy', -- 'policy' or 'red_line' — red_line
                                      -- alerts are the non-disableable floor
                                      -- and cannot be resolved from the UI
    session_id TEXT,              -- set directly by session-level detectors
                                   -- (e.g. Layer 2b) that have no single
                                   -- triggering event_id to join through
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Policy definition (Frank Besadesky model)
CREATE TABLE IF NOT EXISTS policy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_key TEXT UNIQUE NOT NULL,
    policy_value TEXT NOT NULL,   -- JSON
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Statistical baseline per agent (Layer 1 learning)
CREATE TABLE IF NOT EXISTS baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER REFERENCES agents(id),
    metric_name TEXT NOT NULL,    -- "file_read_count", "net_egress_mb"
    metric_scope TEXT,            -- path pattern or destination
    sample_count INTEGER DEFAULT 0,
    mean_value REAL DEFAULT 0,
    stddev_value REAL DEFAULT 0,
    min_value REAL,
    max_value REAL,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(agent_id, metric_name, metric_scope)
);

-- Audit log — every approval, dismissal, exception recorded
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,    -- alert, agent, policy
    entity_id INTEGER,
    actor TEXT DEFAULT 'admin',
    detail TEXT,                  -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions — one row per agent run
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,          -- UUID
    agent_id INTEGER REFERENCES agents(id),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP,
    file_reads INTEGER DEFAULT 0,
    file_writes INTEGER DEFAULT 0,
    net_egress_bytes INTEGER DEFAULT 0,
    proc_spawns INTEGER DEFAULT 0,
    cred_accesses INTEGER DEFAULT 0,
    mcp_connects INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    anomaly_score REAL DEFAULT 0,
    summary TEXT                  -- plain-English digest, set when the
                                   -- session closes (core/digest.py)
);

-- User-defined suppressions for recurring false positives, e.g. a specific
-- agent + rule + destination/path pattern that's known-safe on this machine.
CREATE TABLE IF NOT EXISTS noise_suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_name TEXT,
    rule_type TEXT,
    target_pattern TEXT,
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Small generic key/value counters, e.g. suppressed_alerts. Not for
-- anything that needs querying/aggregation — that belongs in a real table.
CREATE TABLE IF NOT EXISTS stats_kv (
    key TEXT PRIMARY KEY,
    value INTEGER DEFAULT 0
);

-- Generic app config (e.g. webhook_url) — string values, unlike stats_kv's
-- integer counters. Read/written via backend/api/config_api.py.
CREATE TABLE IF NOT EXISTS app_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_suppressions_lookup ON noise_suppressions(agent_name, rule_type);
