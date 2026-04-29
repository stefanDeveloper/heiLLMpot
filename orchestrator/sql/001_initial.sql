-- Honeypot Orchestrator — PostgreSQL Schema
-- Run once on the orchestrator's database.
-- Usage: psql -U orchestrator -d honeypot_db -f 001_initial.sql

-- Enable UUID support
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";   -- for text search on raw JSON fields

-- ---------------------------------------------------------------------------
-- Registered honeypot nodes
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS honeypot_nodes (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         TEXT        UNIQUE NOT NULL,   -- e.g. "node-eu-west-1"
    region          TEXT,
    ip_address      INET,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ,
    config_hash     TEXT,                          -- SHA-256 of honeypot.json
    api_key_hash    TEXT        NOT NULL,          -- bcrypt hash of per-node API key
    active          BOOLEAN     NOT NULL DEFAULT TRUE
);

-- ---------------------------------------------------------------------------
-- Per-connection sessions (one row = one attacker TCP session)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         TEXT        NOT NULL REFERENCES honeypot_nodes(node_id) ON DELETE CASCADE,
    protocol        TEXT        NOT NULL CHECK (protocol IN ('http','ssh','unknown')),
    session_ref     TEXT        NOT NULL,           -- original session_id / connection_id from honeypot
    client_ip       INET,
    client_port     INT,
    geo_country     TEXT,
    geo_country_iso TEXT,
    geo_city        TEXT,
    geo_asn         INT,
    geo_org         TEXT,
    started_at      TIMESTAMPTZ,
    ended_at        TIMESTAMPTZ,
    duration_sec    DOUBLE PRECISION,
    event_count     INT         NOT NULL DEFAULT 0,
    UNIQUE (node_id, session_ref)
);

CREATE INDEX IF NOT EXISTS idx_sessions_node      ON sessions(node_id);
CREATE INDEX IF NOT EXISTS idx_sessions_ip        ON sessions(client_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_started   ON sessions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_protocol  ON sessions(protocol);

-- ---------------------------------------------------------------------------
-- Individual log events (one row per Logger::log() call)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL   PRIMARY KEY,
    session_id  UUID        REFERENCES sessions(id) ON DELETE CASCADE,
    node_id     TEXT        NOT NULL,
    protocol    TEXT        NOT NULL,
    event_type  TEXT        NOT NULL,   -- 'request'|'credential'|'command'|'connect'|'disconnect'|…
    occurred_at TIMESTAMPTZ NOT NULL,
    raw         JSONB       NOT NULL    -- full original JSON log entry
);

CREATE INDEX IF NOT EXISTS idx_events_session    ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_occurred   ON events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_type       ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_raw        ON events USING GIN(raw);

-- ---------------------------------------------------------------------------
-- Credential attempts (SSH + HTTP login)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS credentials (
    id          BIGSERIAL   PRIMARY KEY,
    session_id  UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    node_id     TEXT        NOT NULL,
    protocol    TEXT        NOT NULL,
    username    TEXT,
    password    TEXT,
    occurred_at TIMESTAMPTZ NOT NULL,
    success     BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_cred_username    ON credentials(username);
CREATE INDEX IF NOT EXISTS idx_cred_password    ON credentials(password);
CREATE INDEX IF NOT EXISTS idx_cred_session     ON credentials(session_id);

-- ---------------------------------------------------------------------------
-- HTTP-specific request log
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS http_requests (
    id              BIGSERIAL   PRIMARY KEY,
    session_id      UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    node_id         TEXT        NOT NULL,
    method          TEXT,
    path            TEXT,
    status_code     INT,
    user_agent      TEXT,
    referer         TEXT,
    content_type    TEXT,
    body_size_bytes INT,
    occurred_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_http_session   ON http_requests(session_id);
CREATE INDEX IF NOT EXISTS idx_http_path      ON http_requests(path);
CREATE INDEX IF NOT EXISTS idx_http_ua        ON http_requests(user_agent);

-- ---------------------------------------------------------------------------
-- Bot / Human classification result (one row per session)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bot_classifications (
    session_id      UUID        PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    label           TEXT        NOT NULL CHECK (label IN ('bot','human','unknown')),
    confidence      DOUBLE PRECISION CHECK (confidence BETWEEN 0.0 AND 1.0),
    method          TEXT        NOT NULL DEFAULT 'rules',  -- 'rules' | 'isolation_forest' | 'custom_model'
    features        JSONB,
    triggered_rules TEXT[],
    classified_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    human_override  TEXT        CHECK (human_override IN ('bot','human'))  -- for training data labelling
);

-- ---------------------------------------------------------------------------
-- Materialized daily statistics view (refresh every 5 min via pg_cron or worker)
-- ---------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS daily_stats AS
SELECT
    date_trunc('day', s.started_at)         AS day,
    s.node_id,
    s.protocol,
    COALESCE(bc.label, 'unclassified')      AS label,
    COUNT(*)                                AS session_count,
    COUNT(DISTINCT s.client_ip)             AS unique_ips,
    COUNT(DISTINCT s.geo_country_iso)       AS unique_countries,
    AVG(s.duration_sec)                     AS avg_duration_sec,
    SUM(s.event_count)                      AS total_events
FROM sessions s
LEFT JOIN bot_classifications bc ON bc.session_id = s.id
WHERE s.started_at IS NOT NULL
GROUP BY 1, 2, 3, 4
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_daily_stats
    ON daily_stats(day, node_id, protocol, label);

-- Grant minimal permissions to app user
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO orchestrator_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO orchestrator_app;
