-- =============================================================================
-- Security Log Analytics Dashboard - Database Schema (01_schema.sql)
-- =============================================================================

-- 1. Raw / Structured Authentication Events Table
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    ts TIMESTAMP NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    username VARCHAR(100),
    src_ip VARCHAR(45) NOT NULL,
    port INTEGER,
    source VARCHAR(100) DEFAULT 'openssh'
);

-- 2. GeoIP Enrichment Lookup Table
CREATE TABLE IF NOT EXISTS ip_enrichment (
    ip VARCHAR(45) PRIMARY KEY,
    country VARCHAR(100),
    city VARCHAR(100),
    lat DOUBLE PRECISION,
    lon DOUBLE PRECISION
);

-- 3. Security Detection Alerts Table (MITRE ATT&CK Mapped)
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    ts TIMESTAMP NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    rule VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    mitre_id VARCHAR(20) NOT NULL,
    details TEXT
);

-- 4. Indexes for Analytical & Window Function Queries
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
