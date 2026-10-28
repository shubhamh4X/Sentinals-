-- ============================================================================
-- Sentinel AC — PostgreSQL 16 Schema Migration
-- File: database/migrations/001_initial_schema.sql
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS roles (
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(32) NOT NULL UNIQUE CHECK (role_name IN ('Administrator', 'Security Analyst', 'Read-Only Viewer')),
    permissions JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    firebase_uid VARCHAR(128) NOT NULL UNIQUE,
    email VARCHAR(254) NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    role_name VARCHAR(32) NOT NULL REFERENCES roles(role_name),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR(128) PRIMARY KEY,
    owner_uid VARCHAR(128) NOT NULL,
    hostname VARCHAR(120) NOT NULL,
    os_version VARCHAR(120) NOT NULL,
    agent_version VARCHAR(40) NOT NULL,
    credential_fingerprint VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL CHECK (status IN ('healthy', 'degraded', 'disconnected', 'revoked')),
    integrity_status VARCHAR(32) NOT NULL CHECK (integrity_status IN ('verified', 'tamper_suspected', 'signature_mismatch')),
    risk_score NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    is_simulated BOOLEAN NOT NULL DEFAULT FALSE,
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS emulator_sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    device_id VARCHAR(128) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    emulator_name VARCHAR(80) NOT NULL,
    free_fire_package VARCHAR(80) NOT NULL,
    session_state VARCHAR(32) NOT NULL CHECK (session_state IN ('idle', 'launching', 'active_match', 'terminated')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS signed_rule_versions (
    bundle_id VARCHAR(128) PRIMARY KEY,
    bundle_version VARCHAR(32) NOT NULL,
    signer_key_id VARCHAR(128) NOT NULL,
    ed25519_signature TEXT NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    deployed_by_email VARCHAR(254) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id VARCHAR(64) PRIMARY KEY,
    version VARCHAR(32) NOT NULL,
    name VARCHAR(160) NOT NULL,
    category VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    classification VARCHAR(32) NOT NULL CHECK (classification IN ('informational', 'suspicious', 'strongly_indicative')),
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    risk_score_contribution SMALLINT NOT NULL CHECK (risk_score_contribution BETWEEN 0 AND 100),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    detection_source VARCHAR(120) NOT NULL,
    description TEXT NOT NULL,
    false_positive_considerations TEXT NOT NULL,
    investigation_steps TEXT NOT NULL,
    signature_hash VARCHAR(256) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security_events (
    event_id VARCHAR(128) PRIMARY KEY,
    device_id VARCHAR(128) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    session_id VARCHAR(128) NOT NULL,
    rule_id VARCHAR(64) NOT NULL,
    rule_version VARCHAR(32) NOT NULL,
    category VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    classification VARCHAR(32) NOT NULL,
    confidence SMALLINT NOT NULL,
    risk_contribution SMALLINT NOT NULL,
    process_name VARCHAR(160) NOT NULL,
    process_path VARCHAR(512) NOT NULL,
    sha256 VARCHAR(128) NOT NULL,
    signer_identity VARCHAR(200) NOT NULL,
    summary TEXT NOT NULL,
    detection_source VARCHAR(120) NOT NULL,
    is_simulated BOOLEAN NOT NULL DEFAULT FALSE,
    event_timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id VARCHAR(128) PRIMARY KEY,
    device_id VARCHAR(128) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    title VARCHAR(240) NOT NULL,
    emulator VARCHAR(80) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL CHECK (status IN ('open', 'investigating', 'confirmed_violation', 'dismissed_false_positive')),
    aggregated_risk_score NUMERIC(5,2) NOT NULL,
    confidence_score SMALLINT NOT NULL,
    correlated_event_count INTEGER NOT NULL DEFAULT 1,
    primary_rule_id VARCHAR(64) NOT NULL,
    executable_path VARCHAR(512) NOT NULL,
    file_sha256 VARCHAR(128) NOT NULL,
    digital_signature VARCHAR(200) NOT NULL,
    evidence_summary TEXT NOT NULL,
    limitations_notice TEXT NOT NULL,
    analyst_notes TEXT NOT NULL DEFAULT '',
    recommended_action TEXT NOT NULL,
    is_simulated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id VARCHAR(128) PRIMARY KEY,
    actor_email VARCHAR(254) NOT NULL,
    actor_role VARCHAR(32) NOT NULL,
    action VARCHAR(120) NOT NULL,
    target_type VARCHAR(32) NOT NULL,
    target_id VARCHAR(128) NOT NULL,
    details TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
