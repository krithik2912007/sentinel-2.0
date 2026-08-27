-- Migration 002: Indexes for Performance & Search
CREATE INDEX IF NOT EXISTS idx_emails_ingested_at ON emails (ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_emails_risk_score ON emails (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_emails_classification ON emails (classification);
CREATE INDEX IF NOT EXISTS idx_emails_sender_email ON emails (sender_email);
CREATE INDEX IF NOT EXISTS idx_emails_case_id ON emails (case_id);
CREATE INDEX IF NOT EXISTS idx_emails_evidence_hash ON emails (evidence_hash);

CREATE INDEX IF NOT EXISTS idx_cases_status ON cases (status);
CREATE INDEX IF NOT EXISTS idx_cases_priority ON cases (priority);
CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_target ON audit_events (target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_user ON audit_events (user_id);

CREATE INDEX IF NOT EXISTS idx_intelligence_cache_expires_at ON intelligence_cache (expires_at);
CREATE INDEX IF NOT EXISTS idx_intelligence_cache_indicator ON intelligence_cache (indicator_type, indicator_value);
