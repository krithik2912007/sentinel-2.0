-- Migration 001: Initial Schema
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'ANALYST',
  department VARCHAR(128) NOT NULL DEFAULT 'SOC Tier 2 Forensics',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cases (
  id VARCHAR(64) PRIMARY KEY,
  case_number VARCHAR(64) UNIQUE NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
  priority VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
  created_by VARCHAR(64) NOT NULL,
  created_by_name VARCHAR(255) NOT NULL,
  assigned_to VARCHAR(64),
  tags TEXT[] NOT NULL DEFAULT '{}',
  notes JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS emails (
  id VARCHAR(64) PRIMARY KEY,
  case_id VARCHAR(64) REFERENCES cases(id) ON DELETE SET NULL,
  evidence_hash VARCHAR(128) NOT NULL,
  sha1_hash VARCHAR(128) NOT NULL,
  md5_hash VARCHAR(128) NOT NULL,
  ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  subject TEXT NOT NULL DEFAULT '',
  sender_raw TEXT NOT NULL DEFAULT '',
  sender_email VARCHAR(255) NOT NULL DEFAULT '',
  sender_name VARCHAR(255) NOT NULL DEFAULT '',
  recipient_raw TEXT NOT NULL DEFAULT '',
  recipient_email VARCHAR(255) NOT NULL DEFAULT '',
  reply_to VARCHAR(255),
  return_path VARCHAR(255),
  message_id VARCHAR(512),
  date_header VARCHAR(255),
  raw_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
  body_plain TEXT NOT NULL DEFAULT '',
  body_html TEXT NOT NULL DEFAULT '',
  attachments JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_score INTEGER NOT NULL DEFAULT 0,
  classification VARCHAR(64) NOT NULL DEFAULT 'UNKNOWN',
  confidence NUMERIC(4,3) NOT NULL DEFAULT 0.500,
  executive_summary TEXT NOT NULL DEFAULT '',
  ai_reasoning TEXT NOT NULL DEFAULT '',
  auth_analysis JSONB NOT NULL DEFAULT '{}'::jsonb,
  relay_hops JSONB NOT NULL DEFAULT '[]'::jsonb,
  origin_candidates JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_list JSONB NOT NULL DEFAULT '[]'::jsonb,
  indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
  content_analysis JSONB NOT NULL DEFAULT '{}'::jsonb,
  graph_data JSONB NOT NULL DEFAULT '{}'::jsonb,
  mitre_attack JSONB NOT NULL DEFAULT '[]'::jsonb,
  defensive_recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
  disclaimers JSONB NOT NULL DEFAULT '[]'::jsonb,
  raw_eml_source TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS case_emails (
  case_id VARCHAR(64) REFERENCES cases(id) ON DELETE CASCADE,
  email_id VARCHAR(64) REFERENCES emails(id) ON DELETE CASCADE,
  PRIMARY KEY (case_id, email_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id VARCHAR(64) PRIMARY KEY,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  user_id VARCHAR(64) NOT NULL,
  user_email VARCHAR(255) NOT NULL,
  user_role VARCHAR(32) NOT NULL,
  action VARCHAR(64) NOT NULL,
  target_type VARCHAR(64) NOT NULL,
  target_id VARCHAR(128) NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  ip_address VARCHAR(64) NOT NULL DEFAULT '127.0.0.1'
);

CREATE TABLE IF NOT EXISTS intelligence_cache (
  cache_key VARCHAR(512) PRIMARY KEY,
  provider VARCHAR(64) NOT NULL,
  indicator_type VARCHAR(32) NOT NULL,
  indicator_value VARCHAR(512) NOT NULL,
  response_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);
