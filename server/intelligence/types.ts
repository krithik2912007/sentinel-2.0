export type IntelligenceStatus = 'LIVE' | 'SIMULATION' | 'NOT_CONFIGURED' | 'UNAVAILABLE' | 'ERROR';
export type IndicatorType = 'IP' | 'DOMAIN' | 'URL' | 'HASH';
export type ThreatReputation = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

export interface IntelligenceResult {
  provider: string;
  status: IntelligenceStatus;
  indicator_type: IndicatorType;
  indicator: string;
  confidence?: number; // 0 - 1.0
  reputation?: ThreatReputation;
  data?: Record<string, any>;
  error?: string;
  fetched_at: string;
  expires_at?: string;
}

export interface DnsIntelligence {
  domain: string;
  a_records: string[];
  aaaa_records: string[];
  mx_records: { exchange: string; priority: number }[];
  txt_records: string[];
  ns_records: string[];
  cname_records: string[];
  spf_record?: string;
  dmarc_record?: string;
  queried_at: string;
  status: IntelligenceStatus;
  error?: string;
}

export interface WhoisIntelligence {
  domain: string;
  registrar?: string;
  creation_date?: string;
  updated_date?: string;
  expiration_date?: string;
  nameservers: string[];
  registrant_country?: string;
  domain_age_days?: number;
  provider: string;
  status: IntelligenceStatus;
  error?: string;
}
