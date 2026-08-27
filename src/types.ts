export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  avatar?: string;
  department: string;
}

export type CaseStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';
export type CasePriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface CaseRecord {
  id: string;
  case_number: string;
  title: string;
  description: string;
  status: CaseStatus;
  priority: CasePriority;
  created_by: string;
  created_by_name: string;
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  email_ids: string[];
  tags: string[];
  notes?: CaseNote[];
}

export interface CaseNote {
  id: string;
  author: string;
  author_role: UserRole;
  text: string;
  timestamp: string;
}

export type ThreatClassification =
  | 'LEGITIMATE'
  | 'LOW_RISK'
  | 'SUSPICIOUS'
  | 'PHISHING'
  | 'BUSINESS_EMAIL_COMPROMISE'
  | 'FRAUD'
  | 'MALWARE_SUSPECTED';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ThreatEvidenceItem {
  id: string;
  rule_id: string;
  category: 'AUTH' | 'CONTENT' | 'INFRASTRUCTURE' | 'URL' | 'SENDER' | 'ATTACHMENT' | 'RELAY';
  title: string;
  description: string;
  severity: SeverityLevel;
  weight: number; // 0-100 impact on risk score
  mitre_technique?: string;
}

export interface GeoLocationInfo {
  ip: string;
  country: string;
  country_code: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  asn: string;
  isp: string;
  org: string;
  is_vpn_tor_proxy?: boolean;
  proxy_type?: string;
  threat_reputation?: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
}

export interface RelayHop {
  sequence: number; // 1 = first hop (origin), N = last hop (recipient MX)
  source_host: string;
  destination_host: string;
  ip_address: string;
  timestamp: string;
  delay_seconds?: number;
  protocol: string;
  encryption?: string;
  confidence: number; // 0 - 100%
  is_private: boolean;
  is_origin_candidate: boolean;
  raw_header: string;
  geo?: GeoLocationInfo;
  anomalies: string[];
}

export interface OriginCandidate {
  ip_address: string;
  hostname: string;
  hop_number: number;
  reliability_score: number; // 0 - 100
  evidence_source: string;
  infrastructure_info: string;
  is_vpn_proxy: boolean;
  limitations: string;
  geo?: GeoLocationInfo;
}

export interface AuthAnalysis {
  spf: {
    result: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
    domain?: string;
    sender_ip?: string;
    aligned: boolean;
    explanation: string;
  };
  dkim: {
    signature_present: boolean;
    result: 'pass' | 'fail' | 'neutral' | 'none' | 'temperror' | 'permerror';
    signing_domain?: string;
    selector?: string;
    aligned: boolean;
    explanation: string;
  };
  dmarc: {
    result: 'pass' | 'fail' | 'none' | 'temperror' | 'permerror';
    policy?: 'none' | 'quarantine' | 'reject';
    disposition?: string;
    spf_aligned: boolean;
    dkim_aligned: boolean;
    explanation: string;
  };
  arc?: {
    present: boolean;
    result?: string;
  };
}

export type IndicatorType = 'IP' | 'DOMAIN' | 'URL' | 'HASH' | 'EMAIL_ADDRESS' | 'ASN' | 'HOSTNAME';

export interface IndicatorItem {
  id: string;
  type: IndicatorType;
  value: string;
  source: string;
  risk_level: SeverityLevel;
  reputation: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  confidence: number;
  first_seen: string;
  details?: Record<string, any>;
  resolved_ip?: string;
}

export interface AttachmentMetadata {
  id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  md5: string;
  is_executable_or_script: boolean;
  risk_flag: boolean;
  detected_threat?: string;
}

export interface ContentAnalysisResult {
  sentiment: string;
  urgency_score: number; // 0 - 100
  financial_request_detected: boolean;
  credential_harvesting_detected: boolean;
  executive_impersonation_detected: boolean;
  spoofed_display_name_detected: boolean;
  social_engineering_patterns: string[];
  extracted_topics: string[];
  ai_summary: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'EMAIL' | 'DOMAIN' | 'IP' | 'ASN' | 'URL' | 'ATTACHMENT_HASH' | 'CAMPAIGN' | 'CASE';
  risk: SeverityLevel;
  group: number;
  properties?: Record<string, any>;
}

export interface GraphLink {
  source: string;
  target: string;
  relation:
    | 'SENT_FROM'
    | 'RELAYED_THROUGH'
    | 'RESOLVES_TO'
    | 'REPLY_TO'
    | 'LINKS_TO'
    | 'SHARES_INFRASTRUCTURE'
    | 'ASSOCIATED_WITH'
    | 'SEEN_IN_CAMPAIGN';
  label?: string;
}

export interface CorrelationGraphData {
  nodes: GraphNode[];
  links: GraphLink[];
  campaign_name?: string;
  related_cases_count?: number;
}

export interface AnalyzedEmail {
  id: string;
  case_id: string;
  evidence_hash: string; // SHA-256 of raw email
  sha1_hash: string;
  md5_hash: string;
  ingested_at: string;
  
  // Headers
  subject: string;
  sender_raw: string;
  sender_email: string;
  sender_name: string;
  recipient_raw: string;
  recipient_email: string;
  reply_to?: string;
  return_path?: string;
  message_id?: string;
  date_header?: string;
  raw_headers: Record<string, string>;
  
  // Content
  body_plain: string;
  body_html?: string;
  attachments: AttachmentMetadata[];
  
  // Forensics
  risk_score: number; // 0 - 100
  classification: ThreatClassification;
  confidence: number; // 0 - 1.0
  executive_summary: string;
  ai_reasoning?: string;
  
  auth_analysis: AuthAnalysis;
  relay_hops: RelayHop[];
  origin_candidates: OriginCandidate[];
  evidence_list: ThreatEvidenceItem[];
  indicators: IndicatorItem[];
  content_analysis: ContentAnalysisResult;
  graph_data: CorrelationGraphData;
  mitre_attack: {
    tactic: string;
    technique_id: string;
    technique_name: string;
    description: string;
  }[];
  
  defensive_recommendations: string[];
  disclaimers: {
    geolocation_limitation: string;
    attribution_limitation: string;
    legal_notice: string;
  };
  
  raw_eml_source?: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  user_id: string;
  user_email: string;
  user_role: UserRole;
  action: string;
  target_type: 'CASE' | 'EMAIL' | 'REPORT' | 'CONFIG' | 'AUTH';
  target_id: string;
  details: string;
  ip_address: string;
}

export interface IntelligenceProviderConfig {
  virus_total_enabled: boolean;
  virus_total_api_key?: string;
  abuse_ipdb_enabled: boolean;
  abuse_ipdb_api_key?: string;
  ipqs_enabled: boolean;
  ipqs_api_key?: string;
  gemini_ai_enabled: boolean;
  simulation_mode: boolean; // Mock/Real mode toggle
  cache_ttl_hours: number;
  strict_dmarc_enforcement: boolean;
  auto_alert_threshold: number;
}
