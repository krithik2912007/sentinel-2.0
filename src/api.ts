import {
  AnalyzedEmail,
  AuditEvent,
  CaseRecord,
  IntelligenceProviderConfig,
  RemediationProvider,
  ResponseResult,
  UserProfile,
} from './types';

export async function fetchReadiness(): Promise<{
  ready: boolean;
  database: { connected: boolean; demo_mode: boolean; error: string | null };
  intelligence_providers: Record<string, any>;
  timestamp: string;
}> {
  const res = await fetch('/api/v1/ready');
  return res.json();
}

export async function fetchStats() {
  const res = await fetch('/api/v1/stats');
  if (!res.ok) throw new Error('Failed to fetch stats');
  return res.json();
}

export async function fetchCurrentUser(): Promise<UserProfile> {
  const res = await fetch('/api/v1/auth/me');
  if (!res.ok) throw new Error('Failed to fetch user');
  return res.json();
}

export async function switchUserRole(role: string, name?: string): Promise<{ user: UserProfile; token: string }> {
  const res = await fetch('/api/v1/auth/switch-role', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role, name }),
  });
  if (!res.ok) throw new Error('Failed to switch role');
  return res.json();
}

export async function fetchCases(): Promise<CaseRecord[]> {
  const res = await fetch('/api/v1/cases');
  if (!res.ok) throw new Error('Failed to fetch cases');
  return res.json();
}

export async function fetchCaseById(id: string): Promise<CaseRecord & { emails: AnalyzedEmail[] }> {
  const res = await fetch(`/api/v1/cases/${id}`);
  if (!res.ok) throw new Error('Failed to fetch case');
  return res.json();
}

export async function createCase(data: {
  title: string;
  description: string;
  priority: string;
  tags?: string[];
}): Promise<CaseRecord> {
  const res = await fetch('/api/v1/cases', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to create case');
  return res.json();
}

export async function updateCase(
  id: string,
  data: Partial<CaseRecord>
): Promise<CaseRecord> {
  const res = await fetch(`/api/v1/cases/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update case');
  return res.json();
}

export async function addCaseNote(caseId: string, text: string) {
  const res = await fetch(`/api/v1/cases/${caseId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) throw new Error('Failed to add note');
  return res.json();
}

export async function fetchEmails(params?: {
  classification?: string;
  risk_min?: number;
  risk_max?: number;
  sender?: string;
  recipient?: string;
  subject?: string;
  ip?: string;
  domain?: string;
  hash?: string;
  date_from?: string;
  date_to?: string;
  case_id?: string;
  has_attachment?: boolean;
}): Promise<AnalyzedEmail[]> {
  const query = new URLSearchParams();
  if (params?.classification) query.set('classification', params.classification);
  if (params?.risk_min !== undefined) query.set('risk_min', params.risk_min.toString());
  if (params?.risk_max !== undefined) query.set('risk_max', params.risk_max.toString());
  if (params?.sender) query.set('sender', params.sender);
  if (params?.recipient) query.set('recipient', params.recipient);
  if (params?.subject) query.set('subject', params.subject);
  if (params?.ip) query.set('ip', params.ip);
  if (params?.domain) query.set('domain', params.domain);
  if (params?.hash) query.set('hash', params.hash);
  if (params?.date_from) query.set('date_from', params.date_from);
  if (params?.date_to) query.set('date_to', params.date_to);
  if (params?.case_id) query.set('case_id', params.case_id);
  if (params?.has_attachment !== undefined) query.set('has_attachment', params.has_attachment.toString());

  const url = `/api/v1/emails${query.toString() ? `?${query.toString()}` : ''}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch emails');
  return res.json();
}

export async function fetchEmailById(id: string): Promise<AnalyzedEmail> {
  const res = await fetch(`/api/v1/emails/${id}`);
  if (!res.ok) throw new Error('Failed to fetch email');
  return res.json();
}

export async function analyzeEmail(data: {
  raw_eml: string;
  case_id?: string;
  custom_subject?: string;
}): Promise<AnalyzedEmail> {
  const res = await fetch('/api/v1/emails/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Email analysis failed');
  }
  return res.json();
}

export interface BatchAnalysisResponse {
  total_submitted: number;
  total_analyzed: number;
  total_failed: number;
  items: AnalyzedEmail[];
  batch_details: Array<{
    index: number;
    status: 'SUCCESS' | 'FAILED';
    file_name?: string;
    email?: AnalyzedEmail;
    error?: string;
  }>;
}

export async function batchAnalyzeEmails(
  emails: Array<{ raw_eml: string; case_id?: string; file_name?: string }>
): Promise<BatchAnalysisResponse> {
  const res = await fetch('/api/v1/emails/batch-analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ emails }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Batch email analysis failed');
  }
  return res.json();
}

export async function fetchPresetSamples(): Promise<any[]> {
  const res = await fetch('/api/v1/samples');
  if (!res.ok) throw new Error('Failed to fetch samples');
  return res.json();
}

export async function fetchAuditLogs(): Promise<AuditEvent[]> {
  const res = await fetch('/api/v1/audit-log');
  if (!res.ok) throw new Error('Failed to fetch audit logs');
  return res.json();
}

export async function fetchConfig(): Promise<any> {
  const res = await fetch('/api/v1/config');
  if (!res.ok) throw new Error('Failed to fetch config');
  return res.json();
}

export async function updateConfig(data: Partial<IntelligenceProviderConfig>): Promise<any> {
  const res = await fetch('/api/v1/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update config');
  return res.json();
}

export async function fetchEmailReport(emailId: string) {
  const res = await fetch(`/api/v1/emails/${emailId}/report`);
  if (!res.ok) throw new Error('Failed to fetch report');
  return res.json();
}

export function getEmailPdfUrl(emailId: string): string {
  return `/api/v1/emails/${emailId}/pdf`;
}

export function getEmailJsonUrl(emailId: string): string {
  return `/api/v1/emails/${emailId}/json`;
}

export async function fetchRemediationProviders(): Promise<RemediationProvider[]> {
  const res = await fetch('/api/v1/response/providers');
  if (!res.ok) throw new Error('Failed to fetch remediation providers');
  return res.json();
}

export interface ResponseActionOptions {
  reason?: string;
  preferred_provider?: 'm365' | 'google' | 'simulation' | 'auto';
  simulation_mode?: boolean;
}

export async function quarantineEmail(emailId: string, options?: ResponseActionOptions): Promise<ResponseResult> {
  const res = await fetch(`/api/v1/emails/${emailId}/quarantine`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(options || {}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Quarantine action failed');
  }
  return res.json();
}

export async function blockSender(emailId: string, options?: ResponseActionOptions): Promise<ResponseResult> {
  const res = await fetch(`/api/v1/emails/${emailId}/block-sender`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(options || {}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Block sender action failed');
  }
  return res.json();
}

export async function purgeEmail(emailId: string, options?: ResponseActionOptions): Promise<ResponseResult> {
  const res = await fetch(`/api/v1/emails/${emailId}/purge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(options || {}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Purge email action failed (Admin required)');
  }
  return res.json();
}

export async function executeBulkResponseAction(
  action: 'QUARANTINE' | 'BLOCK_SENDER' | 'PURGE',
  email_ids: string[],
  options?: ResponseActionOptions
) {
  const res = await fetch('/api/v1/actions/bulk', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, email_ids, ...options }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Bulk response action failed');
  }
  return res.json();
}

export async function fetchIntelligenceStatus() {
  const res = await fetch('/api/v1/intelligence/status');
  if (!res.ok) throw new Error('Failed to fetch intelligence status');
  return res.json();
}

