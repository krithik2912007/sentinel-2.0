import {
  AnalyzedEmail,
  AuditEvent,
  CaseRecord,
  IntelligenceProviderConfig,
  UserProfile,
} from './types';

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

export async function switchUserRole(role: string, name?: string): Promise<UserProfile> {
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

export async function fetchEmails(): Promise<AnalyzedEmail[]> {
  const res = await fetch('/api/v1/emails');
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

export async function fetchConfig(): Promise<IntelligenceProviderConfig> {
  const res = await fetch('/api/v1/config');
  if (!res.ok) throw new Error('Failed to fetch config');
  return res.json();
}

export async function updateConfig(data: Partial<IntelligenceProviderConfig>): Promise<IntelligenceProviderConfig> {
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
