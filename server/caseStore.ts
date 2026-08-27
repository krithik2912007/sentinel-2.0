import {
  AnalyzedEmail,
  AuditEvent,
  CaseRecord,
  IntelligenceProviderConfig,
  UserProfile,
  UserRole,
} from '../src/types';
import { parseEmailContent } from './emailParser';
import { reconstructRelayChain } from './relayAnalyzer';
import { analyzeThreats } from './threatEngine';
import { buildCorrelationGraph } from './graphEngine';
import { PRESET_SAMPLES } from './sampleData';

export class CaseStore {
  public cases: Map<string, CaseRecord> = new Map();
  public emails: Map<string, AnalyzedEmail> = new Map();
  public auditEvents: AuditEvent[] = [];
  public config: IntelligenceProviderConfig = {
    virus_total_enabled: true,
    abuse_ipdb_enabled: true,
    ipqs_enabled: true,
    gemini_ai_enabled: true,
    simulation_mode: true, // Seamless hybrid live/mock mode
    cache_ttl_hours: 24,
    strict_dmarc_enforcement: true,
    auto_alert_threshold: 75,
  };

  public currentUser: UserProfile = {
    id: 'usr-sih-cannon-01',
    name: 'Lead Forensic Analyst',
    email: 'analyst@cannon-crew.security',
    role: 'ANALYST',
    department: 'Cyber Threat Intelligence & Incident Response (SOC)',
  };

  constructor() {
    this.seedInitialData();
  }

  public logAudit(
    action: string,
    targetType: 'CASE' | 'EMAIL' | 'REPORT' | 'CONFIG' | 'AUTH',
    targetId: string,
    details: string,
    user?: UserProfile
  ) {
    const actor = user || this.currentUser;
    const event: AuditEvent = {
      id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date().toISOString(),
      user_id: actor.id,
      user_email: actor.email,
      user_role: actor.role,
      action,
      target_type: targetType,
      target_id: targetId,
      details,
      ip_address: '10.240.0.1 (SOC Workstation)',
    };
    this.auditEvents.unshift(event);
    if (this.auditEvents.length > 500) {
      this.auditEvents.pop();
    }
  }

  public async processAndStoreEmail(
    rawEml: string,
    caseId?: string,
    customSubject?: string
  ): Promise<AnalyzedEmail> {
    const parsed = parseEmailContent(rawEml);
    if (customSubject) parsed.subject = customSubject;

    const relayResult = reconstructRelayChain(parsed.received_headers);
    const threatResult = await analyzeThreats(parsed, relayResult);

    const emailId = `email-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    let targetCaseId = caseId;

    // If no case provided, find or create one
    if (!targetCaseId) {
      const caseNum = `CASE-2026-${(this.cases.size + 101).toString()}`;
      const newCase: CaseRecord = {
        id: `case-${Date.now()}`,
        case_number: caseNum,
        title: `Investigation: ${parsed.subject.slice(0, 45)}`,
        description: `Automated investigation initiated for suspicious incoming message from ${parsed.from_email}.`,
        status: threatResult.risk_score >= 65 ? 'INVESTIGATING' : 'OPEN',
        priority: threatResult.risk_score >= 80 ? 'CRITICAL' : threatResult.risk_score >= 50 ? 'HIGH' : 'MEDIUM',
        created_by: this.currentUser.id,
        created_by_name: this.currentUser.name,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        email_ids: [emailId],
        tags: [threatResult.classification, 'Email Forensics', parsed.from_email.split('@')[1] || 'External'],
        notes: [
          {
            id: `note-${Date.now()}`,
            author: this.currentUser.name,
            author_role: this.currentUser.role,
            text: `Email ingested with Evidence Hash SHA-256: ${parsed.evidence_hash_sha256.slice(0, 16)}... Risk classified as ${threatResult.classification} (${threatResult.risk_score}/100).`,
            timestamp: new Date().toISOString(),
          },
        ],
      };
      this.cases.set(newCase.id, newCase);
      targetCaseId = newCase.id;
      this.logAudit('CREATE_CASE', 'CASE', newCase.id, `Case ${newCase.case_number} created automatically upon email ingestion`);
    } else {
      const existingCase = this.cases.get(targetCaseId);
      if (existingCase) {
        existingCase.email_ids.push(emailId);
        existingCase.updated_at = new Date().toISOString();
        if (threatResult.risk_score >= 80) existingCase.priority = 'CRITICAL';
      }
    }

    const assignedCase = this.cases.get(targetCaseId);
    const graphData = buildCorrelationGraph(
      emailId,
      parsed,
      relayResult,
      threatResult,
      assignedCase?.case_number
    );

    const analyzedEmail: AnalyzedEmail = {
      id: emailId,
      case_id: targetCaseId,
      evidence_hash: parsed.evidence_hash_sha256,
      sha1_hash: parsed.sha1_hash,
      md5_hash: parsed.md5_hash,
      ingested_at: new Date().toISOString(),
      subject: parsed.subject,
      sender_raw: parsed.from,
      sender_email: parsed.from_email,
      sender_name: parsed.from_name,
      recipient_raw: parsed.to,
      recipient_email: parsed.to_email,
      reply_to: parsed.reply_to,
      return_path: parsed.return_path,
      message_id: parsed.message_id,
      date_header: parsed.date,
      raw_headers: parsed.headers,
      body_plain: parsed.body_plain,
      body_html: parsed.body_html,
      attachments: parsed.attachments,
      risk_score: threatResult.risk_score,
      classification: threatResult.classification,
      confidence: threatResult.confidence,
      executive_summary: threatResult.executive_summary,
      ai_reasoning: threatResult.ai_reasoning,
      auth_analysis: threatResult.auth_analysis,
      relay_hops: relayResult.hops,
      origin_candidates: relayResult.origin_candidates,
      evidence_list: threatResult.evidence_list,
      indicators: threatResult.indicators,
      content_analysis: threatResult.content_analysis,
      graph_data: graphData,
      mitre_attack: threatResult.mitre_attack,
      defensive_recommendations: threatResult.defensive_recommendations,
      disclaimers: threatResult.disclaimers,
      raw_eml_source: rawEml,
    };

    this.emails.set(emailId, analyzedEmail);

    this.logAudit(
      'INGEST_EMAIL',
      'EMAIL',
      emailId,
      `Ingested and analyzed email "${parsed.subject.slice(0, 30)}" -> Risk: ${threatResult.risk_score}/100 (${threatResult.classification})`
    );

    return analyzedEmail;
  }

  private async seedInitialData() {
    this.logAudit('SYSTEM_INIT', 'CONFIG', 'SYS-001', 'Cannon Crew Forensic Intelligence Platform initialized');

    for (const sample of PRESET_SAMPLES) {
      try {
        await this.processAndStoreEmail(sample.eml, undefined, sample.name);
      } catch (err) {
        console.error('Failed to seed sample email:', sample.name, err);
      }
    }
  }
}

export const globalCaseStore = new CaseStore();
