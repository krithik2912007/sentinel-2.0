import { query, getDatabaseStatus, assertDatabaseAccessible } from '../pool';
import { AnalyzedEmail } from '../../../src/types';

const inMemoryEmails: Map<string, AnalyzedEmail> = new Map();

export interface EmailSearchParams {
  classification?: string;
  risk_min?: number;
  risk_max?: number;
  sender?: string;
  recipient?: string;
  subject?: string;
  domain?: string;
  ip?: string;
  hash?: string;
  case_id?: string;
  date_from?: string;
  date_to?: string;
  has_attachment?: boolean;
  page?: number;
  page_size?: number;
}

export class EmailRepository {
  async getAll(limit = 100, offset = 0): Promise<AnalyzedEmail[]> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      return Array.from(inMemoryEmails.values())
        .sort((a, b) => new Date(b.ingested_at).getTime() - new Date(a.ingested_at).getTime())
        .slice(offset, offset + limit);
    }

    const res = await query(
      `SELECT * FROM emails ORDER BY ingested_at DESC LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    return res.rows.map(this.mapRowToAnalyzedEmail);
  }

  async getById(id: string): Promise<AnalyzedEmail | null> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      return inMemoryEmails.get(id) || null;
    }

    const res = await query(`SELECT * FROM emails WHERE id = $1`, [id]);
    if (res.rows.length === 0) return null;
    return this.mapRowToAnalyzedEmail(res.rows[0]);
  }

  async save(email: AnalyzedEmail): Promise<AnalyzedEmail> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      inMemoryEmails.set(email.id, email);
      return email;
    }


    await query(
      `
      INSERT INTO emails (
        id, case_id, evidence_hash, sha1_hash, md5_hash, ingested_at,
        subject, sender_raw, sender_email, sender_name,
        recipient_raw, recipient_email, reply_to, return_path,
        message_id, date_header, raw_headers, body_plain, body_html,
        attachments, risk_score, classification, confidence,
        executive_summary, ai_reasoning, auth_analysis, relay_hops,
        origin_candidates, evidence_list, indicators, content_analysis,
        graph_data, mitre_attack, defensive_recommendations, disclaimers,
        raw_eml_source
      ) VALUES (
        $1, $2, $3, $4, $5, $6,
        $7, $8, $9, $10,
        $11, $12, $13, $14,
        $15, $16, $17, $18, $19,
        $20, $21, $22, $23,
        $24, $25, $26, $27,
        $28, $29, $30, $31,
        $32, $33, $34, $35,
        $36
      )
      ON CONFLICT (id) DO UPDATE SET
        case_id = EXCLUDED.case_id,
        risk_score = EXCLUDED.risk_score,
        classification = EXCLUDED.classification,
        confidence = EXCLUDED.confidence,
        executive_summary = EXCLUDED.executive_summary,
        ai_reasoning = EXCLUDED.ai_reasoning,
        auth_analysis = EXCLUDED.auth_analysis,
        relay_hops = EXCLUDED.relay_hops,
        origin_candidates = EXCLUDED.origin_candidates,
        evidence_list = EXCLUDED.evidence_list,
        indicators = EXCLUDED.indicators,
        content_analysis = EXCLUDED.content_analysis,
        graph_data = EXCLUDED.graph_data,
        mitre_attack = EXCLUDED.mitre_attack,
        defensive_recommendations = EXCLUDED.defensive_recommendations
    `,
      [
        email.id,
        email.case_id || null,
        email.evidence_hash,
        email.sha1_hash,
        email.md5_hash,
        email.ingested_at,
        email.subject,
        email.sender.raw,
        email.sender.email,
        email.sender.name,
        email.recipient.raw,
        email.recipient.email,
        email.reply_to || null,
        email.return_path || null,
        email.message_id || null,
        email.date_header || null,
        JSON.stringify(email.raw_headers || {}),
        email.body_plain || '',
        email.body_html || '',
        JSON.stringify(email.attachments || []),
        email.risk_score,
        email.classification,
        email.confidence,
        email.executive_summary,
        email.ai_reasoning || '',
        JSON.stringify(email.auth_analysis || {}),
        JSON.stringify(email.relay_hops || []),
        JSON.stringify(email.origin_candidates || []),
        JSON.stringify(email.evidence_list || []),
        JSON.stringify(email.indicators || []),
        JSON.stringify(email.content_analysis || {}),
        JSON.stringify(email.graph_data || {}),
        JSON.stringify(email.mitre_attack || []),
        JSON.stringify(email.defensive_recommendations || []),
        JSON.stringify(email.disclaimers || []),
        email.raw_eml_source || '',
      ]
    );

    return email;
  }

  async search(params: EmailSearchParams): Promise<{ items: AnalyzedEmail[]; total: number; page: number; page_size: number }> {
    const page = Math.max(1, params.page || 1);
    const pageSize = Math.min(100, Math.max(1, params.page_size || 20));
    const offset = (page - 1) * pageSize;

    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      let filtered = Array.from(inMemoryEmails.values());
      if (params.classification) {
        filtered = filtered.filter((e) => e.classification === params.classification);
      }
      if (params.risk_min !== undefined) {
        filtered = filtered.filter((e) => e.risk_score >= (params.risk_min ?? 0));
      }
      if (params.risk_max !== undefined) {
        filtered = filtered.filter((e) => e.risk_score <= (params.risk_max ?? 100));
      }
      if (params.sender) {
        const s = params.sender.toLowerCase();
        filtered = filtered.filter((e) => e.sender.email.toLowerCase().includes(s) || e.sender.name.toLowerCase().includes(s));
      }
      if (params.recipient) {
        const r = params.recipient.toLowerCase();
        filtered = filtered.filter((e) => e.recipient.email.toLowerCase().includes(r));
      }
      if (params.subject) {
        const sub = params.subject.toLowerCase();
        filtered = filtered.filter((e) => e.subject.toLowerCase().includes(sub));
      }
      if (params.case_id) {
        filtered = filtered.filter((e) => e.case_id === params.case_id);
      }
      if (params.ip) {
        const targetIp = params.ip.trim();
        filtered = filtered.filter((e) =>
          e.relay_hops?.some((h) => h.hop_ip === targetIp || h.source_ip === targetIp) ||
          e.origin_candidates?.some((o) => o.ip === targetIp)
        );
      }
      if (params.domain) {
        const targetDom = params.domain.toLowerCase().trim();
        filtered = filtered.filter((e) =>
          e.sender.email.toLowerCase().endsWith(`@${targetDom}`) ||
          e.sender.email.toLowerCase().includes(targetDom) ||
          e.relay_hops?.some((h) => h.from_domain?.toLowerCase().includes(targetDom))
        );
      }
      if (params.hash) {
        const targetHash = params.hash.toLowerCase().trim();
        filtered = filtered.filter((e) =>
          e.evidence_hash?.toLowerCase().includes(targetHash) ||
          e.sha1_hash?.toLowerCase().includes(targetHash) ||
          e.md5_hash?.toLowerCase().includes(targetHash) ||
          e.attachments?.some((a) => a.sha256?.toLowerCase().includes(targetHash) || a.md5?.toLowerCase().includes(targetHash))
        );
      }
      if (params.date_from) {
        const fromTime = new Date(params.date_from).getTime();
        filtered = filtered.filter((e) => new Date(e.ingested_at).getTime() >= fromTime);
      }
      if (params.date_to) {
        const toTime = new Date(params.date_to).getTime();
        filtered = filtered.filter((e) => new Date(e.ingested_at).getTime() <= toTime);
      }
      if (params.has_attachment !== undefined) {
        filtered = filtered.filter((e) => (params.has_attachment ? e.attachments.length > 0 : e.attachments.length === 0));
      }

      const total = filtered.length;
      filtered.sort((a, b) => new Date(b.ingested_at).getTime() - new Date(a.ingested_at).getTime());
      const items = filtered.slice(offset, offset + pageSize);
      return { items, total, page, page_size: pageSize };
    }

    const conditions: string[] = [];
    const values: any[] = [];

    if (params.classification) {
      values.push(params.classification);
      conditions.push(`classification = $${values.length}`);
    }
    if (params.risk_min !== undefined) {
      values.push(params.risk_min);
      conditions.push(`risk_score >= $${values.length}`);
    }
    if (params.risk_max !== undefined) {
      values.push(params.risk_max);
      conditions.push(`risk_score <= $${values.length}`);
    }
    if (params.sender) {
      values.push(`%${params.sender.toLowerCase()}%`);
      conditions.push(`(LOWER(sender_email) LIKE $${values.length} OR LOWER(sender_name) LIKE $${values.length})`);
    }
    if (params.recipient) {
      values.push(`%${params.recipient.toLowerCase()}%`);
      conditions.push(`LOWER(recipient_email) LIKE $${values.length}`);
    }
    if (params.subject) {
      values.push(`%${params.subject.toLowerCase()}%`);
      conditions.push(`LOWER(subject) LIKE $${values.length}`);
    }
    if (params.case_id) {
      values.push(params.case_id);
      conditions.push(`case_id = $${values.length}`);
    }
    if (params.domain) {
      values.push(`%${params.domain.toLowerCase()}%`);
      conditions.push(`(LOWER(sender_email) LIKE $${values.length} OR LOWER(raw_eml_source) LIKE $${values.length})`);
    }
    if (params.ip) {
      values.push(`%${params.ip.trim()}%`);
      conditions.push(`(raw_eml_source LIKE $${values.length} OR origin_candidates::text LIKE $${values.length})`);
    }
    if (params.hash) {
      values.push(`%${params.hash.toLowerCase()}%`);
      conditions.push(`(LOWER(evidence_hash) LIKE $${values.length} OR LOWER(attachments::text) LIKE $${values.length})`);
    }
    if (params.date_from) {
      values.push(params.date_from);
      conditions.push(`ingested_at >= $${values.length}`);
    }
    if (params.date_to) {
      values.push(params.date_to);
      conditions.push(`ingested_at <= $${values.length}`);
    }
    if (params.has_attachment !== undefined) {
      if (params.has_attachment) {
        conditions.push(`jsonb_array_length(attachments) > 0`);
      } else {
        conditions.push(`jsonb_array_length(attachments) = 0`);
      }
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRes = await query(`SELECT COUNT(*) as total FROM emails ${whereClause}`, values);
    const total = parseInt(countRes.rows[0].total, 10);

    values.push(pageSize);
    values.push(offset);
    const sql = `
      SELECT * FROM emails
      ${whereClause}
      ORDER BY ingested_at DESC
      LIMIT $${values.length - 1} OFFSET $${values.length}
    `;

    const dataRes = await query(sql, values);
    const items = dataRes.rows.map(this.mapRowToAnalyzedEmail);

    return { items, total, page, page_size: pageSize };
  }

  async count(): Promise<number> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      return inMemoryEmails.size;
    }
    const res = await query('SELECT COUNT(*) as cnt FROM emails');
    return parseInt(res.rows[0].cnt, 10);
  }

  async getDashboardStats() {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      const all = Array.from(inMemoryEmails.values());
      const critical_threats = all.filter((e) => e.risk_score >= 80).length;
      const phishing_count = all.filter((e) => e.classification === 'PHISHING').length;
      const bec_count = all.filter((e) => e.classification === 'BUSINESS_EMAIL_COMPROMISE').length;
      const malware_count = all.filter((e) => e.classification === 'MALWARE_SUSPECTED').length;
      const clean_count = all.filter((e) => e.classification === 'LEGITIMATE' || e.classification === 'LOW_RISK').length;
      const avg_score = all.length > 0 ? Math.round(all.reduce((acc, e) => acc + e.risk_score, 0) / all.length) : 0;
      return {
        total_analyzed: all.length,
        critical_threats,
        phishing_count,
        bec_count,
        malware_count,
        clean_count,
        average_risk_score: avg_score,
      };
    }


    const res = await query(`
      SELECT
        COUNT(*) as total_analyzed,
        COUNT(*) FILTER (WHERE risk_score >= 80) as critical_threats,
        COUNT(*) FILTER (WHERE classification = 'PHISHING') as phishing_count,
        COUNT(*) FILTER (WHERE classification = 'BUSINESS_EMAIL_COMPROMISE') as bec_count,
        COUNT(*) FILTER (WHERE classification = 'MALWARE_SUSPECTED') as malware_count,
        COUNT(*) FILTER (WHERE classification IN ('LEGITIMATE', 'LOW_RISK')) as clean_count,
        COALESCE(ROUND(AVG(risk_score)), 0) as average_risk_score
      FROM emails
    `);

    const r = res.rows[0];
    return {
      total_analyzed: parseInt(r.total_analyzed || '0', 10),
      critical_threats: parseInt(r.critical_threats || '0', 10),
      phishing_count: parseInt(r.phishing_count || '0', 10),
      bec_count: parseInt(r.bec_count || '0', 10),
      malware_count: parseInt(r.malware_count || '0', 10),
      clean_count: parseInt(r.clean_count || '0', 10),
      average_risk_score: parseInt(r.average_risk_score || '0', 10),
    };
  }

  private mapRowToAnalyzedEmail(r: any): AnalyzedEmail {
    return {
      id: r.id,
      case_id: r.case_id || undefined,
      evidence_hash: r.evidence_hash,
      sha1_hash: r.sha1_hash,
      md5_hash: r.md5_hash,
      ingested_at: new Date(r.ingested_at).toISOString(),
      subject: r.subject || '',
      sender: {
        raw: r.sender_raw || '',
        email: r.sender_email || '',
        name: r.sender_name || '',
      },
      sender_raw: r.sender_raw || '',
      sender_email: r.sender_email || '',
      sender_name: r.sender_name || '',
      recipient: {
        raw: r.recipient_raw || '',
        email: r.recipient_email || '',
      },
      recipient_raw: r.recipient_raw || '',
      recipient_email: r.recipient_email || '',
      reply_to: r.reply_to || undefined,
      return_path: r.return_path || undefined,
      message_id: r.message_id || undefined,
      date_header: r.date_header || undefined,
      raw_headers: typeof r.raw_headers === 'string' ? JSON.parse(r.raw_headers) : r.raw_headers || {},
      body_plain: r.body_plain || '',
      body_html: r.body_html || '',
      attachments: typeof r.attachments === 'string' ? JSON.parse(r.attachments) : r.attachments || [],
      risk_score: r.risk_score || 0,
      classification: r.classification || 'UNKNOWN',
      confidence: parseFloat(r.confidence || '0.5'),
      executive_summary: r.executive_summary || '',
      ai_reasoning: r.ai_reasoning || '',
      auth_analysis: typeof r.auth_analysis === 'string' ? JSON.parse(r.auth_analysis) : r.auth_analysis || {},
      relay_hops: typeof r.relay_hops === 'string' ? JSON.parse(r.relay_hops) : r.relay_hops || [],
      origin_candidates: typeof r.origin_candidates === 'string' ? JSON.parse(r.origin_candidates) : r.origin_candidates || [],
      evidence_list: typeof r.evidence_list === 'string' ? JSON.parse(r.evidence_list) : r.evidence_list || [],
      indicators: typeof r.indicators === 'string' ? JSON.parse(r.indicators) : r.indicators || [],
      content_analysis: typeof r.content_analysis === 'string' ? JSON.parse(r.content_analysis) : r.content_analysis || {},
      graph_data: typeof r.graph_data === 'string' ? JSON.parse(r.graph_data) : r.graph_data || {},
      mitre_attack: typeof r.mitre_attack === 'string' ? JSON.parse(r.mitre_attack) : r.mitre_attack || [],
      defensive_recommendations: typeof r.defensive_recommendations === 'string' ? JSON.parse(r.defensive_recommendations) : r.defensive_recommendations || [],
      disclaimers: typeof r.disclaimers === 'string' ? JSON.parse(r.disclaimers) : r.disclaimers || [],
      raw_eml_source: r.raw_eml_source || '',
    };
  }
}

export const emailRepository = new EmailRepository();
