import express, { Request, Response } from 'express';
import path from 'path';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { globalCaseStore } from './server/caseStore';
import { PRESET_SAMPLES } from './server/sampleData';
import { CaseRecord, UserRole } from './src/types';

dotenv.config();

async function startServer() {
  const app = express();
  const PORT = 3000;

  // JSON Body parsing (support up to 25MB for large EMLs / attachments)
  app.use(express.json({ limit: '25mb' }));
  app.use(express.urlencoded({ extended: true, limit: '25mb' }));

  // --- API ROUTE DEFINITIONS ---

  // Health check
  app.get('/api/health', (req: Request, res: Response) => {
    res.json({
      status: 'ok',
      service: 'Cannon Crew - AI Email Threat & Forensic Intelligence Platform',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
    });
  });

  // Auth / Current User
  app.get('/api/v1/auth/me', (req: Request, res: Response) => {
    res.json(globalCaseStore.currentUser);
  });

  app.post('/api/v1/auth/switch-role', (req: Request, res: Response) => {
    const { role, name, email } = req.body;
    if (role && ['ADMIN', 'ANALYST', 'VIEWER'].includes(role)) {
      globalCaseStore.currentUser.role = role as UserRole;
      if (name) globalCaseStore.currentUser.name = name;
      if (email) globalCaseStore.currentUser.email = email;
      globalCaseStore.logAudit(
        'ROLE_CHANGE',
        'AUTH',
        globalCaseStore.currentUser.id,
        `Active user role switched to ${role}`
      );
    }
    res.json(globalCaseStore.currentUser);
  });

  // Dashboard Stats
  app.get('/api/v1/stats', (req: Request, res: Response) => {
    const allEmails = Array.from(globalCaseStore.emails.values());
    const allCases = Array.from(globalCaseStore.cases.values());

    const criticalCount = allEmails.filter((e) => e.risk_score >= 80).length;
    const phishingCount = allEmails.filter((e) => e.classification === 'PHISHING').length;
    const becCount = allEmails.filter((e) => e.classification === 'BUSINESS_EMAIL_COMPROMISE').length;
    const malwareCount = allEmails.filter((e) => e.classification === 'MALWARE_SUSPECTED').length;
    const legitimateCount = allEmails.filter((e) => e.classification === 'LEGITIMATE' || e.classification === 'LOW_RISK').length;

    const totalIndicators = allEmails.reduce((acc, e) => acc + (e.indicators?.length || 0), 0);
    const avgRiskScore = allEmails.length > 0 ? Math.round(allEmails.reduce((acc, e) => acc + e.risk_score, 0) / allEmails.length) : 0;

    res.json({
      total_cases: allCases.length,
      total_emails_analyzed: allEmails.length,
      critical_threats: criticalCount,
      active_investigations: allCases.filter((c) => c.status === 'INVESTIGATING').length,
      threat_breakdown: {
        phishing: phishingCount,
        bec: becCount,
        malware: malwareCount,
        fraud: allEmails.filter((e) => e.classification === 'FRAUD').length,
        suspicious: allEmails.filter((e) => e.classification === 'SUSPICIOUS').length,
        legitimate: legitimateCount,
      },
      total_indicators_extracted: totalIndicators,
      average_risk_score: avgRiskScore,
    });
  });

  // Preset Samples for Fast 1-Click Testing
  app.get('/api/v1/samples', (req: Request, res: Response) => {
    res.json(PRESET_SAMPLES);
  });

  // Cases Endpoints
  app.get('/api/v1/cases', (req: Request, res: Response) => {
    const list = Array.from(globalCaseStore.cases.values()).sort(
      (a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime()
    );
    res.json(list);
  });

  app.post('/api/v1/cases', (req: Request, res: Response) => {
    const { title, description, priority, tags } = req.body;
    const caseNum = `CASE-2026-${(globalCaseStore.cases.size + 101).toString()}`;
    const newCase: CaseRecord = {
      id: `case-${Date.now()}`,
      case_number: caseNum,
      title: title || 'New Threat Investigation',
      description: description || 'Investigative case initiated by security analyst.',
      status: 'OPEN',
      priority: priority || 'MEDIUM',
      created_by: globalCaseStore.currentUser.id,
      created_by_name: globalCaseStore.currentUser.name,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      email_ids: [],
      tags: tags || ['Email Forensics'],
      notes: [
        {
          id: `note-${Date.now()}`,
          author: globalCaseStore.currentUser.name,
          author_role: globalCaseStore.currentUser.role,
          text: 'Case dossier established.',
          timestamp: new Date().toISOString(),
        },
      ],
    };

    globalCaseStore.cases.set(newCase.id, newCase);
    globalCaseStore.logAudit('CREATE_CASE', 'CASE', newCase.id, `Manual case created: ${newCase.title}`);
    res.status(201).json(newCase);
  });

  app.get('/api/v1/cases/:id', (req: Request, res: Response) => {
    const c = globalCaseStore.cases.get(req.params.id);
    if (!c) {
      res.status(404).json({ error: 'Case not found' });
      return;
    }
    const associatedEmails = c.email_ids.map((id) => globalCaseStore.emails.get(id)).filter(Boolean);
    res.json({ ...c, emails: associatedEmails });
  });

  app.patch('/api/v1/cases/:id', (req: Request, res: Response) => {
    const c = globalCaseStore.cases.get(req.params.id);
    if (!c) {
      res.status(404).json({ error: 'Case not found' });
      return;
    }
    const { status, priority, title, description, assigned_to } = req.body;
    if (status) c.status = status;
    if (priority) c.priority = priority;
    if (title) c.title = title;
    if (description) c.description = description;
    if (assigned_to) c.assigned_to = assigned_to;
    c.updated_at = new Date().toISOString();

    globalCaseStore.logAudit('UPDATE_CASE', 'CASE', c.id, `Case ${c.case_number} status updated to ${c.status}`);
    res.json(c);
  });

  app.post('/api/v1/cases/:id/notes', (req: Request, res: Response) => {
    const c = globalCaseStore.cases.get(req.params.id);
    if (!c) {
      res.status(404).json({ error: 'Case not found' });
      return;
    }
    const { text } = req.body;
    if (!text) {
      res.status(400).json({ error: 'Note text is required' });
      return;
    }
    const note = {
      id: `note-${Date.now()}`,
      author: globalCaseStore.currentUser.name,
      author_role: globalCaseStore.currentUser.role,
      text,
      timestamp: new Date().toISOString(),
    };
    if (!c.notes) c.notes = [];
    c.notes.unshift(note);
    c.updated_at = new Date().toISOString();

    globalCaseStore.logAudit('ADD_NOTE', 'CASE', c.id, `Analyst note appended to case ${c.case_number}`);
    res.status(201).json(note);
  });

  // Email Ingestion & Analysis
  app.post('/api/v1/emails/analyze', async (req: Request, res: Response) => {
    try {
      const { raw_eml, case_id, custom_subject } = req.body;
      if (!raw_eml || typeof raw_eml !== 'string' || !raw_eml.trim()) {
        res.status(400).json({ error: 'Valid RFC 5322 raw email text is required.' });
        return;
      }

      const analyzed = await globalCaseStore.processAndStoreEmail(raw_eml, case_id, custom_subject);
      res.status(201).json(analyzed);
    } catch (err: any) {
      console.error('Error analyzing email:', err);
      res.status(500).json({ error: 'Analysis failed: ' + (err?.message || 'Unknown error') });
    }
  });

  // Email Retrieval & Sub-views
  app.get('/api/v1/emails', (req: Request, res: Response) => {
    const list = Array.from(globalCaseStore.emails.values()).sort(
      (a, b) => new Date(b.ingested_at).getTime() - new Date(a.ingested_at).getTime()
    );
    res.json(list);
  });

  app.get('/api/v1/emails/:id', (req: Request, res: Response) => {
    const email = globalCaseStore.emails.get(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    res.json(email);
  });

  app.get('/api/v1/emails/:id/headers', (req: Request, res: Response) => {
    const email = globalCaseStore.emails.get(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    res.json({
      raw_headers: email.raw_headers,
      auth_analysis: email.auth_analysis,
    });
  });

  app.get('/api/v1/emails/:id/relay-path', (req: Request, res: Response) => {
    const email = globalCaseStore.emails.get(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    res.json({
      hops: email.relay_hops,
      origin_candidates: email.origin_candidates,
    });
  });

  app.get('/api/v1/emails/:id/indicators', (req: Request, res: Response) => {
    const email = globalCaseStore.emails.get(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    res.json(email.indicators);
  });

  app.get('/api/v1/emails/:id/graph', (req: Request, res: Response) => {
    const email = globalCaseStore.emails.get(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    res.json(email.graph_data);
  });

  app.get('/api/v1/emails/:id/report', (req: Request, res: Response) => {
    const email = globalCaseStore.emails.get(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    const targetCase = globalCaseStore.cases.get(email.case_id);

    globalCaseStore.logAudit('EXPORT_REPORT', 'REPORT', email.id, `Forensic report accessed for ${email.subject}`);

    res.json({
      report_id: `REP-${email.id.toUpperCase()}`,
      generated_at: new Date().toISOString(),
      lead_analyst: globalCaseStore.currentUser.name,
      analyst_role: globalCaseStore.currentUser.role,
      case_info: targetCase,
      email_metadata: {
        id: email.id,
        subject: email.subject,
        from: email.sender_raw,
        to: email.recipient_raw,
        date: email.date_header,
        evidence_hash_sha256: email.evidence_hash,
        sha1_hash: email.sha1_hash,
        md5_hash: email.md5_hash,
      },
      classification: email.classification,
      risk_score: email.risk_score,
      confidence: email.confidence,
      executive_summary: email.executive_summary,
      ai_reasoning: email.ai_reasoning,
      evidence_factors: email.evidence_list,
      authentication: email.auth_analysis,
      relay_hops: email.relay_hops,
      origin_candidates: email.origin_candidates,
      indicators: email.indicators,
      mitre_mapping: email.mitre_attack,
      recommendations: email.defensive_recommendations,
      disclaimers: email.disclaimers,
    });
  });

  // Audit Log
  app.get('/api/v1/audit-log', (req: Request, res: Response) => {
    res.json(globalCaseStore.auditEvents);
  });

  // Configuration
  app.get('/api/v1/config', (req: Request, res: Response) => {
    res.json(globalCaseStore.config);
  });

  app.post('/api/v1/config', (req: Request, res: Response) => {
    Object.assign(globalCaseStore.config, req.body);
    globalCaseStore.logAudit('UPDATE_CONFIG', 'CONFIG', 'SYS-CONF', 'Threat intelligence adapters & rules updated');
    res.json(globalCaseStore.config);
  });

  // --- VITE MIDDLEWARE / STATIC ASSETS ---
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Cannon Crew Threat Forensics Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
