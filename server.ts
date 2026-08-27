import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import dotenv from 'dotenv';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { createServer as createViteServer } from 'vite';

import { testDatabaseConnection, getDatabaseStatus, isDemoModeExplicit } from './server/db/pool';
import { runMigrations } from './server/db/migrate';
import { seedDatabaseIfEmpty } from './server/db/seed';

import { userRepository } from './server/db/repositories/userRepository';
import { caseRepository } from './server/db/repositories/caseRepository';
import { emailRepository } from './server/db/repositories/emailRepository';
import { auditRepository } from './server/db/repositories/auditRepository';

import { logger } from './server/logger';
import {
  authenticateToken,
  requireAuth,
  requireRole,
  generateToken,
  AuthenticatedRequest,
} from './server/middleware/auth';
import {
  apiLimiter,
  analysisLimiter,
  responseActionLimiter,
} from './server/middleware/rateLimit';
import {
  validateBody,
  validateQuery,
  AnalyzeEmailSchema,
  BatchAnalyzeSchema,
  CreateCaseSchema,
  PatchCaseSchema,
  AddCaseNoteSchema,
  ResponseActionSchema,
  BulkResponseActionSchema,
  IntelligenceLookupSchema,
} from './server/middleware/validation';
import { errorHandler } from './server/middleware/errorHandler';

import { parseRawEmail } from './server/emailParser';
import { analyzeRelayHops } from './server/relayAnalyzer';
import { analyzeThreats } from './server/threatEngine';
import { generateCorrelationGraph } from './server/graphEngine';
import { PRESET_SAMPLES } from './server/sampleData';
import { intelligenceManager } from './server/intelligence/providerManager';
import { responseManager } from './server/response/responseManager';
import { generateForensicPdf } from './server/reports/pdfGenerator';
import { AnalyzedEmail, CaseRecord, UserRole } from './src/types';

dotenv.config();

async function startServer() {
  const app = express();
  const PORT = 3000;

  // 1. Security Headers
  app.use(
    helmet({
      contentSecurityPolicy: false, // Vite Dev / Live iframe compatibility
      crossOriginEmbedderPolicy: false,
    })
  );

  // 2. Cookie & Body Parsing
  app.use(cookieParser());
  app.use(express.json({ limit: '30mb' }));
  app.use(express.urlencoded({ extended: true, limit: '30mb' }));

  // 3. Request Tracing & Structured Logging
  app.use((req: Request, res: Response, next: NextFunction) => {
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    (req as any).requestId = requestId;
    const startTime = Date.now();

    res.on('finish', () => {
      const duration = Date.now() - startTime;
      if (req.path !== '/api/v1/health' && req.path !== '/api/v1/ready') {
        logger.info(`${req.method} ${req.path} ${res.statusCode} (${duration}ms)`, {
          request_id: requestId,
          method: req.method,
          path: req.path,
          status: res.statusCode,
          duration_ms: duration,
          user_id: (req as any).user?.id,
        });
      }
    });

    next();
  });

  // 4. Rate Limiting for all API routes
  app.use('/api', apiLimiter);

  // 5. Database Initialization & Migrations
  console.log('[Server] Connecting to PostgreSQL database...');
  try {
    const dbHealth = await testDatabaseConnection();
    if (dbHealth.connected) {
      console.log('[Server] PostgreSQL connected successfully. Running migrations...');
      const migRes = await runMigrations();
      if (migRes.success) {
        console.log(`[Server] Migrations finished. Applied: ${migRes.applied.length}`);
        await seedDatabaseIfEmpty();
      } else {
        console.error('[Server] Migration failed:', migRes.error);
      }
    } else if (isDemoModeExplicit()) {
      console.log('[Server] Explicit demo mode active. Seeding in-memory store...');
      await seedDatabaseIfEmpty();
    } else {
      console.warn(`[Server] PostgreSQL not connected (${dbHealth.error || 'No connection'}). Normal mode requires PostgreSQL or explicit IN_MEMORY_DEMO_MODE=true.`);
    }
  } catch (initErr: any) {
    console.error('[Server] Database initialization warning:', initErr?.message || initErr);
  }

  // --- API ROUTES ---

  // Liveness Check
  app.get('/api/health', (req: Request, res: Response) => {
    res.json({
      status: 'ok',
      service: 'Sentinel AI — Email Forensics & Threat Intelligence',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/v1/health', (req: Request, res: Response) => {
    res.json({
      status: 'ok',
      service: 'Sentinel AI',
      timestamp: new Date().toISOString(),
    });
  });

  // Readiness Check (Reports Database status honestly)
  app.get('/api/v1/ready', async (req: Request, res: Response) => {
    const dbTest = await testDatabaseConnection();
    const dbStatus = getDatabaseStatus();

    const isReady = dbTest.connected || dbStatus.demoMode;
    const statusCode = isReady ? 200 : 503;

    res.status(statusCode).json({
      ready: isReady,
      database: {
        connected: dbTest.connected,
        demo_mode: dbStatus.demoMode,
        error: dbTest.error || null,
      },
      intelligence_providers: intelligenceManager.getProviderStatuses(),
      timestamp: new Date().toISOString(),
    });
  });

  // Auth: Session / Current User
  app.get('/api/v1/auth/me', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    if (req.user) {
      res.json(req.user);
      return;
    }

    // In dev / demo mode: automatically bootstrap initial session token if none exists
    if (process.env.NODE_ENV !== 'production' || isDemoModeExplicit()) {
      const defaultAdmin = (await userRepository.getById('usr_soc_01')) || {
        id: 'usr_soc_01',
        name: 'Agent Krithik (Lead Forensics)',
        email: 'krithik.forensics@defense.gov.in',
        role: 'ADMIN' as UserRole,
        department: 'CERT / Cyber Defense Incident Response',
      };
      const token = generateToken(defaultAdmin);
      res.cookie('sentinel_session', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 3600 * 1000,
      });
      res.json(defaultAdmin);
      return;
    }

    res.status(401).json({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Unauthenticated. Valid token required.',
        request_id: req.requestId,
      },
    });
  });

  app.post('/api/v1/auth/switch-role', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    // Strictly disallowed in production or when dev role switch is disabled
    const isDevRoleSwitchAllowed =
      process.env.NODE_ENV !== 'production' &&
      (process.env.ENABLE_DEV_ROLE_SWITCH === 'true' ||
        process.env.DEMO_MODE === 'true' ||
        process.env.IN_MEMORY_DEMO_MODE === 'true');

    if (!isDevRoleSwitchAllowed) {
      res.status(403).json({
        error: {
          code: 'FORBIDDEN',
          message:
            'Role switching endpoint is strictly disabled. In production, roles are assigned via server-side identity providers.',
          request_id: req.requestId,
        },
      });
      return;
    }

    if (!req.user) {
      res.status(401).json({
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication is required before switching roles.',
          request_id: req.requestId,
        },
      });
      return;
    }

    const { role } = req.body;
    if (role && ['ADMIN', 'ANALYST', 'VIEWER'].includes(role)) {
      const presetUserId =
        role === 'ADMIN' ? 'usr_soc_01' : role === 'ANALYST' ? 'usr_soc_02' : 'usr_soc_03';
      const targetUser =
        (await userRepository.getById(presetUserId)) || {
          id: presetUserId,
          name:
            role === 'ADMIN'
              ? 'Agent Krithik (Lead Forensics)'
              : role === 'ANALYST'
              ? 'Analyst Sarah Chen'
              : 'Auditor David Vance',
          email:
            role === 'ADMIN'
              ? 'krithik.forensics@defense.gov.in'
              : role === 'ANALYST'
              ? 'sarah.chen@defense.gov.in'
              : 'david.vance@defense.gov.in',
          role: role as UserRole,
          department:
            role === 'ADMIN'
              ? 'CERT / Cyber Defense Incident Response'
              : role === 'ANALYST'
              ? 'SOC Tier 2 Forensics'
              : 'Compliance & Audit',
        };

      const updatedUser = await userRepository.save(targetUser);
      const token = generateToken(updatedUser);
      res.cookie('sentinel_session', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 3600 * 1000,
      });

      await auditRepository.log({
        id: `audit_role_${Date.now()}`,
        timestamp: new Date().toISOString(),
        user_id: updatedUser.id,
        user_email: updatedUser.email,
        user_role: updatedUser.role,
        action: 'ROLE_SWITCH',
        target_type: 'USER',
        target_id: updatedUser.id,
        details: `Active role switched to ${role} (Development/Demo Mode Only)`,
        ip_address: req.ip || '127.0.0.1',
      });

      res.json({ user: updatedUser, token });
      return;
    }
    res.status(400).json({ error: 'Valid role (ADMIN, ANALYST, VIEWER) is required' });
  });


  // Dashboard Stats
  app.get('/api/v1/stats', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const emailStats = await emailRepository.getDashboardStats();
    const allCases = await caseRepository.getAll();

    res.json({
      total_cases: allCases.length,
      total_emails_analyzed: emailStats.total_analyzed,
      critical_threats: emailStats.critical_threats,
      active_investigations: allCases.filter((c) => c.status === 'INVESTIGATING').length,
      threat_breakdown: {
        phishing: emailStats.phishing_count,
        bec: emailStats.bec_count,
        malware: emailStats.malware_count,
        clean: emailStats.clean_count,
      },
      average_risk_score: emailStats.average_risk_score,
      database_status: getDatabaseStatus(),
    });
  });

  // Preset Forensic Samples
  app.get('/api/v1/samples', (req: Request, res: Response) => {
    res.json(PRESET_SAMPLES);
  });

  // Cases Endpoints
  app.get('/api/v1/cases', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const list = await caseRepository.getAll();
    res.json(list);
  });

  app.post(
    '/api/v1/cases',
    authenticateToken,
    requireRole(['ADMIN', 'ANALYST']),
    validateBody(CreateCaseSchema),
    async (req: AuthenticatedRequest, res: Response) => {
      const { title, description, priority, tags, assigned_to } = req.body;
      const count = await caseRepository.count();
      const caseNum = `SEC-2026-${(count + 101).toString().padStart(3, '0')}`;

      const newCase: CaseRecord = {
        id: `case_${Date.now()}`,
        case_number: caseNum,
        title,
        description: description || 'Investigative case initiated by security analyst.',
        status: 'OPEN',
        priority: priority || 'MEDIUM',
        created_by: req.user!.id,
        created_by_name: req.user!.name,
        assigned_to: assigned_to || req.user!.id,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        email_ids: [],
        tags: tags || ['Email Forensics'],
        notes: [
          {
            id: `note_${Date.now()}`,
            author: req.user!.name,
            author_role: req.user!.role,
            text: 'Case dossier established.',
            timestamp: new Date().toISOString(),
          },
        ],
      };

      const saved = await caseRepository.save(newCase);

      await auditRepository.log({
        id: `audit_case_${Date.now()}`,
        timestamp: new Date().toISOString(),
        user_id: req.user!.id,
        user_email: req.user!.email,
        user_role: req.user!.role,
        action: 'CREATE_CASE',
        target_type: 'CASE',
        target_id: saved.id,
        details: `Case ${saved.case_number} created: ${saved.title}`,
        ip_address: req.ip || '127.0.0.1',
      });

      res.status(201).json(saved);
    }
  );

  app.get('/api/v1/cases/:id', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const c = await caseRepository.getById(req.params.id);
    if (!c) {
      res.status(404).json({ error: 'Case dossier not found' });
      return;
    }

    const emails: AnalyzedEmail[] = [];
    for (const emailId of c.email_ids) {
      const em = await emailRepository.getById(emailId);
      if (em) emails.push(em);
    }

    res.json({ ...c, emails });
  });

  app.patch(
    '/api/v1/cases/:id',
    authenticateToken,
    requireRole(['ADMIN', 'ANALYST']),
    validateBody(PatchCaseSchema),
    async (req: AuthenticatedRequest, res: Response) => {
      const updated = await caseRepository.patch(req.params.id, req.body);
      if (!updated) {
        res.status(404).json({ error: 'Case not found' });
        return;
      }

      await auditRepository.log({
        id: `audit_case_${Date.now()}`,
        timestamp: new Date().toISOString(),
        user_id: req.user!.id,
        user_email: req.user!.email,
        user_role: req.user!.role,
        action: 'UPDATE_CASE',
        target_type: 'CASE',
        target_id: updated.id,
        details: `Case ${updated.case_number} status updated to ${updated.status} (Priority: ${updated.priority})`,
        ip_address: req.ip || '127.0.0.1',
      });

      res.json(updated);
    }
  );

  app.post(
    '/api/v1/cases/:id/notes',
    authenticateToken,
    requireRole(['ADMIN', 'ANALYST']),
    validateBody(AddCaseNoteSchema),
    async (req: AuthenticatedRequest, res: Response) => {
      const note = {
        id: `note_${Date.now()}`,
        author: req.user!.name,
        author_role: req.user!.role,
        text: req.body.text,
        timestamp: new Date().toISOString(),
      };

      const updated = await caseRepository.addNote(req.params.id, note);
      if (!updated) {
        res.status(404).json({ error: 'Case not found' });
        return;
      }

      await auditRepository.log({
        id: `audit_note_${Date.now()}`,
        timestamp: new Date().toISOString(),
        user_id: req.user!.id,
        user_email: req.user!.email,
        user_role: req.user!.role,
        action: 'ADD_CASE_NOTE',
        target_type: 'CASE',
        target_id: updated.id,
        details: `Forensic note added to case ${updated.case_number}`,
        ip_address: req.ip || '127.0.0.1',
      });

      res.status(201).json(note);
    }
  );

  // Email Ingestion & Forensics
  app.post(
    '/api/v1/emails/analyze',
    authenticateToken,
    requireRole(['ADMIN', 'ANALYST']),
    analysisLimiter,
    validateBody(AnalyzeEmailSchema),
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const { raw_eml, case_id } = req.body;

        const parsed = parseRawEmail(raw_eml);
        const relayAnalysis = analyzeRelayHops(parsed);
        const threatResult = await analyzeThreats(parsed, relayAnalysis);

        const graphData = generateCorrelationGraph(
          parsed,
          relayAnalysis.origin_candidates,
          threatResult.indicators,
          case_id
        );

        const analyzedEmail: AnalyzedEmail = {
          ...parsed,
          case_id: case_id || undefined,
          risk_score: threatResult.risk_score,
          classification: threatResult.classification,
          confidence: threatResult.confidence,
          executive_summary: threatResult.executive_summary,
          ai_reasoning: threatResult.ai_reasoning,
          auth_analysis: threatResult.auth_analysis,
          relay_hops: relayAnalysis.relay_hops,
          origin_candidates: relayAnalysis.origin_candidates,
          evidence_list: threatResult.evidence_list,
          indicators: threatResult.indicators,
          content_analysis: threatResult.content_analysis,
          graph_data: graphData,
          mitre_attack: threatResult.mitre_attack,
          defensive_recommendations: threatResult.defensive_recommendations,
          disclaimers: threatResult.disclaimers,
        };

        const saved = await emailRepository.save(analyzedEmail);
        if (case_id) {
          await caseRepository.attachEmail(case_id, saved.id);
        }

        await auditRepository.log({
          id: `audit_ingest_${Date.now()}`,
          timestamp: new Date().toISOString(),
          user_id: req.user!.id,
          user_email: req.user!.email,
          user_role: req.user!.role,
          action: 'INGEST_EMAIL',
          target_type: 'EMAIL',
          target_id: saved.id,
          details: `Analyzed "${saved.subject}" -> Score ${saved.risk_score}/100 (${saved.classification})`,
          ip_address: req.ip || '127.0.0.1',
        });

        res.status(201).json(saved);
      } catch (err: any) {
        logger.error('Error analyzing email payload', err, { request_id: (req as any).requestId });
        res.status(500).json({ error: 'Forensic analysis failed: ' + (err?.message || 'Unknown error') });
      }
    }
  );

  // Batch Ingestion & Analysis
  app.post(
    '/api/v1/emails/batch-analyze',
    authenticateToken,
    requireRole(['ADMIN', 'ANALYST']),
    analysisLimiter,
    validateBody(BatchAnalyzeSchema),
    async (req: AuthenticatedRequest, res: Response) => {
      const { emails: rawEmailsList, raw_emls, case_id: globalCaseId } = req.body;

      const itemsToProcess: Array<{ raw_eml: string; case_id?: string; file_name?: string }> = [];
      if (Array.isArray(rawEmailsList)) {
        for (const item of rawEmailsList) {
          itemsToProcess.push({
            raw_eml: item.raw_eml,
            case_id: item.case_id || globalCaseId,
            file_name: item.file_name,
          });
        }
      } else if (Array.isArray(raw_emls)) {
        for (let i = 0; i < raw_emls.length; i++) {
          itemsToProcess.push({
            raw_eml: raw_emls[i],
            case_id: globalCaseId,
            file_name: `batch_email_${i + 1}.eml`,
          });
        }
      }

      const results: Array<{
        index: number;
        status: 'SUCCESS' | 'FAILED';
        file_name?: string;
        email?: AnalyzedEmail;
        error?: string;
      }> = [];

      let successfulCount = 0;
      let failedCount = 0;

      for (let idx = 0; idx < itemsToProcess.length; idx++) {
        const item = itemsToProcess[idx];
        try {
          const parsed = parseRawEmail(item.raw_eml);
          const relayAnalysis = analyzeRelayHops(parsed);
          const threatResult = await analyzeThreats(parsed, relayAnalysis);
          const graphData = generateCorrelationGraph(
            parsed,
            relayAnalysis.origin_candidates,
            threatResult.indicators,
            item.case_id
          );

          const analyzed: AnalyzedEmail = {
            ...parsed,
            case_id: item.case_id || undefined,
            risk_score: threatResult.risk_score,
            classification: threatResult.classification,
            confidence: threatResult.confidence,
            executive_summary: threatResult.executive_summary,
            ai_reasoning: threatResult.ai_reasoning,
            auth_analysis: threatResult.auth_analysis,
            relay_hops: relayAnalysis.relay_hops,
            origin_candidates: relayAnalysis.origin_candidates,
            evidence_list: threatResult.evidence_list,
            indicators: threatResult.indicators,
            content_analysis: threatResult.content_analysis,
            graph_data: graphData,
            mitre_attack: threatResult.mitre_attack,
            defensive_recommendations: threatResult.defensive_recommendations,
            disclaimers: threatResult.disclaimers,
          };

          const saved = await emailRepository.save(analyzed);
          if (item.case_id) {
            await caseRepository.attachEmail(item.case_id, saved.id);
          }

          results.push({
            index: idx,
            status: 'SUCCESS',
            file_name: item.file_name,
            email: saved,
          });
          successfulCount++;
        } catch (err: any) {
          logger.error(`Batch item ${idx} failed`, err);
          results.push({
            index: idx,
            status: 'FAILED',
            file_name: item.file_name,
            error: err?.message || 'Failed to parse and analyze email content',
          });
          failedCount++;
        }
      }

      await auditRepository.log({
        id: `audit_batch_${Date.now()}`,
        timestamp: new Date().toISOString(),
        user_id: req.user!.id,
        user_email: req.user!.email,
        user_role: req.user!.role,
        action: 'INGEST_EMAIL',
        target_type: 'EMAIL',
        target_id: `batch_${Date.now()}`,
        details: `Batch analyzed ${itemsToProcess.length} emails (${successfulCount} succeeded, ${failedCount} failed)`,
        ip_address: req.ip || '127.0.0.1',
      });

      res.status(201).json({
        total_submitted: itemsToProcess.length,
        total_analyzed: successfulCount,
        total_failed: failedCount,
        items: results.filter((r) => r.status === 'SUCCESS').map((r) => r.email!),
        batch_details: results,
      });
    }
  );

  // Search & List Emails (Full multi-parameter filtering)
  app.get('/api/v1/emails', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const {
      classification,
      risk_min,
      risk_max,
      sender,
      recipient,
      subject,
      ip,
      domain,
      hash,
      date_from,
      date_to,
      case_id,
      has_attachment,
      page,
      page_size,
    } = req.query as any;

    const result = await emailRepository.search({
      classification: classification || undefined,
      risk_min: risk_min !== undefined && risk_min !== '' ? parseInt(risk_min, 10) : undefined,
      risk_max: risk_max !== undefined && risk_max !== '' ? parseInt(risk_max, 10) : undefined,
      sender: sender || undefined,
      recipient: recipient || undefined,
      subject: subject || undefined,
      ip: ip || undefined,
      domain: domain || undefined,
      hash: hash || undefined,
      date_from: date_from || undefined,
      date_to: date_to || undefined,
      case_id: case_id || undefined,
      has_attachment: has_attachment !== undefined && has_attachment !== '' ? has_attachment === 'true' : undefined,
      page: page ? parseInt(page, 10) : 1,
      page_size: page_size ? parseInt(page_size, 10) : 50,
    });

    res.json(result.items);
  });

  app.get('/api/v1/emails/:id', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const email = await emailRepository.getById(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    res.json(email);
  });

  app.get('/api/v1/emails/:id/headers', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const email = await emailRepository.getById(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    res.json({
      raw_headers: email.raw_headers,
      auth_analysis: email.auth_analysis,
    });
  });

  app.get('/api/v1/emails/:id/relay-path', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const email = await emailRepository.getById(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    res.json({
      hops: email.relay_hops,
      origin_candidates: email.origin_candidates,
    });
  });

  app.get('/api/v1/emails/:id/indicators', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const email = await emailRepository.getById(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    res.json(email.indicators);
  });

  app.get('/api/v1/emails/:id/graph', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const email = await emailRepository.getById(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    res.json(email.graph_data);
  });

  app.get('/api/v1/emails/:id/report', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const email = await emailRepository.getById(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    const targetCase = email.case_id ? await caseRepository.getById(email.case_id) : null;

    await auditRepository.log({
      id: `audit_rep_${Date.now()}`,
      timestamp: new Date().toISOString(),
      user_id: req.user!.id,
      user_email: req.user!.email,
      user_role: req.user!.role,
      action: 'EXPORT_REPORT',
      target_type: 'REPORT',
      target_id: email.id,
      details: `Forensic report accessed for "${email.subject}"`,
      ip_address: req.ip || '127.0.0.1',
    });

    res.json({
      report_id: `REP-${email.id.toUpperCase()}`,
      generated_at: new Date().toISOString(),
      lead_analyst: req.user!.name,
      analyst_role: req.user!.role,
      case_info: targetCase,
      email_metadata: {
        id: email.id,
        subject: email.subject,
        from: email.sender.raw,
        to: email.recipient.raw,
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

  // Forensic PDF Download
  app.get('/api/v1/emails/:id/pdf', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const email = await emailRepository.getById(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    const targetCase = email.case_id ? await caseRepository.getById(email.case_id) : null;

    try {
      const pdfBuffer = await generateForensicPdf(email, targetCase);

      await auditRepository.log({
        id: `audit_pdf_${Date.now()}`,
        timestamp: new Date().toISOString(),
        user_id: req.user!.id,
        user_email: req.user!.email,
        user_role: req.user!.role,
        action: 'DOWNLOAD_PDF',
        target_type: 'REPORT',
        target_id: email.id,
        details: `Forensic PDF report generated and downloaded for ${email.id}`,
        ip_address: req.ip || '127.0.0.1',
      });

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="Sentinel-Forensic-Report-${email.id.slice(0, 8)}.pdf"`);
      res.send(pdfBuffer);
    } catch (err: any) {
      logger.error('PDF Generation Failed', err);
      res.status(500).json({ error: 'Failed to generate forensic PDF: ' + err.message });
    }
  });

  // Forensic JSON Export
  app.get('/api/v1/emails/:id/json', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const email = await emailRepository.getById(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email record not found' });
      return;
    }
    const targetCase = email.case_id ? await caseRepository.getById(email.case_id) : null;

    const forensicExport = {
      export_schema_version: '1.0.0',
      system: 'Sentinel AI Forensics & SOC Platform',
      generated_at: new Date().toISOString(),
      generated_by: {
        id: req.user!.id,
        name: req.user!.name,
        role: req.user!.role,
      },
      evidence_integrity: {
        evidence_hash_sha256: email.evidence_hash,
        sha1_hash: email.sha1_hash,
        md5_hash: email.md5_hash,
      },
      case_association: targetCase
        ? {
            id: targetCase.id,
            case_number: targetCase.case_number,
            title: targetCase.title,
            priority: targetCase.priority,
            status: targetCase.status,
          }
        : null,
      email: email,
    };

    await auditRepository.log({
      id: `audit_json_${Date.now()}`,
      timestamp: new Date().toISOString(),
      user_id: req.user!.id,
      user_email: req.user!.email,
      user_role: req.user!.role,
      action: 'EXPORT_REPORT',
      target_type: 'REPORT',
      target_id: email.id,
      details: `Forensic JSON export generated for ${email.id}`,
      ip_address: req.ip || '127.0.0.1',
    });

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="Sentinel-Forensic-Export-${email.id.slice(0, 8)}.json"`);
    res.json(forensicExport);
  });

  // Remediation Providers Status
  app.get('/api/v1/response/providers', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    res.json(responseManager.getRemediationProviders());
  });

  // Response Actions (Quarantine, Block Sender, Purge)
  app.post(
    '/api/v1/emails/:id/quarantine',
    authenticateToken,
    requireRole(['ADMIN', 'ANALYST']),
    responseActionLimiter,
    validateBody(ResponseActionSchema),
    async (req: AuthenticatedRequest, res: Response) => {
      const email = await emailRepository.getById(req.params.id);
      if (!email) {
        res.status(404).json({ error: 'Email not found' });
        return;
      }

      const result = await responseManager.quarantine({
        emailId: email.id,
        senderEmail: email.sender.email,
        subject: email.subject,
        messageId: email.message_id,
        reason: req.body.reason,
        preferredProvider: req.body.preferred_provider,
        simulationMode: req.body.simulation_mode,
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        actorRole: req.user!.role,
        ipAddress: req.ip || '127.0.0.1',
      });

      res.json(result);
    }
  );

  app.post(
    '/api/v1/emails/:id/block-sender',
    authenticateToken,
    requireRole(['ADMIN', 'ANALYST']),
    responseActionLimiter,
    validateBody(ResponseActionSchema),
    async (req: AuthenticatedRequest, res: Response) => {
      const email = await emailRepository.getById(req.params.id);
      if (!email) {
        res.status(404).json({ error: 'Email not found' });
        return;
      }

      const result = await responseManager.blockSender({
        emailId: email.id,
        senderEmail: email.sender.email,
        subject: email.subject,
        messageId: email.message_id,
        reason: req.body.reason,
        preferredProvider: req.body.preferred_provider,
        simulationMode: req.body.simulation_mode,
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        actorRole: req.user!.role,
        ipAddress: req.ip || '127.0.0.1',
      });

      res.json(result);
    }
  );

  app.post(
    '/api/v1/emails/:id/purge',
    authenticateToken,
    requireRole(['ADMIN']), // Purge is ADMIN only
    responseActionLimiter,
    validateBody(ResponseActionSchema),
    async (req: AuthenticatedRequest, res: Response) => {
      const email = await emailRepository.getById(req.params.id);
      if (!email) {
        res.status(404).json({ error: 'Email not found' });
        return;
      }

      const result = await responseManager.purge({
        emailId: email.id,
        senderEmail: email.sender.email,
        subject: email.subject,
        messageId: email.message_id,
        reason: req.body.reason,
        preferredProvider: req.body.preferred_provider,
        simulationMode: req.body.simulation_mode,
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        actorRole: req.user!.role,
        ipAddress: req.ip || '127.0.0.1',
      });

      res.json(result);
    }
  );

  // Bulk Response Actions
  app.post(
    '/api/v1/actions/bulk',
    authenticateToken,
    requireRole(['ADMIN', 'ANALYST']),
    responseActionLimiter,
    validateBody(BulkResponseActionSchema),
    async (req: AuthenticatedRequest, res: Response) => {
      const { action, email_ids, reason, preferred_provider, simulation_mode } = req.body;
      if (action === 'PURGE' && req.user!.role !== 'ADMIN') {
        res.status(403).json({ error: 'Purge action requires ADMIN role.' });
        return;
      }

      const results = [];
      for (const id of email_ids) {
        const email = await emailRepository.getById(id);
        if (email) {
          const input = {
            emailId: email.id,
            senderEmail: email.sender.email,
            subject: email.subject,
            messageId: email.message_id,
            reason: reason || 'Bulk SOC Incident Remediation',
            preferredProvider: preferred_provider,
            simulationMode: simulation_mode,
            actorId: req.user!.id,
            actorEmail: req.user!.email,
            actorRole: req.user!.role,
            ipAddress: req.ip || '127.0.0.1',
          };

          if (action === 'QUARANTINE') {
            results.push(await responseManager.quarantine(input));
          } else if (action === 'BLOCK_SENDER') {
            results.push(await responseManager.blockSender(input));
          } else if (action === 'PURGE') {
            results.push(await responseManager.purge(input));
          }
        }
      }

      res.json({ action, processed: results.length, results });
    }
  );

  // Intelligence Providers Status & Direct Indicator Queries
  app.get('/api/v1/intelligence/status', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    res.json(intelligenceManager.getProviderStatuses());
  });

  app.post(
    '/api/v1/intelligence/lookup',
    authenticateToken,
    validateBody(IntelligenceLookupSchema),
    async (req: AuthenticatedRequest, res: Response) => {
      try {
        const { type, indicator } = req.body;
        const result = await intelligenceManager.lookupIndicator(type, indicator);
        res.json(result);
      } catch (err: any) {
        res.status(500).json({ error: 'Intelligence lookup failed: ' + (err.message || 'Unknown error') });
      }
    }
  );

  app.get('/api/v1/intelligence/ip/:ip', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const result = await intelligenceManager.enrichIp(req.params.ip);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: 'IP intelligence lookup failed: ' + (err.message || 'Unknown error') });
    }
  });

  app.get('/api/v1/intelligence/domain/:domain', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const result = await intelligenceManager.enrichDomain(req.params.domain);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: 'Domain intelligence lookup failed: ' + (err.message || 'Unknown error') });
    }
  });

  app.get('/api/v1/intelligence/hash/:hash', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const result = await intelligenceManager.enrichHash(req.params.hash);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: 'Hash intelligence lookup failed: ' + (err.message || 'Unknown error') });
    }
  });

  // Audit Logs
  app.get('/api/v1/audit-log', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const logs = await auditRepository.getAll(150);
    res.json(logs);
  });

  // Global Config
  app.get('/api/v1/config', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    res.json({
      environment: process.env.NODE_ENV || 'development',
      simulation_mode: process.env.SIMULATION_MODE !== 'false',
      database: getDatabaseStatus(),
      providers: intelligenceManager.getProviderStatuses(),
      rate_limits: {
        window_ms: process.env.RATE_LIMIT_WINDOW_MS || '900000',
        max_requests: process.env.RATE_LIMIT_MAX_REQUESTS || '100',
      },
    });
  });

  // 6. Centralized Error Handler
  app.use(errorHandler);

  // 7. Vite Frontend Integration
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
    console.log(`Sentinel AI SOC Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
