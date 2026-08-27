import { userRepository } from './repositories/userRepository';
import { caseRepository } from './repositories/caseRepository';
import { emailRepository } from './repositories/emailRepository';
import { auditRepository } from './repositories/auditRepository';
import { PRESET_SAMPLES } from '../sampleData';
import { parseRawEmail } from '../emailParser';
import { analyzeThreatDeterministic } from '../threatEngine';
import { analyzeRelayHops } from '../relayAnalyzer';
import { generateCorrelationGraph } from '../graphEngine';
import { CaseRecord, UserProfile } from '../../src/types';

export async function seedDatabaseIfEmpty(force = false): Promise<void> {
  const emailCount = await emailRepository.count();
  const caseCount = await caseRepository.count();

  const shouldSeed = force || (emailCount === 0 && caseCount === 0);
  if (!shouldSeed) {
    console.log(`[Seed] Database already contains ${emailCount} emails and ${caseCount} cases. Skipping seed.`);
    return;
  }

  console.log('[Seed] Seeding initial users, cases, and forensic samples...');

  // 1. Seed Users
  const defaultUsers: UserProfile[] = [
    {
      id: 'usr_soc_01',
      name: 'Agent Krithik (Lead Forensics)',
      email: 'krithik.forensics@defense.gov.in',
      role: 'ADMIN',
      avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150',
      department: 'CERT / Cyber Defense Incident Response',
    },
    {
      id: 'usr_soc_02',
      name: 'Analyst Sarah Chen',
      email: 'sarah.chen@defense.gov.in',
      role: 'ANALYST',
      avatar: 'https://images.unsplash.com/photo-1580489944761-15a19d654956?w=150',
      department: 'SOC Tier 2 Forensics',
    },
    {
      id: 'usr_soc_03',
      name: 'Auditor David Vance',
      email: 'david.vance@defense.gov.in',
      role: 'VIEWER',
      avatar: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150',
      department: 'Compliance & Audit',
    },
  ];

  for (const user of defaultUsers) {
    await userRepository.save(user);
  }

  // 2. Seed Default Cases
  const defaultCases: CaseRecord[] = [
    {
      id: 'case_bec_2026_091',
      case_number: 'SEC-2026-091',
      title: 'Executive BEC & Acquisition Fraud Campaign',
      description: 'Sophisticated executive impersonation soliciting confidential wire transfer routing via European Tor exit nodes.',
      status: 'INVESTIGATING',
      priority: 'CRITICAL',
      created_by: 'usr_soc_01',
      created_by_name: 'Agent Krithik (Lead Forensics)',
      assigned_to: 'usr_soc_01',
      created_at: new Date(Date.now() - 3600000 * 8).toISOString(),
      updated_at: new Date(Date.now() - 3600000 * 2).toISOString(),
      email_ids: [],
      tags: ['BEC', 'Tor-Exit', 'Wire-Fraud', 'CEO-Spoof'],
      notes: [
        {
          id: 'note_01',
          author: 'Agent Krithik (Lead Forensics)',
          author_role: 'ADMIN',
          text: 'Origin IP 185.220.101.5 traced to known Zwiebelfreunde Tor exit node in Frankfurt. Hostname spoofing confirmed.',
          timestamp: new Date(Date.now() - 3600000 * 6).toISOString(),
        },
      ],
    },
    {
      id: 'case_phish_2026_092',
      case_number: 'SEC-2026-092',
      title: 'Credential Harvesting via Microsoft 365 Lookalike Domain',
      description: 'Spear-phishing wave deploying punycode lookalike domain micr0soft-security-portal.co with password expiry lures.',
      status: 'OPEN',
      priority: 'HIGH',
      created_by: 'usr_soc_02',
      created_by_name: 'Analyst Sarah Chen',
      assigned_to: 'usr_soc_02',
      created_at: new Date(Date.now() - 3600000 * 14).toISOString(),
      updated_at: new Date(Date.now() - 3600000 * 12).toISOString(),
      email_ids: [],
      tags: ['Phishing', 'Lookalike-Domain', 'Credential-Harvesting'],
      notes: [],
    },
    {
      id: 'case_malware_2026_093',
      case_number: 'SEC-2026-093',
      title: 'Remcos RAT Weaponized Invoice Delivery',
      description: 'Double-extension executable attachment (.pdf.exe) with embedded VBS downloader payload.',
      status: 'INVESTIGATING',
      priority: 'CRITICAL',
      created_by: 'usr_soc_01',
      created_by_name: 'Agent Krithik (Lead Forensics)',
      assigned_to: 'usr_soc_01',
      created_at: new Date(Date.now() - 3600000 * 24).toISOString(),
      updated_at: new Date(Date.now() - 3600000 * 18).toISOString(),
      email_ids: [],
      tags: ['Malware', 'Trojan-Dropper', 'Remcos-RAT'],
      notes: [],
    },
  ];

  for (const c of defaultCases) {
    await caseRepository.save(c);
  }

  // 3. Process and Save Preset Sample Emails
  const caseMap: Record<string, string> = {
    'sample-bec-ceo': 'case_bec_2026_091',
    'sample-phish-m365': 'case_phish_2026_092',
    'sample-malware-invoice': 'case_malware_2026_093',
  };

  for (const sample of PRESET_SAMPLES) {
    try {
      const parsed = parseRawEmail(sample.eml);
      const caseId = caseMap[sample.id];
      const relayAnalysis = analyzeRelayHops(parsed);
      const threatResult = analyzeThreatDeterministic(parsed, relayAnalysis);

      const graphData = generateCorrelationGraph(
        parsed,
        relayAnalysis.origin_candidates,
        threatResult.indicators,
        caseId
      );

      const analyzedEmail = {
        ...parsed,
        case_id: caseId,
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

      await emailRepository.save(analyzedEmail);
      if (caseId) {
        await caseRepository.attachEmail(caseId, analyzedEmail.id);
      }
    } catch (err) {
      console.error(`[Seed] Error processing preset sample ${sample.id}:`, err);
    }
  }

  // 4. Initial Audit Log
  await auditRepository.log({
    id: `audit_seed_${Date.now()}`,
    timestamp: new Date().toISOString(),
    user_id: 'usr_soc_01',
    user_email: 'krithik.forensics@defense.gov.in',
    user_role: 'ADMIN',
    action: 'SYSTEM_BOOTSTRAP',
    target_type: 'DATABASE',
    target_id: 'schema_migrations',
    details: 'Initial database schema and sample forensic dossiers seeded successfully.',
    ip_address: '127.0.0.1',
  });

  console.log('[Seed] Database initialization and seed complete.');
}
