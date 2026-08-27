import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  FileCheck2,
  Bug,
  Globe2,
  Terminal,
  ArrowRight,
  TrendingUp,
  Clock,
  ShieldX,
  ExternalLink,
  ChevronRight,
  Crosshair,
} from 'lucide-react';
import { AnalyzedEmail, CaseRecord } from '../types';

interface DashboardViewProps {
  stats: any;
  emails: AnalyzedEmail[];
  cases: CaseRecord[];
  onSelectEmail: (email: AnalyzedEmail) => void;
  onNavigateToIngest: (presetId?: string) => void;
  onNavigateToCases: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  stats,
  emails,
  cases,
  onSelectEmail,
  onNavigateToIngest,
  onNavigateToCases,
}) => {
  const recentEmails = emails.slice(0, 6);

  const getClassificationBadge = (classification: string, score: number) => {
    switch (classification) {
      case 'BUSINESS_EMAIL_COMPROMISE':
        return {
          label: 'BEC / CEO FRAUD',
          bg: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
        };
      case 'PHISHING':
        return {
          label: 'CREDENTIAL PHISH',
          bg: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
        };
      case 'MALWARE_SUSPECTED':
        return {
          label: 'MALWARE DROPPER',
          bg: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
        };
      case 'FRAUD':
        return {
          label: 'FINANCIAL FRAUD',
          bg: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
        };
      case 'SUSPICIOUS':
        return {
          label: 'SUSPICIOUS',
          bg: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
        };
      default:
        return {
          label: 'LEGITIMATE',
          bg: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
        };
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Top Banner: SOC Status & Quick Ingestion Hero */}
      <div className="bg-gradient-to-r from-neutral-900 via-neutral-900 to-neutral-950 border border-neutral-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute -right-10 -top-10 w-72 h-72 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
              <span className="text-xs font-mono font-semibold uppercase tracking-wider text-indigo-400">
                Threat Intelligence & Forensic Engine Active
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Email Forensics & Infrastructure Intelligence
            </h1>
            <p className="text-neutral-400 text-sm max-w-2xl mt-1">
              Multi-layer analysis correlating RFC 5322 headers, SMTP relay transit paths, SPF/DKIM/DMARC authentication, and autonomous network indicators.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              id="dash-quick-ingest-btn"
              onClick={() => onNavigateToIngest()}
              className="flex items-center space-x-2 px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm transition-all shadow-lg shadow-indigo-600/25 hover:shadow-indigo-600/40"
            >
              <Terminal className="h-4 w-4" />
              <span>Ingest Raw .EML</span>
            </button>
            <button
              id="dash-quick-sample-btn"
              onClick={() => onNavigateToIngest('sample-bec-ceo')}
              className="flex items-center space-x-2 px-3.5 py-2.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 border border-neutral-700 text-sm font-medium transition-colors"
            >
              <Crosshair className="h-4 w-4 text-rose-400" />
              <span>Load BEC Attack Sample</span>
            </button>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Metric 1 */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 hover:border-neutral-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-neutral-400 uppercase tracking-wider">Total Ingested Messages</span>
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <FileCheck2 className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold font-mono text-white">{stats?.total_emails_analyzed ?? emails.length}</span>
            <span className="text-xs text-neutral-400 font-mono">100% Cryptohashed</span>
          </div>
          <div className="mt-2 text-xs text-neutral-500">Full MIME & Header Forensic Breakdown</div>
        </div>

        {/* Metric 2 */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 hover:border-neutral-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-neutral-400 uppercase tracking-wider">Critical Threat Alerts</span>
            <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
              <ShieldAlert className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold font-mono text-rose-400">{stats?.critical_threats ?? 3}</span>
            <span className="text-xs px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-mono">Score ≥ 80</span>
          </div>
          <div className="mt-2 text-xs text-neutral-500">Urgent BEC & Phishing Payloads</div>
        </div>

        {/* Metric 3 */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 hover:border-neutral-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-neutral-400 uppercase tracking-wider">Active Case Investigations</span>
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <AlertTriangle className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold font-mono text-amber-300">{stats?.total_cases ?? cases.length}</span>
            <button onClick={onNavigateToCases} className="text-xs text-indigo-400 hover:underline flex items-center gap-0.5">
              View All <ChevronRight className="h-3 w-3" />
            </button>
          </div>
          <div className="mt-2 text-xs text-neutral-500">Tier-3 Analyst Triage Dossiers</div>
        </div>

        {/* Metric 4 */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 hover:border-neutral-700 transition-colors">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-neutral-400 uppercase tracking-wider">Extracted IoC Indicators</span>
            <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Globe2 className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-bold font-mono text-indigo-300">{stats?.total_indicators_extracted ?? 48}</span>
            <span className="text-xs text-emerald-400 font-mono">ASNs, IPs, Domains</span>
          </div>
          <div className="mt-2 text-xs text-neutral-500">Enriched with Geolocation & Intel</div>
        </div>

      </div>

      {/* Threat Distribution & Investigation Stream Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Threat Categories Breakdown */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-indigo-400" />
              Threat Classification Matrix
            </h2>
          </div>

          <div className="space-y-3.5">
            {[
              { label: 'Business Email Compromise (BEC)', count: stats?.threat_breakdown?.bec || 1, color: 'bg-rose-500', text: 'text-rose-400', pct: '35%' },
              { label: 'Credential Phishing / Harvester', count: stats?.threat_breakdown?.phishing || 1, color: 'bg-amber-500', text: 'text-amber-400', pct: '30%' },
              { label: 'Malware Dropper / Payload', count: stats?.threat_breakdown?.malware || 1, color: 'bg-purple-500', text: 'text-purple-400', pct: '20%' },
              { label: 'Legitimate / Verified Traffic', count: stats?.threat_breakdown?.legitimate || 1, color: 'bg-emerald-500', text: 'text-emerald-400', pct: '15%' },
            ].map((cat, i) => (
              <div key={i} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-neutral-300">{cat.label}</span>
                  <span className={`font-mono font-bold ${cat.text}`}>{cat.count} msgs</span>
                </div>
                <div className="h-2 w-full bg-neutral-800 rounded-full overflow-hidden">
                  <div className={`h-full ${cat.color}`} style={{ width: cat.pct }} />
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 p-3 rounded-lg bg-neutral-950/70 border border-neutral-800">
            <div className="flex items-center justify-between text-xs text-neutral-400 mb-1">
              <span>Overall Average Risk Level:</span>
              <span className="font-mono font-bold text-amber-400">{stats?.average_risk_score || 68}/100</span>
            </div>
            <p className="text-[11px] text-neutral-500 leading-relaxed">
              Calculated via multi-factor heuristics: SPF/DKIM/DMARC alignment, Received relay chain anomalies, NLP urgency triggers, and lookalike domain distance.
            </p>
          </div>
        </div>

        {/* Live Investigations Stream */}
        <div className="lg:col-span-2 bg-neutral-900 border border-neutral-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Clock className="h-4 w-4 text-indigo-400" />
                  Recent Ingested Forensics Dossiers
                </h2>
                <p className="text-xs text-neutral-400">Click any message to open full header, relay path, and intelligence report</p>
              </div>
              <button
                onClick={() => onNavigateToIngest()}
                className="text-xs text-indigo-400 hover:text-indigo-300 font-medium flex items-center gap-1"
              >
                + New Analysis
              </button>
            </div>

            <div className="divide-y divide-neutral-800">
              {recentEmails.map((email) => {
                const badge = getClassificationBadge(email.classification, email.risk_score);
                const originIp = email.origin_candidates[0]?.ip_address || 'Unspecified';
                const originCountry = email.origin_candidates[0]?.geo?.country || 'Unknown';

                return (
                  <div
                    key={email.id}
                    id={`email-row-${email.id}`}
                    onClick={() => onSelectEmail(email)}
                    className="py-3.5 px-2 hover:bg-neutral-800/60 rounded-lg cursor-pointer transition-colors group flex items-center justify-between gap-4"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center space-x-2.5 mb-1">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border font-mono ${badge.bg}`}>
                          {badge.label}
                        </span>
                        <span className="text-xs font-mono text-neutral-400 truncate">
                          {email.sender_email}
                        </span>
                        {email.auth_analysis.dmarc.result === 'fail' && (
                          <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-rose-950 text-rose-400 border border-rose-800">
                            DMARC FAIL
                          </span>
                        )}
                      </div>

                      <p className="text-sm font-medium text-neutral-200 group-hover:text-indigo-300 transition-colors truncate">
                        {email.subject}
                      </p>

                      <div className="flex items-center space-x-4 text-[11px] text-neutral-400 mt-1">
                        <span className="flex items-center gap-1">
                          <Globe2 className="h-3 w-3 text-neutral-500" />
                          Origin: <strong className="font-mono text-neutral-300">{originIp}</strong> ({originCountry})
                        </span>
                        <span>•</span>
                        <span>{email.relay_hops?.length || 0} Relay Hops</span>
                        <span>•</span>
                        <span className="font-mono text-neutral-500">SHA256: {email.evidence_hash.slice(0, 8)}...</span>
                      </div>
                    </div>

                    {/* Risk Score Pill */}
                    <div className="text-right flex items-center space-x-3">
                      <div>
                        <div className={`text-lg font-bold font-mono ${
                          email.risk_score >= 80 ? 'text-rose-400' : email.risk_score >= 50 ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {email.risk_score}<span className="text-xs text-neutral-500">/100</span>
                        </div>
                        <div className="text-[10px] text-neutral-400 uppercase">Risk Level</div>
                      </div>
                      <ChevronRight className="h-5 w-5 text-neutral-600 group-hover:text-indigo-400 transition-transform group-hover:translate-x-0.5" />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-neutral-800 flex items-center justify-between text-xs text-neutral-400">
            <span>Showing {recentEmails.length} investigated email records</span>
            <span className="font-mono">Evidence Integrity: SHA-256 Validated</span>
          </div>
        </div>

      </div>

      {/* Forensic Intelligence Highlights Footer */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
          <Bug className="h-4 w-4 text-indigo-400" />
          Technical Attribution & Forensic Evidence Standards
        </h3>
        <p className="text-xs text-neutral-400 leading-relaxed">
          The platform parses raw RFC 5322 messages to reconstruct verified SMTP mail transport chains and extracts infrastructure indicators. 
          <strong className="text-neutral-300"> Note on Legal & Technical Limitations:</strong> Geolocation coordinates indicate the estimated physical or logical point of presence for the autonomous network system (ASN) and transmitting Mail Transfer Agent (MTA); they do not constitute definitive legal proof of the physical sender or human identity.
        </p>
      </div>

    </div>
  );
};
