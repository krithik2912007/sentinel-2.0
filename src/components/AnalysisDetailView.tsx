import React, { useState } from 'react';
import {
  AnalyzedEmail,
  CaseRecord,
  SeverityLevel,
} from '../types';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Activity,
  Layers,
  Globe2,
  Share2,
  Terminal,
  Printer,
  Copy,
  Check,
  Clock,
  KeyRound,
  Lock,
  Unlock,
  Server,
  Crosshair,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Info,
  Hash,
  Download,
  Eye,
  Code,
} from 'lucide-react';
import { LeafletRelayMap } from './LeafletRelayMap';
import { CorrelationGraphCanvas } from './CorrelationGraphCanvas';

interface AnalysisDetailViewProps {
  email: AnalyzedEmail;
  caseRecord?: CaseRecord;
  onBack: () => void;
  onNavigateToCase?: (caseId: string) => void;
}

export const AnalysisDetailView: React.FC<AnalysisDetailViewProps> = ({
  email,
  caseRecord,
  onBack,
  onNavigateToCase,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<string>('overview');
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const copyToClipboard = (text: string, fieldId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldId);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return { text: 'text-rose-400', bg: 'bg-rose-500', border: 'border-rose-500/40', badge: 'bg-rose-500/15 text-rose-300' };
    if (score >= 50) return { text: 'text-amber-400', bg: 'bg-amber-500', border: 'border-amber-500/40', badge: 'bg-amber-500/15 text-amber-300' };
    return { text: 'text-emerald-400', bg: 'bg-emerald-500', border: 'border-emerald-500/40', badge: 'bg-emerald-500/15 text-emerald-300' };
  };

  const riskStyle = getRiskColor(email.risk_score);

  const tabs = [
    { id: 'overview', label: 'Executive Overview', icon: Activity },
    { id: 'auth', label: 'Auth & Headers', icon: KeyRound },
    { id: 'relay', label: 'Relay Timeline', icon: Clock, count: email.relay_hops?.length },
    { id: 'origin', label: 'Origin Candidates', icon: Crosshair, count: email.origin_candidates?.length },
    { id: 'geomap', label: 'Geolocation Intel', icon: Globe2 },
    { id: 'indicators', label: 'IoC Indicators', icon: Hash, count: email.indicators?.length },
    { id: 'graph', label: 'Correlation Graph', icon: Share2 },
    { id: 'report', label: 'Forensic Report', icon: FileText },
    { id: 'raw', label: 'Raw Message / Body', icon: Code },
  ];

  return (
    <div className="space-y-6">
      
      {/* Top Banner: Dossier Status & Action Controls */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          
          <div className="space-y-2 flex-1">
            <div className="flex items-center space-x-3 flex-wrap">
              <button
                onClick={onBack}
                className="text-xs text-indigo-400 hover:text-indigo-300 font-mono flex items-center gap-1 bg-neutral-800 px-2.5 py-1 rounded border border-neutral-700 cursor-pointer"
              >
                &larr; Back to Dashboard
              </button>
              {caseRecord && (
                <span
                  onClick={() => onNavigateToCase && onNavigateToCase(caseRecord.id)}
                  className="text-xs font-mono bg-indigo-950 text-indigo-300 px-2.5 py-1 rounded border border-indigo-800 cursor-pointer hover:border-indigo-600"
                >
                  Case: {caseRecord.case_number}
                </span>
              )}
              <span className={`text-xs font-bold font-mono px-2.5 py-1 rounded border ${riskStyle.badge} ${riskStyle.border}`}>
                {email.classification.replace(/_/g, ' ')}
              </span>
            </div>

            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">{email.subject}</h1>

            <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-xs text-neutral-400">
              <div>
                From: <strong className="text-neutral-200">{email.sender_raw}</strong>
              </div>
              <div>
                To: <strong className="text-neutral-200">{email.recipient_raw}</strong>
              </div>
              <div>
                Date: <span className="font-mono text-neutral-300">{email.date_header || email.ingested_at}</span>
              </div>
            </div>

            {/* Evidence Hash Badge */}
            <div className="flex items-center space-x-2 pt-1">
              <span className="text-[11px] font-mono text-neutral-500">SHA-256 Hash:</span>
              <span className="text-[11px] font-mono text-neutral-300 bg-neutral-950 px-2 py-0.5 rounded border border-neutral-800">
                {email.evidence_hash}
              </span>
              <button
                onClick={() => copyToClipboard(email.evidence_hash, 'sha256')}
                className="text-neutral-400 hover:text-indigo-300 text-xs p-1 cursor-pointer"
                title="Copy SHA-256 hash"
              >
                {copiedField === 'sha256' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              </button>
            </div>
          </div>

          {/* Risk Gauge Card */}
          <div className="bg-neutral-950/80 border border-neutral-800 rounded-xl p-4 flex items-center space-x-5 min-w-[240px] justify-center lg:justify-start">
            <div className="relative flex items-center justify-center">
              <div className="w-18 h-18 rounded-full border-4 border-neutral-800 flex items-center justify-center relative">
                <div
                  className="absolute inset-0 rounded-full border-4 border-t-transparent animate-spin-slow"
                  style={{
                    borderColor: email.risk_score >= 80 ? '#f43f5e' : email.risk_score >= 50 ? '#f59e0b' : '#10b981',
                    borderTopColor: 'transparent',
                  }}
                />
                <span className={`text-2xl font-bold font-mono ${riskStyle.text}`}>{email.risk_score}</span>
              </div>
            </div>
            <div>
              <div className="text-xs text-neutral-400 uppercase font-mono">Risk Level</div>
              <div className={`text-base font-bold font-mono ${riskStyle.text}`}>
                {email.risk_score >= 80 ? 'CRITICAL' : email.risk_score >= 50 ? 'HIGH' : email.risk_score >= 25 ? 'SUSPICIOUS' : 'BENIGN'}
              </div>
              <div className="text-[11px] text-neutral-500 font-mono">Confidence: {Math.round(email.confidence * 100)}%</div>
            </div>
          </div>

        </div>

        {/* Tab Navigation Ribbon */}
        <div className="flex items-center space-x-1 mt-6 border-t border-neutral-800 pt-4 overflow-x-auto scrollbar-none">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeSubTab === tab.id;
            return (
              <button
                key={tab.id}
                id={`subtab-${tab.id}`}
                onClick={() => setActiveSubTab(tab.id)}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors cursor-pointer ${
                  isActive
                    ? 'bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 shadow-sm'
                    : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/60'
                }`}
              >
                <Icon className={`h-3.5 w-3.5 ${isActive ? 'text-indigo-400' : 'text-neutral-500'}`} />
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-neutral-800 text-neutral-300 font-mono">
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* --- SUBTAB 1: EXECUTIVE OVERVIEW --- */}
      {activeSubTab === 'overview' && (
        <div className="space-y-6">
          
          {/* AI Forensic Reasoning & Executive Summary */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-indigo-400" />
                AI-Assisted Tier-3 Forensic Reasoning & Findings
              </h2>
              <span className="text-[11px] font-mono text-indigo-400 bg-indigo-950 px-2 py-0.5 rounded border border-indigo-800">
                Gemini 2.5 Flash Engine
              </span>
            </div>
            <p className="text-sm text-neutral-300 leading-relaxed bg-neutral-950/60 p-4 rounded-lg border border-neutral-800 font-sans">
              {email.ai_reasoning || email.executive_summary}
            </p>
          </div>

          {/* Key Threat Factors & Contributing Evidences */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-4">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-rose-400" />
              Detected Threat Evidence Factors ({email.evidence_list.length})
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {email.evidence_list.map((ev) => (
                <div
                  key={ev.id}
                  className="bg-neutral-950 border border-neutral-800 hover:border-neutral-700 rounded-lg p-3.5 space-y-1.5 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase font-bold font-mono px-2 py-0.5 rounded bg-neutral-900 text-neutral-300 border border-neutral-800">
                      {ev.category} • {ev.rule_id}
                    </span>
                    <span className={`text-[10px] font-bold uppercase font-mono px-2 py-0.5 rounded ${
                      ev.severity === 'critical'
                        ? 'bg-rose-500/20 text-rose-300'
                        : ev.severity === 'high'
                        ? 'bg-amber-500/20 text-amber-300'
                        : 'bg-indigo-500/20 text-indigo-300'
                    }`}>
                      {ev.severity} (+{ev.weight})
                    </span>
                  </div>

                  <h4 className="text-sm font-semibold text-white">{ev.title}</h4>
                  <p className="text-xs text-neutral-400 leading-relaxed">{ev.description}</p>

                  {ev.mitre_technique && (
                    <div className="text-[10px] font-mono text-indigo-400 pt-1">
                      MITRE ATT&CK: {ev.mitre_technique}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* MITRE ATT&CK Mapping & Defensive Actions */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* MITRE ATT&CK Matrix */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Crosshair className="h-4 w-4 text-indigo-400" />
                MITRE ATT&CK® Technique Mapping
              </h3>

              <div className="space-y-2">
                {email.mitre_attack?.length > 0 ? (
                  email.mitre_attack.map((m, i) => (
                    <div key={i} className="bg-neutral-950 p-3 rounded-lg border border-neutral-800 space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-mono font-bold text-indigo-400">{m.technique_id}</span>
                        <span className="text-neutral-500 font-mono">{m.tactic}</span>
                      </div>
                      <div className="text-xs font-semibold text-neutral-200">{m.technique_name}</div>
                      <div className="text-[11px] text-neutral-400">{m.description}</div>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-neutral-500 italic p-3 bg-neutral-950 rounded">
                    No active adversary ATT&CK matrix techniques mapped.
                  </div>
                )}
              </div>
            </div>

            {/* Recommended Defensive Actions */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                Prescribed Defensive Playbook Actions
              </h3>

              <ul className="space-y-2 text-xs text-neutral-300">
                {email.defensive_recommendations?.map((rec, i) => (
                  <li key={i} className="flex items-start space-x-2 bg-neutral-950 p-2.5 rounded-lg border border-neutral-800/80">
                    <span className="h-4 w-4 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                      {i + 1}
                    </span>
                    <span className="leading-relaxed">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>

          </div>

        </div>
      )}

      {/* --- SUBTAB 2: AUTH & HEADERS FORENSICS --- */}
      {activeSubTab === 'auth' && (
        <div className="space-y-6">
          
          {/* Authentication Trio: SPF, DKIM, DMARC */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            
            {/* SPF Card */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold font-mono text-neutral-400">SPF (Sender Policy)</span>
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded uppercase ${
                  email.auth_analysis.spf.result === 'pass'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                }`}>
                  {email.auth_analysis.spf.result}
                </span>
              </div>
              <p className="text-xs text-neutral-300">{email.auth_analysis.spf.explanation}</p>
              <div className="text-[11px] font-mono text-neutral-500">
                Sender IP: {email.auth_analysis.spf.sender_ip || 'Unresolved'}
              </div>
            </div>

            {/* DKIM Card */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold font-mono text-neutral-400">DKIM (Crypto Signature)</span>
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded uppercase ${
                  email.auth_analysis.dkim.result === 'pass'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                }`}>
                  {email.auth_analysis.dkim.result}
                </span>
              </div>
              <p className="text-xs text-neutral-300">{email.auth_analysis.dkim.explanation}</p>
              <div className="text-[11px] font-mono text-neutral-500">
                Signing Domain: {email.auth_analysis.dkim.signing_domain || 'None'}
              </div>
            </div>

            {/* DMARC Card */}
            <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold font-mono text-neutral-400">DMARC (Alignment Policy)</span>
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded uppercase ${
                  email.auth_analysis.dmarc.result === 'pass'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                }`}>
                  {email.auth_analysis.dmarc.result}
                </span>
              </div>
              <p className="text-xs text-neutral-300">{email.auth_analysis.dmarc.explanation}</p>
              <div className="text-[11px] font-mono text-neutral-500">
                Policy: {email.auth_analysis.dmarc.policy || 'none'}
              </div>
            </div>

          </div>

          {/* Envelope vs Header Mismatch Checks */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-indigo-400" />
              Routing & Envelope Address Consistency Verification
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
              <div className="bg-neutral-950 p-3 rounded-lg border border-neutral-800">
                <span className="text-neutral-500 block mb-1">From Header:</span>
                <span className="text-neutral-200 font-bold">{email.sender_raw}</span>
              </div>
              <div className="bg-neutral-950 p-3 rounded-lg border border-neutral-800">
                <span className="text-neutral-500 block mb-1">Reply-To Diversion:</span>
                <span className={email.reply_to && email.reply_to !== email.sender_email ? 'text-rose-400 font-bold' : 'text-neutral-200'}>
                  {email.reply_to || 'Aligned with From'}
                </span>
              </div>
              <div className="bg-neutral-950 p-3 rounded-lg border border-neutral-800">
                <span className="text-neutral-500 block mb-1">Return-Path (Envelope):</span>
                <span className="text-neutral-200">{email.return_path || 'Aligned'}</span>
              </div>
            </div>
          </div>

          {/* Decoded Raw Headers Table */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <FileText className="h-4 w-4 text-indigo-400" />
                Decoded RFC 5322 Headers ({Object.keys(email.raw_headers || {}).length})
              </h3>
            </div>

            <div className="max-h-96 overflow-y-auto rounded-lg border border-neutral-800 bg-neutral-950 p-3 font-mono text-xs space-y-1.5">
              {Object.entries(email.raw_headers || {}).map(([key, val]) => (
                <div key={key} className="flex flex-col sm:flex-row sm:items-start py-1 border-b border-neutral-900">
                  <span className="text-indigo-400 font-bold sm:w-48 shrink-0">{key}:</span>
                  <span className="text-neutral-300 break-all">{val}</span>
                </div>
              ))}
            </div>
          </div>

        </div>
      )}

      {/* --- SUBTAB 3: RELAY PATH & TIMELINE --- */}
      {activeSubTab === 'relay' && (
        <div className="space-y-6">
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-semibold text-white flex items-center gap-2">
                  <Clock className="h-4 w-4 text-indigo-400" />
                  Chronological Reconstructed Mail Relay Path
                </h3>
                <p className="text-xs text-neutral-400">
                  Transmitting SMTP MTAs ordered chronologically from origin node (#1) to destination gateway.
                </p>
              </div>
              <span className="text-xs font-mono text-neutral-400 bg-neutral-950 px-3 py-1 rounded border border-neutral-800">
                {email.relay_hops?.length} Sequential Hops
              </span>
            </div>

            {/* Visual Timeline Stepper */}
            <div className="space-y-4 relative before:absolute before:inset-0 before:left-4 before:h-full before:w-0.5 before:bg-neutral-800">
              {email.relay_hops?.map((hop) => (
                <div key={hop.sequence} className="relative flex items-start space-x-4 ml-1">
                  
                  {/* Step Circle */}
                  <div className={`h-7 w-7 rounded-full flex items-center justify-center font-bold text-xs font-mono shrink-0 z-10 ${
                    hop.is_origin_candidate
                      ? 'bg-rose-500 text-neutral-950 ring-4 ring-rose-500/20'
                      : hop.is_private
                      ? 'bg-neutral-800 text-neutral-400'
                      : 'bg-indigo-600 text-white ring-4 ring-indigo-500/20'
                  }`}>
                    {hop.sequence}
                  </div>

                  {/* Hop Content Card */}
                  <div className="bg-neutral-950 border border-neutral-800 rounded-xl p-4 flex-1 space-y-2">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-sm text-white font-mono">{hop.ip_address}</span>
                        {hop.is_origin_candidate && (
                          <span className="text-[10px] font-bold uppercase font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                            Probable Origin
                          </span>
                        )}
                        {hop.is_private && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-neutral-800 text-neutral-400">
                            Private Subnet (RFC 1918)
                          </span>
                        )}
                      </div>
                      <span className="text-xs font-mono text-neutral-400">{hop.timestamp}</span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                      <div>
                        <span className="text-neutral-500">From Host:</span> <span className="text-neutral-300">{hop.source_host}</span>
                      </div>
                      <div>
                        <span className="text-neutral-500">By MTA:</span> <span className="text-neutral-300">{hop.destination_host}</span>
                      </div>
                      <div>
                        <span className="text-neutral-500">Protocol:</span> <span className="text-indigo-400">{hop.protocol}</span>
                      </div>
                      <div>
                        <span className="text-neutral-500">Encryption:</span> <span className="text-neutral-300">{hop.encryption || 'Cleartext'}</span>
                      </div>
                    </div>

                    {hop.geo && (
                      <div className="mt-2 pt-2 border-t border-neutral-900 flex items-center justify-between text-xs text-neutral-400">
                        <span>📍 {hop.geo.city}, {hop.geo.country} ({hop.geo.isp})</span>
                        <span className="font-mono text-indigo-400">{hop.geo.asn}</span>
                      </div>
                    )}

                    {hop.anomalies?.length > 0 && (
                      <div className="mt-2 p-2 rounded bg-rose-950/50 border border-rose-800/50 text-[11px] text-rose-300">
                        ⚠️ Anomalies: {hop.anomalies.join('; ')}
                      </div>
                    )}
                  </div>

                </div>
              ))}
            </div>

          </div>
        </div>
      )}

      {/* --- SUBTAB 4: ORIGIN CANDIDATE MATRIX --- */}
      {activeSubTab === 'origin' && (
        <div className="space-y-6">
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-4">
            <div>
              <h3 className="text-base font-semibold text-white flex items-center gap-2">
                <Crosshair className="h-4 w-4 text-indigo-400" />
                Origin Candidate Evaluation & Reliability Matrix
              </h3>
              <p className="text-xs text-neutral-400">
                Evaluated sender infrastructure candidates based on observed Received hop sequence, reverse DNS, and MTA legitimacy.
              </p>
            </div>

            <div className="space-y-3">
              {email.origin_candidates?.map((candidate, idx) => (
                <div
                  key={idx}
                  className="bg-neutral-950 border border-neutral-800 rounded-xl p-4 space-y-2 hover:border-neutral-700 transition-colors"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center space-x-3">
                      <span className="h-6 w-6 rounded-full bg-neutral-800 text-neutral-300 flex items-center justify-center text-xs font-mono font-bold">
                        #{idx + 1}
                      </span>
                      <span className="text-base font-bold font-mono text-white">{candidate.ip_address}</span>
                      {candidate.is_vpn_proxy && (
                        <span className="text-[10px] font-bold uppercase font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                          VPN / Tor Anonymizer
                        </span>
                      )}
                    </div>

                    <div className="flex items-center space-x-2">
                      <span className="text-xs text-neutral-400">Candidate Reliability:</span>
                      <span className={`text-sm font-bold font-mono ${
                        candidate.reliability_score >= 80 ? 'text-emerald-400' : candidate.reliability_score >= 50 ? 'text-amber-400' : 'text-neutral-400'
                      }`}>
                        {candidate.reliability_score}%
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono pt-1">
                    <div>
                      <span className="text-neutral-500">Source:</span> <span className="text-neutral-300">{candidate.evidence_source}</span>
                    </div>
                    <div>
                      <span className="text-neutral-500">Infrastructure:</span> <span className="text-neutral-300">{candidate.infrastructure_info}</span>
                    </div>
                  </div>

                  <p className="text-xs text-neutral-400 bg-neutral-900/80 p-2.5 rounded-lg border border-neutral-800/80 leading-relaxed">
                    <strong className="text-neutral-300">Forensic Evaluation:</strong> {candidate.limitations}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* --- SUBTAB 5: GEOLOCATION MAP --- */}
      {activeSubTab === 'geomap' && (
        <div className="space-y-6">
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-4">
            <div>
              <h3 className="text-base font-semibold text-white flex items-center gap-2">
                <Globe2 className="h-4 w-4 text-indigo-400" />
                Global Mail Relay Infrastructure & Geolocation Plot
              </h3>
              <p className="text-xs text-neutral-400">
                Visualizes geographical hops traversed by the message across global data centers and autonomous networks.
              </p>
            </div>

            <LeafletRelayMap
              relayHops={email.relay_hops}
              originCandidates={email.origin_candidates}
            />
          </div>
        </div>
      )}

      {/* --- SUBTAB 6: IoC INDICATORS --- */}
      {activeSubTab === 'indicators' && (
        <div className="space-y-6">
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-semibold text-white flex items-center gap-2">
                  <Hash className="h-4 w-4 text-indigo-400" />
                  Extracted Indicators of Compromise (IoC)
                </h3>
                <p className="text-xs text-neutral-400">
                  Structured indicators available for SIEM/EDR blocklisting and external threat-intel correlation.
                </p>
              </div>
              <button
                onClick={() => {
                  const exportText = email.indicators.map((i) => `${i.type},${i.value},${i.risk_level}`).join('\n');
                  copyToClipboard(exportText, 'all-ioc');
                }}
                className="text-xs px-3 py-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-300 border border-neutral-700 flex items-center gap-1.5 cursor-pointer"
              >
                {copiedField === 'all-ioc' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                Copy All IoCs
              </button>
            </div>

            <div className="overflow-x-auto rounded-lg border border-neutral-800">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-neutral-950 text-neutral-400 uppercase text-[10px]">
                  <tr>
                    <th className="p-3">Type</th>
                    <th className="p-3">Indicator Value</th>
                    <th className="p-3">Source</th>
                    <th className="p-3">Reputation</th>
                    <th className="p-3">Risk</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-800/80 bg-neutral-900/50">
                  {email.indicators?.map((ind) => (
                    <tr key={ind.id} className="hover:bg-neutral-800/50 transition-colors">
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded bg-neutral-800 text-indigo-400 font-bold">
                          {ind.type}
                        </span>
                      </td>
                      <td className="p-3 font-medium text-white break-all max-w-xs">{ind.value}</td>
                      <td className="p-3 text-neutral-400">{ind.source}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          ind.reputation === 'MALICIOUS'
                            ? 'bg-rose-500/20 text-rose-300'
                            : ind.reputation === 'SUSPICIOUS'
                            ? 'bg-amber-500/20 text-amber-300'
                            : 'bg-emerald-500/20 text-emerald-300'
                        }`}>
                          {ind.reputation}
                        </span>
                      </td>
                      <td className="p-3 text-neutral-300 uppercase">{ind.risk_level}</td>
                      <td className="p-3 text-right">
                        <button
                          onClick={() => copyToClipboard(ind.value, ind.id)}
                          className="text-neutral-400 hover:text-indigo-300 p-1 cursor-pointer"
                          title="Copy indicator value"
                        >
                          {copiedField === ind.id ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

          </div>
        </div>
      )}

      {/* --- SUBTAB 7: CORRELATION GRAPH --- */}
      {activeSubTab === 'graph' && (
        <div className="space-y-6">
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5">
            <CorrelationGraphCanvas data={email.graph_data} />
          </div>
        </div>
      )}

      {/* --- SUBTAB 8: CERTIFIED FORENSIC REPORT --- */}
      {activeSubTab === 'report' && (
        <div className="space-y-6">
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-6 space-y-6 print:bg-white print:text-black">
            
            {/* Report Header & Action */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-neutral-800">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono font-bold text-indigo-400">SIH FORENSIC DOSSIER</span>
                  <span className="text-[11px] font-mono text-neutral-400">• RFC 5322 STANDARDS</span>
                </div>
                <h2 className="text-xl font-bold text-white mt-1">Official Forensic Threat Investigation Report</h2>
                <p className="text-xs text-neutral-400">Evidence ID: {email.id} | Generated: {new Date().toUTCString()}</p>
              </div>

              {/* Action Toolbar */}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => window.print()}
                  className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-indigo-600 text-white font-bold text-xs hover:bg-indigo-500 transition-colors shadow-lg cursor-pointer"
                  title="Print official report to PDF"
                >
                  <Printer className="h-4 w-4" />
                  <span>Print PDF</span>
                </button>

                <button
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(email, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `forensic-dossier-${email.id}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 font-bold text-xs border border-neutral-700 transition-colors cursor-pointer"
                  title="Export full dossier in JSON format"
                >
                  <Download className="h-4 w-4 text-indigo-400" />
                  <span>JSON Dossier</span>
                </button>

                <button
                  onClick={() => {
                    const stixBundle = {
                      type: 'bundle',
                      id: `bundle--${email.evidence_hash.slice(0, 36)}`,
                      spec_version: '2.1',
                      objects: [
                        {
                          type: 'email-message',
                          id: `email-message--${email.evidence_hash.slice(0, 36)}`,
                          spec_version: '2.1',
                          is_multipart: email.attachments?.length > 0,
                          subject: email.subject,
                          from_ref: `email-addr--${email.sender_email}`,
                          date: email.date_header || email.ingested_at,
                          body: email.body_plain?.slice(0, 500),
                        },
                        ...email.indicators.map((ind) => ({
                          type: 'indicator',
                          id: `indicator--${ind.id}`,
                          spec_version: '2.1',
                          name: `${ind.type}: ${ind.value}`,
                          pattern_type: 'stix',
                          pattern: `[${ind.type === 'IP' ? 'ipv4-addr:value' : ind.type === 'DOMAIN' ? 'domain-name:value' : ind.type === 'URL' ? 'url:value' : 'file:hashes.sha256'} = '${ind.value}']`,
                          valid_from: new Date().toISOString(),
                          confidence: ind.reputation === 'MALICIOUS' ? 95 : 70,
                        })),
                        ...email.mitre_attack.map((m) => ({
                          type: 'attack-pattern',
                          id: `attack-pattern--${m.technique_id.toLowerCase()}`,
                          spec_version: '2.1',
                          name: m.technique_name,
                          external_references: [
                            {
                              source_name: 'mitre-attack',
                              external_id: m.technique_id,
                              url: `https://attack.mitre.org/techniques/${m.technique_id}`,
                            },
                          ],
                        })),
                      ],
                    };
                    const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `stix-threat-intel-${email.id}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 font-bold text-xs border border-neutral-700 transition-colors cursor-pointer"
                  title="Export STIX 2.1 Threat Intel Bundle"
                >
                  <Share2 className="h-4 w-4 text-emerald-400" />
                  <span>STIX 2.1</span>
                </button>

                <button
                  onClick={() => {
                    const csvContent = [
                      'Type,Value,Source,Reputation,Risk Level',
                      ...email.indicators.map((i) => `"${i.type}","${i.value}","${i.source}","${i.reputation}","${i.risk_level}"`),
                    ].join('\n');
                    const blob = new Blob([csvContent], { type: 'text/csv' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `indicators-${email.id}.csv`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 font-bold text-xs border border-neutral-700 transition-colors cursor-pointer"
                  title="Export Indicators to CSV"
                >
                  <Hash className="h-4 w-4 text-amber-400" />
                  <span>CSV IoCs</span>
                </button>

                {email.raw_eml_source && (
                  <button
                    onClick={() => {
                      const blob = new Blob([email.raw_eml_source || ''], { type: 'message/rfc822' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `evidence-${email.id}.eml`;
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 font-bold text-xs border border-neutral-700 transition-colors cursor-pointer"
                    title="Download raw .eml evidence file"
                  >
                    <Download className="h-4 w-4 text-purple-400" />
                    <span>.EML Source</span>
                  </button>
                )}
              </div>
            </div>

            {/* Cryptographic Hash Badge */}
            <div className="bg-neutral-950 p-4 rounded-lg border border-neutral-800 space-y-2 text-xs font-mono">
              <div className="text-neutral-400 font-bold uppercase text-[11px]">Evidence Integrity & Custody Seal</div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                <div>SHA-256: <strong className="text-indigo-400">{email.evidence_hash}</strong></div>
                <div>MD5: <strong className="text-neutral-300">{email.md5_hash}</strong></div>
              </div>
            </div>

            {/* Findings Summary */}
            <div className="space-y-2">
              <h3 className="text-sm font-bold text-white uppercase font-mono">1. Executive Threat Classification</h3>
              <p className="text-xs text-neutral-300 leading-relaxed bg-neutral-950 p-3.5 rounded-lg border border-neutral-800">
                {email.executive_summary}
              </p>
            </div>

            {/* Authentication Matrix in Report */}
            <div className="space-y-2">
              <h3 className="text-sm font-bold text-white uppercase font-mono">2. RFC 5322 Authentication & Spoofing Audit</h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                <div className="bg-neutral-950 p-3 rounded-lg border border-neutral-800">
                  <div className="text-neutral-500">SPF Validation:</div>
                  <div className={`font-bold uppercase ${email.auth_analysis.spf.result === 'pass' ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {email.auth_analysis.spf.result}
                  </div>
                  <div className="text-[11px] text-neutral-400 mt-1">{email.auth_analysis.spf.explanation}</div>
                </div>
                <div className="bg-neutral-950 p-3 rounded-lg border border-neutral-800">
                  <div className="text-neutral-500">DKIM Cryptographic Signature:</div>
                  <div className={`font-bold uppercase ${email.auth_analysis.dkim.result === 'pass' ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {email.auth_analysis.dkim.result}
                  </div>
                  <div className="text-[11px] text-neutral-400 mt-1">{email.auth_analysis.dkim.explanation}</div>
                </div>
                <div className="bg-neutral-950 p-3 rounded-lg border border-neutral-800">
                  <div className="text-neutral-500">DMARC Domain Alignment:</div>
                  <div className={`font-bold uppercase ${email.auth_analysis.dmarc.result === 'pass' ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {email.auth_analysis.dmarc.result}
                  </div>
                  <div className="text-[11px] text-neutral-400 mt-1">{email.auth_analysis.dmarc.explanation}</div>
                </div>
              </div>
            </div>

            {/* Relay Hops in Report */}
            <div className="space-y-2">
              <h3 className="text-sm font-bold text-white uppercase font-mono">3. Reconstructed SMTP Relay Trace ({email.relay_hops?.length || 0} Hops)</h3>
              <div className="overflow-x-auto rounded-lg border border-neutral-800">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-neutral-950 text-neutral-400 uppercase text-[10px]">
                    <tr>
                      <th className="p-2.5">Hop</th>
                      <th className="p-2.5">IP Address</th>
                      <th className="p-2.5">MTA Source / Host</th>
                      <th className="p-2.5">Geolocation</th>
                      <th className="p-2.5">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-neutral-800/80 bg-neutral-950/50">
                    {email.relay_hops?.map((hop) => (
                      <tr key={hop.sequence}>
                        <td className="p-2.5 text-indigo-400 font-bold">#{hop.sequence}</td>
                        <td className="p-2.5 font-bold text-white">{hop.ip_address}</td>
                        <td className="p-2.5 text-neutral-400">{hop.source_host} &rarr; {hop.destination_host}</td>
                        <td className="p-2.5 text-neutral-300">{hop.geo ? `${hop.geo.city}, ${hop.geo.country}` : 'Private / Internal'}</td>
                        <td className="p-2.5">
                          {hop.is_origin_candidate ? (
                            <span className="text-[10px] bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded font-bold">ORIGIN CANDIDATE</span>
                          ) : (
                            <span className="text-[10px] text-neutral-500">RELAY</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Disclaimers & Legal Notice */}
            <div className="space-y-2 pt-2 border-t border-neutral-800 text-[11px] text-neutral-400 leading-relaxed">
              <p><strong>Attribution & Geolocation Limitations:</strong> {email.disclaimers?.geolocation_limitation}</p>
              <p><strong>Legal Notice:</strong> {email.disclaimers?.legal_notice}</p>
            </div>

          </div>
        </div>
      )}

      {/* --- SUBTAB 9: RAW MESSAGE / BODY --- */}
      {activeSubTab === 'raw' && (
        <div className="space-y-6">
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-4">
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              <Code className="h-4 w-4 text-indigo-400" />
              Decoded Message Body & Raw RFC 5322 Source
            </h3>

            {email.body_html ? (
              <div className="space-y-2">
                <span className="text-xs text-neutral-400 font-mono">Sanitized HTML Sandbox View:</span>
                <div
                  className="bg-white text-neutral-900 p-4 rounded-lg overflow-x-auto max-h-96 text-sm"
                  dangerouslySetInnerHTML={{ __html: email.body_html }}
                />
              </div>
            ) : null}

            <div className="space-y-2">
              <span className="text-xs text-neutral-400 font-mono">Plaintext Content:</span>
              <pre className="bg-neutral-950 text-neutral-300 p-4 rounded-lg font-mono text-xs overflow-x-auto max-h-96 whitespace-pre-wrap leading-relaxed border border-neutral-800">
                {email.body_plain || '(No plaintext body rendered)'}
              </pre>
            </div>

            {email.raw_eml_source && (
              <div className="space-y-2 pt-4 border-t border-neutral-800">
                <span className="text-xs text-neutral-400 font-mono">Full Raw .EML Source:</span>
                <pre className="bg-neutral-950 text-neutral-400 p-4 rounded-lg font-mono text-[11px] overflow-x-auto max-h-96 whitespace-pre-wrap leading-relaxed border border-neutral-800">
                  {email.raw_eml_source}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  );
};
