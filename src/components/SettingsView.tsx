import React, { useState } from 'react';
import { IntelligenceProviderConfig } from '../types';
import {
  Sliders,
  Shield,
  Radio,
  CheckCircle2,
  Database,
  Cpu,
  Globe2,
  Lock,
} from 'lucide-react';
import { updateConfig } from '../api';

interface SettingsViewProps {
  config: IntelligenceProviderConfig;
  onConfigSaved: (newConf: IntelligenceProviderConfig) => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ config, onConfigSaved }) => {
  const [formData, setFormData] = useState<IntelligenceProviderConfig>(config);
  const [saveStatus, setSaveStatus] = useState<string | null>(null);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const saved = await updateConfig(formData);
      onConfigSaved(saved);
      setSaveStatus('Intelligence adapters configuration successfully saved.');
      setTimeout(() => setSaveStatus(null), 3000);
    } catch (err: any) {
      setSaveStatus('Failed to update config: ' + err?.message);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      
      {/* Top Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Sliders className="h-6 w-6 text-indigo-400" />
          Threat Intelligence Adapters & Heuristic Rules
        </h1>
        <p className="text-sm text-neutral-400 mt-1">
          Configure external OSINT enrichment providers, AI forensic analysis model, and DMARC enforcement policies.
        </p>
      </div>

      {saveStatus && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="h-4 w-4" />
          <span>{saveStatus}</span>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-6">
        
        {/* Intelligence Providers Section */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Globe2 className="h-4 w-4 text-indigo-400" />
            External Threat Intelligence Providers
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            
            {/* VirusTotal Adapter */}
            <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-white">VirusTotal v3 Adapter</span>
                <input
                  type="checkbox"
                  checked={formData.virus_total_enabled}
                  onChange={(e) => setFormData({ ...formData, virus_total_enabled: e.target.checked })}
                  className="rounded text-indigo-500 accent-indigo-600"
                />
              </div>
              <p className="text-[11px] text-neutral-400">
                Queries URL, domain, and attachment hash reputation databases.
              </p>
            </div>

            {/* AbuseIPDB Adapter */}
            <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-white">AbuseIPDB Gateway</span>
                <input
                  type="checkbox"
                  checked={formData.abuse_ipdb_enabled}
                  onChange={(e) => setFormData({ ...formData, abuse_ipdb_enabled: e.target.checked })}
                  className="rounded text-indigo-500 accent-indigo-600"
                />
              </div>
              <p className="text-[11px] text-neutral-400">
                Checks IP address abuse confidence scores and malicious reports.
              </p>
            </div>

            {/* IPQS Adapter */}
            <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-white">IPQualityScore (IPQS) Proxy Detect</span>
                <input
                  type="checkbox"
                  checked={formData.ipqs_enabled}
                  onChange={(e) => setFormData({ ...formData, ipqs_enabled: e.target.checked })}
                  className="rounded text-indigo-500 accent-indigo-600"
                />
              </div>
              <p className="text-[11px] text-neutral-400">
                Detects commercial VPN, residential proxy, and Tor exit relay nodes.
              </p>
            </div>

            {/* Gemini 2.5 Flash Engine */}
            <div className="bg-neutral-950 p-4 rounded-xl border border-neutral-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-white">Google Gemini 2.5 Flash</span>
                <input
                  type="checkbox"
                  checked={formData.gemini_ai_enabled}
                  onChange={(e) => setFormData({ ...formData, gemini_ai_enabled: e.target.checked })}
                  className="rounded text-indigo-500 accent-indigo-600"
                />
              </div>
              <p className="text-[11px] text-neutral-400">
                Powers AI forensic explanations and social engineering NLP analysis.
              </p>
            </div>

          </div>
        </div>

        {/* Heuristic Thresholds & Policy Enforcement */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Shield className="h-4 w-4 text-indigo-400" />
            Detection Thresholds & Enforcement Policies
          </h2>

          <div className="space-y-4 text-xs">
            <div>
              <div className="flex justify-between text-neutral-300 mb-1">
                <span>Critical Threat Alert Threshold (Score: {formData.auto_alert_threshold}/100)</span>
                <span className="font-mono text-indigo-400 font-bold">{formData.auto_alert_threshold}</span>
              </div>
              <input
                type="range"
                min="50"
                max="95"
                value={formData.auto_alert_threshold}
                onChange={(e) => setFormData({ ...formData, auto_alert_threshold: parseInt(e.target.value, 10) })}
                className="w-full accent-indigo-600"
              />
            </div>

            <label className="flex items-center space-x-2 text-neutral-300 cursor-pointer pt-2 border-t border-neutral-800">
              <input
                type="checkbox"
                checked={formData.strict_dmarc_enforcement}
                onChange={(e) => setFormData({ ...formData, strict_dmarc_enforcement: e.target.checked })}
                className="rounded text-indigo-500 accent-indigo-600"
              />
              <div>
                <span className="font-semibold text-white">Strict DMARC Policy Enforcement</span>
                <p className="text-[11px] text-neutral-400">
                  Instantly triggers critical severity if DMARC alignment fails on claimed corporate domains.
                </p>
              </div>
            </label>
          </div>
        </div>

        <button
          type="submit"
          className="px-6 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-lg shadow-indigo-600/20 cursor-pointer"
        >
          Save Configuration & Adapters
        </button>
      </form>

    </div>
  );
};
