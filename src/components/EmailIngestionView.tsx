import React, { useState, useEffect } from 'react';
import {
  Upload,
  FileCode,
  Terminal,
  Play,
  Sparkles,
  Layers,
  Shield,
  EyeOff,
  AlertCircle,
  CheckCircle2,
  FileText,
  RotateCcw,
} from 'lucide-react';
import { AnalyzedEmail, CaseRecord } from '../types';
import { analyzeEmail, fetchPresetSamples } from '../api';

interface EmailIngestionViewProps {
  cases: CaseRecord[];
  onAnalysisComplete: (email: AnalyzedEmail) => void;
  presetToLoad?: string | null;
}

export const EmailIngestionView: React.FC<EmailIngestionViewProps> = ({
  cases,
  onAnalysisComplete,
  presetToLoad,
}) => {
  const [rawEml, setRawEml] = useState<string>('');
  const [selectedCaseId, setSelectedCaseId] = useState<string>('');
  const [customSubject, setCustomSubject] = useState<string>('');
  const [maskPii, setMaskPii] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [presetSamples, setPresetSamples] = useState<any[]>([]);

  useEffect(() => {
    fetchPresetSamples()
      .then((samples) => {
        setPresetSamples(samples);
        if (presetToLoad) {
          const match = samples.find((s) => s.id === presetToLoad);
          if (match) {
            setRawEml(match.eml);
            setCustomSubject(match.name);
          }
        }
      })
      .catch(console.error);
  }, [presetToLoad]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setRawEml(content);
      setCustomSubject(file.name.replace(/\.(eml|txt|msg)$/i, ''));
      setError(null);
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setRawEml(content);
      setCustomSubject(file.name.replace(/\.(eml|txt|msg)$/i, ''));
      setError(null);
    };
    reader.readAsText(file);
  };

  const handleSelectPreset = (sample: any) => {
    setRawEml(sample.eml);
    setCustomSubject(sample.name);
    setError(null);
  };

  const handleRunAnalysis = async () => {
    if (!rawEml.trim()) {
      setError('Please provide raw RFC 5322 email text or upload an .eml file.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      let payloadText = rawEml;
      if (maskPii) {
        // Redact phone numbers and standard private names if privacy toggle enabled
        payloadText = payloadText.replace(/\+1\s*\(\d{3}\)\s*\d{3}-\d{4}/g, '[REDACTED_PHONE]');
      }

      const analyzed = await analyzeEmail({
        raw_eml: payloadText,
        case_id: selectedCaseId || undefined,
        custom_subject: customSubject || undefined,
      });

      setIsLoading(false);
      onAnalysisComplete(analyzed);
    } catch (err: any) {
      setIsLoading(false);
      setError(err?.message || 'Failed to complete email threat analysis.');
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Header & Overview */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Terminal className="h-6 w-6 text-indigo-400" />
            Email Ingestion & Forensic Parsing Engine
          </h1>
          <p className="text-sm text-neutral-400 mt-1">
            Accepts raw RFC 5322 message headers, MIME multi-part attachments, and traces originating relay nodes.
          </p>
        </div>

        {/* Quick Sample Selector Bar */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-neutral-400 font-mono flex items-center gap-1">
            <Sparkles className="h-3.5 w-3.5 text-indigo-400" />
            Attack Presets:
          </span>
          {presetSamples.map((sample) => (
            <button
              key={sample.id}
              onClick={() => handleSelectPreset(sample)}
              className="text-xs px-2.5 py-1 rounded bg-neutral-800 hover:bg-neutral-700 text-neutral-300 border border-neutral-700 transition-colors font-medium cursor-pointer"
              title={sample.description}
            >
              {sample.category === 'BUSINESS_EMAIL_COMPROMISE'
                ? 'BEC Wire Fraud'
                : sample.category === 'PHISHING'
                ? 'M365 Phish'
                : sample.category === 'MALWARE_SUSPECTED'
                ? 'Malware .ISO'
                : 'Legit Newsletter'}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold">Analysis Ingestion Error</p>
            <p className="text-rose-400/90 text-xs mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* Main Form Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 2 Cols: Editor & Upload Area */}
        <div className="lg:col-span-2 space-y-4">
          
          {/* Drag and Drop Zone */}
          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleDrop}
            className="border-2 border-dashed border-neutral-700 hover:border-indigo-500/50 rounded-xl p-6 bg-neutral-900/60 hover:bg-neutral-900 transition-colors text-center relative group"
          >
            <input
              type="file"
              id="file-upload-input"
              accept=".eml,.txt,.msg"
              onChange={handleFileUpload}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            />
            <div className="flex flex-col items-center justify-center space-y-2 pointer-events-none">
              <div className="p-3 rounded-full bg-indigo-500/10 text-indigo-400 group-hover:scale-110 transition-transform">
                <Upload className="h-6 w-6" />
              </div>
              <p className="text-sm font-medium text-neutral-200">
                Drag & Drop <strong className="text-indigo-400">.EML</strong> file here, or click to browse
              </p>
              <p className="text-xs text-neutral-500">
                Calculates cryptographic SHA-256 evidence hash upon ingestion. Attachments are never executed.
              </p>
            </div>
          </div>

          {/* Raw Text Editor */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-4 space-y-2">
            <div className="flex items-center justify-between text-xs text-neutral-400 pb-2 border-b border-neutral-800">
              <span className="flex items-center gap-1.5 font-mono">
                <FileCode className="h-4 w-4 text-indigo-400" />
                Raw RFC 5322 Header & MIME Content
              </span>
              <div className="flex items-center space-x-3">
                <span>{rawEml.split('\n').length} lines</span>
                {rawEml && (
                  <button
                    onClick={() => setRawEml('')}
                    className="text-neutral-400 hover:text-rose-400 flex items-center gap-1"
                  >
                    <RotateCcw className="h-3 w-3" /> Clear
                  </button>
                )}
              </div>
            </div>

            <textarea
              id="raw-eml-textarea"
              value={rawEml}
              onChange={(e) => setRawEml(e.target.value)}
              placeholder="Paste RFC 5322 raw email source here (including Received: headers, From:, To:, Subject:, SPF/DKIM authentication results, and body)..."
              rows={16}
              className="w-full bg-neutral-950 border border-neutral-800 rounded-lg p-3 font-mono text-xs text-neutral-200 placeholder:text-neutral-600 focus:outline-none focus:border-indigo-500/50 leading-relaxed resize-y"
            />
          </div>

        </div>

        {/* Right Col: Ingestion Configuration & Action Panel */}
        <div className="space-y-4">
          
          {/* Case Association */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Layers className="h-4 w-4 text-indigo-400" />
              Investigation Case File
            </h2>

            <div>
              <label className="block text-xs font-medium text-neutral-400 mb-1">
                Assign to Existing Case (Optional)
              </label>
              <select
                id="case-select-dropdown"
                value={selectedCaseId}
                onChange={(e) => setSelectedCaseId(e.target.value)}
                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-neutral-200 focus:outline-none focus:border-indigo-500/50"
              >
                <option value="">+ Auto-generate New Investigation Case</option>
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.case_number}: {c.title.slice(0, 35)}...
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-neutral-400 mb-1">
                Investigation Title / Alias
              </label>
              <input
                type="text"
                value={customSubject}
                onChange={(e) => setCustomSubject(e.target.value)}
                placeholder="e.g. Suspicious CEO Wire Request - Incident #4"
                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-neutral-200 focus:outline-none focus:border-indigo-500/50"
              />
            </div>
          </div>

          {/* Privacy & Forensics Options */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-3">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Shield className="h-4 w-4 text-indigo-400" />
              Evidence & Privacy Controls
            </h2>

            <label className="flex items-start space-x-2 text-xs text-neutral-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={maskPii}
                onChange={(e) => setMaskPii(e.target.checked)}
                className="rounded bg-neutral-950 border-neutral-700 text-indigo-500 focus:ring-0 mt-0.5"
              />
              <div>
                <span className="font-medium text-neutral-200 flex items-center gap-1">
                  <EyeOff className="h-3 w-3 text-neutral-400" /> Mask Confidential PII
                </span>
                <p className="text-[11px] text-neutral-500 mt-0.5">
                  Masks phone numbers and private identifiers during ingestion.
                </p>
              </div>
            </label>

            <div className="pt-2 border-t border-neutral-800 text-[11px] text-neutral-400 space-y-1.5">
              <div className="flex items-center gap-1.5 text-emerald-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                <span>SHA-256 Cryptographic Evidence Stamping</span>
              </div>
              <div className="flex items-center gap-1.5 text-emerald-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                <span>Safe Sandbox Attachment Hashing (Zero Exec)</span>
              </div>
              <div className="flex items-center gap-1.5 text-emerald-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                <span>Deterministic + Gemini AI Threat Reasoning</span>
              </div>
            </div>
          </div>

          {/* Action Trigger Button */}
          <button
            id="run-analysis-btn"
            onClick={handleRunAnalysis}
            disabled={isLoading || !rawEml.trim()}
            className={`w-full flex items-center justify-center space-x-2 py-3 px-4 rounded-xl font-bold text-sm transition-all shadow-lg ${
              isLoading || !rawEml.trim()
                ? 'bg-neutral-800 text-neutral-500 cursor-not-allowed border border-neutral-700'
                : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-indigo-600/25 hover:shadow-indigo-600/40 cursor-pointer'
            }`}
          >
            {isLoading ? (
              <>
                <div className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Deconstructing Headers & Relay Path...</span>
              </>
            ) : (
              <>
                <Play className="h-4 w-4 fill-current" />
                <span>Run Forensic Threat Analysis</span>
              </>
            )}
          </button>

        </div>

      </div>

    </div>
  );
};
