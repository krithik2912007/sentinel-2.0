import React, { useState, useEffect } from 'react';
import {
  AnalyzedEmail,
  AuditEvent,
  CaseRecord,
  IntelligenceProviderConfig,
  UserProfile,
  UserRole,
} from './types';
import {
  fetchCurrentUser,
  fetchEmails,
  fetchCases,
  fetchStats,
  fetchAuditLogs,
  fetchConfig,
  switchUserRole,
  createCase,
} from './api';
import { Header } from './components/Header';
import { DashboardView } from './components/DashboardView';
import { EmailIngestionView } from './components/EmailIngestionView';
import { AnalysisDetailView } from './components/AnalysisDetailView';
import { CasesListView } from './components/CasesListView';
import { CaseDetailModal } from './components/CaseDetailModal';
import { GlobalRelayMapView } from './components/GlobalRelayMapView';
import { GlobalThreatGraphView } from './components/GlobalThreatGraphView';
import { AuditLogView } from './components/AuditLogView';
import { SettingsView } from './components/SettingsView';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(null);
  const [stats, setStats] = useState<any>(null);
  const [emails, setEmails] = useState<AnalyzedEmail[]>([]);
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>([]);
  const [config, setConfig] = useState<IntelligenceProviderConfig | null>(null);

  // Deep view selections
  const [selectedEmail, setSelectedEmail] = useState<AnalyzedEmail | null>(null);
  const [selectedCaseModal, setSelectedCaseModal] = useState<CaseRecord | null>(null);
  const [presetToIngest, setPresetToIngest] = useState<string | null>(null);

  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Load initial SOC data
  const loadData = async () => {
    try {
      const [userRes, statsRes, emailsRes, casesRes, logsRes, confRes] = await Promise.all([
        fetchCurrentUser().catch(() => null),
        fetchStats().catch(() => null),
        fetchEmails().catch(() => []),
        fetchCases().catch(() => []),
        fetchAuditLogs().catch(() => []),
        fetchConfig().catch(() => null),
      ]);

      if (userRes) setCurrentUser(userRes);
      if (statsRes) setStats(statsRes);
      if (emailsRes) setEmails(emailsRes);
      if (casesRes) setCases(casesRes);
      if (logsRes) setAuditLogs(logsRes);
      if (confRes) setConfig(confRes);
      setIsLoading(false);
    } catch (err) {
      console.error('Failed to load application data:', err);
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSwitchRole = async (newRole: UserRole) => {
    try {
      const updatedUser = await switchUserRole(newRole);
      setCurrentUser(updatedUser);
      loadData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleSelectEmail = (email: AnalyzedEmail) => {
    setSelectedEmail(email);
    setActiveTab('analysis_detail');
  };

  const handleAnalysisCompleted = (analyzed: AnalyzedEmail) => {
    setEmails((prev) => [analyzed, ...prev]);
    setSelectedEmail(analyzed);
    setActiveTab('analysis_detail');
    loadData();
  };

  const handleCreateCase = async (caseData: { title: string; description: string; priority: string; tags?: string[] }) => {
    try {
      const newCase = await createCase(caseData);
      setCases((prev) => [newCase, ...prev]);
      loadData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleNavigateToIngestWithPreset = (presetId?: string) => {
    setPresetToIngest(presetId || null);
    setSelectedEmail(null);
    setActiveTab('ingest');
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-200 flex flex-col font-sans antialiased">
      
      {/* Platform Header */}
      <Header
        activeTab={activeTab === 'analysis_detail' ? 'ingest' : activeTab}
        setActiveTab={(tab) => {
          setSelectedEmail(null);
          setActiveTab(tab);
        }}
        currentUser={currentUser}
        onSwitchRole={handleSwitchRole}
        stats={stats}
      />

      {/* Main Content Stage */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {isLoading ? (
          <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4">
            <div className="h-10 w-10 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-sm font-mono text-neutral-400">Loading Cannon Crew Forensic Intelligence Hub...</p>
          </div>
        ) : (
          <>
            {/* View: Dashboard */}
            {activeTab === 'dashboard' && (
              <DashboardView
                stats={stats}
                emails={emails}
                cases={cases}
                onSelectEmail={handleSelectEmail}
                onNavigateToIngest={handleNavigateToIngestWithPreset}
                onNavigateToCases={() => setActiveTab('cases')}
              />
            )}

            {/* View: Ingestion & Analysis */}
            {activeTab === 'ingest' && (
              <EmailIngestionView
                cases={cases}
                onAnalysisComplete={handleAnalysisCompleted}
                presetToLoad={presetToIngest}
              />
            )}

            {/* View: Deep Forensic Detail View */}
            {activeTab === 'analysis_detail' && selectedEmail && (
              <AnalysisDetailView
                email={selectedEmail}
                caseRecord={cases.find((c) => c.id === selectedEmail.case_id)}
                onBack={() => setActiveTab('dashboard')}
                onNavigateToCase={(caseId) => {
                  const match = cases.find((c) => c.id === caseId);
                  if (match) setSelectedCaseModal(match);
                }}
              />
            )}

            {/* View: Cases List */}
            {activeTab === 'cases' && (
              <CasesListView
                cases={cases}
                onSelectCase={(c) => setSelectedCaseModal(c)}
                onCreateCase={handleCreateCase}
              />
            )}

            {/* View: Global Relay Map */}
            {activeTab === 'geomap' && (
              <GlobalRelayMapView
                emails={emails}
                onSelectEmail={handleSelectEmail}
              />
            )}

            {/* View: Global Threat Graph */}
            {activeTab === 'graph' && (
              <GlobalThreatGraphView
                emails={emails}
                onSelectEmail={handleSelectEmail}
              />
            )}

            {/* View: Audit Trail */}
            {activeTab === 'audit' && (
              <AuditLogView logs={auditLogs} />
            )}

            {/* View: Settings & Adapters */}
            {activeTab === 'settings' && config && (
              <SettingsView
                config={config}
                onConfigSaved={(newConf) => setConfig(newConf)}
              />
            )}
          </>
        )}

      </main>

      {/* Case Details Modal */}
      {selectedCaseModal && (
        <CaseDetailModal
          caseData={selectedCaseModal}
          emails={emails}
          onClose={() => setSelectedCaseModal(null)}
          onSelectEmail={handleSelectEmail}
          onCaseUpdated={(updated) => {
            setCases((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
            setSelectedCaseModal(updated);
          }}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-neutral-900 bg-neutral-950 py-4 text-center text-xs text-neutral-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2 font-mono">
          <div className="flex items-center space-x-2">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            <span className="text-neutral-400">CANNON CREW • AI EMAIL THREAT FORENSICS & INTEL PLATFORM</span>
          </div>
          <div className="text-neutral-500">
            Smart India Hackathon • RFC 5322 Forensics & Graph Intelligence
          </div>
        </div>
      </footer>

    </div>
  );
}
