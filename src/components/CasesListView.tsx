import React, { useState } from 'react';
import {
  Layers,
  Search,
  Filter,
  Plus,
  Clock,
  AlertTriangle,
  ChevronRight,
  Shield,
  MessageSquare,
  FileText,
  User,
} from 'lucide-react';
import { CasePriority, CaseRecord, CaseStatus } from '../types';

interface CasesListViewProps {
  cases: CaseRecord[];
  onSelectCase: (caseRecord: CaseRecord) => void;
  onCreateCase: (data: { title: string; description: string; priority: string; tags?: string[] }) => void;
}

export const CasesListView: React.FC<CasesListViewProps> = ({
  cases,
  onSelectCase,
  onCreateCase,
}) => {
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [isCreateModalOpen, setIsCreateModalOpen] = useState<boolean>(false);

  // New Case form state
  const [newTitle, setNewTitle] = useState<string>('');
  const [newDesc, setNewDesc] = useState<string>('');
  const [newPriority, setNewPriority] = useState<CasePriority>('HIGH');
  const [newTags, setNewTags] = useState<string>('Email Forensics, Phishing');

  const filteredCases = cases.filter((c) => {
    const matchesSearch =
      c.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.case_number.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || c.status === statusFilter;
    const matchesPriority = priorityFilter === 'ALL' || c.priority === priorityFilter;
    return matchesSearch && matchesStatus && matchesPriority;
  });

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    onCreateCase({
      title: newTitle,
      description: newDesc,
      priority: newPriority,
      tags: newTags.split(',').map((t) => t.trim()).filter(Boolean),
    });
    setNewTitle('');
    setNewDesc('');
    setIsCreateModalOpen(false);
  };

  const getPriorityStyle = (priority: CasePriority) => {
    switch (priority) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30';
      default:
        return 'bg-neutral-800 text-neutral-300 border-neutral-700';
    }
  };

  const getStatusStyle = (status: CaseStatus) => {
    switch (status) {
      case 'INVESTIGATING':
        return 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30';
      case 'OPEN':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      case 'RESOLVED':
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
      default:
        return 'bg-neutral-800 text-neutral-400 border-neutral-700';
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Top Header & Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Layers className="h-6 w-6 text-indigo-400" />
            Active Investigation Case Files
          </h1>
          <p className="text-sm text-neutral-400 mt-1">
            Manage forensic incident response dossiers, associated evidence streams, and case triage notes.
          </p>
        </div>

        <button
          id="open-create-case-btn"
          onClick={() => setIsCreateModalOpen(true)}
          className="flex items-center space-x-2 px-4 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-sm transition-all shadow-lg shadow-indigo-600/20 self-start sm:self-auto cursor-pointer"
        >
          <Plus className="h-4 w-4" />
          <span>New Investigation Case</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-80">
          <Search className="h-4 w-4 text-neutral-500 absolute left-3 top-3" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search case #, title, or keywords..."
            className="w-full bg-neutral-950 border border-neutral-800 rounded-lg pl-9 pr-3 py-2 text-xs text-neutral-200 placeholder:text-neutral-500 focus:outline-none focus:border-indigo-500/50"
          />
        </div>

        <div className="flex items-center space-x-2 w-full md:w-auto overflow-x-auto">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-neutral-300 focus:outline-none"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
            <option value="CLOSED">Closed</option>
          </select>

          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-neutral-300 focus:outline-none"
          >
            <option value="ALL">All Priorities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Cases List */}
      <div className="space-y-3">
        {filteredCases.map((c) => (
          <div
            key={c.id}
            id={`case-card-${c.id}`}
            onClick={() => onSelectCase(c)}
            className="bg-neutral-900 border border-neutral-800 hover:border-neutral-700 rounded-xl p-5 cursor-pointer transition-all hover:shadow-lg group flex flex-col md:flex-row md:items-center justify-between gap-4"
          >
            <div className="space-y-2 flex-1">
              <div className="flex items-center space-x-2.5 flex-wrap">
                <span className="text-xs font-bold font-mono text-indigo-400 bg-neutral-950 px-2 py-0.5 rounded border border-neutral-800">
                  {c.case_number}
                </span>
                <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border uppercase ${getStatusStyle(c.status)}`}>
                  {c.status}
                </span>
                <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border uppercase ${getPriorityStyle(c.priority)}`}>
                  {c.priority} Priority
                </span>
              </div>

              <h3 className="text-base font-semibold text-white group-hover:text-indigo-300 transition-colors">
                {c.title}
              </h3>
              <p className="text-xs text-neutral-400 line-clamp-2">{c.description}</p>

              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-neutral-500 pt-1">
                <span className="flex items-center gap-1">
                  <User className="h-3 w-3" /> Lead: <strong className="text-neutral-400">{c.created_by_name}</strong>
                </span>
                <span>•</span>
                <span className="flex items-center gap-1">
                  <FileText className="h-3 w-3" /> {c.email_ids?.length || 0} Ingested Emails
                </span>
                <span>•</span>
                <span className="flex items-center gap-1">
                  <MessageSquare className="h-3 w-3" /> {c.notes?.length || 0} Analyst Notes
                </span>
                <span>•</span>
                <span>Updated: {new Date(c.updated_at).toLocaleDateString()}</span>
              </div>
            </div>

            <div className="flex items-center space-x-3 shrink-0 self-end md:self-auto">
              <span className="text-xs text-indigo-400 font-medium hidden sm:inline">Inspect Dossier</span>
              <ChevronRight className="h-5 w-5 text-neutral-600 group-hover:text-indigo-400 transition-transform group-hover:translate-x-1" />
            </div>
          </div>
        ))}

        {filteredCases.length === 0 && (
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-12 text-center text-neutral-500 text-sm">
            No matching investigation case files found.
          </div>
        )}
      </div>

      {/* Create Case Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 bg-neutral-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-neutral-900 border border-neutral-800 rounded-2xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Layers className="h-5 w-5 text-indigo-400" />
              Open New Investigation Dossier
            </h3>

            <form onSubmit={handleCreateSubmit} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-neutral-400 mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Incident: Phishing Attack Campaign against Execs"
                  className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500/50"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-neutral-400 mb-1">Description & Scope</label>
                <textarea
                  rows={3}
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Describe initial detection vectors, affected departments, and goals..."
                  className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500/50"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-neutral-400 mb-1">Triage Priority</label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value as CasePriority)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-neutral-300 focus:outline-none"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-neutral-400 mb-1">Tags (Comma-separated)</label>
                  <input
                    type="text"
                    value={newTags}
                    onChange={(e) => setNewTags(e.target.value)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end space-x-3 pt-3 border-t border-neutral-800">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 rounded-lg text-xs font-semibold text-neutral-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-lg cursor-pointer"
                >
                  Create Case File
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
};
