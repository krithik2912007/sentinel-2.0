import React, { useState, useEffect } from 'react';
import {
  CaseRecord,
  AnalyzedEmail,
  CaseStatus,
  CasePriority,
} from '../types';
import {
  Layers,
  X,
  Plus,
  Clock,
  ShieldAlert,
  FileText,
  MessageSquare,
  CheckCircle2,
  ChevronRight,
} from 'lucide-react';
import { addCaseNote, updateCase } from '../api';

interface CaseDetailModalProps {
  caseData: CaseRecord;
  emails: AnalyzedEmail[];
  onClose: () => void;
  onSelectEmail: (email: AnalyzedEmail) => void;
  onCaseUpdated: (updated: CaseRecord) => void;
}

export const CaseDetailModal: React.FC<CaseDetailModalProps> = ({
  caseData,
  emails,
  onClose,
  onSelectEmail,
  onCaseUpdated,
}) => {
  const [status, setStatus] = useState<CaseStatus>(caseData.status);
  const [priority, setPriority] = useState<CasePriority>(caseData.priority);
  const [noteText, setNoteText] = useState<string>('');
  const [notes, setNotes] = useState(caseData.notes || []);

  const associatedEmails = emails.filter((e) => caseData.email_ids.includes(e.id));

  const handleStatusChange = async (newStatus: CaseStatus) => {
    setStatus(newStatus);
    try {
      const updated = await updateCase(caseData.id, { status: newStatus });
      onCaseUpdated(updated);
    } catch (err) {
      console.error(err);
    }
  };

  const handlePriorityChange = async (newPriority: CasePriority) => {
    setPriority(newPriority);
    try {
      const updated = await updateCase(caseData.id, { priority: newPriority });
      onCaseUpdated(updated);
    } catch (err) {
      console.error(err);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!noteText.trim()) return;

    try {
      const newNote = await addCaseNote(caseData.id, noteText);
      const updatedNotes = [newNote, ...notes];
      setNotes(updatedNotes);
      setNoteText('');
      onCaseUpdated({ ...caseData, notes: updatedNotes });
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-neutral-950/85 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-neutral-900 border border-neutral-800 rounded-2xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        
        {/* Modal Header */}
        <div className="p-6 border-b border-neutral-800 flex items-start justify-between gap-4 bg-neutral-950/50">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold font-mono text-indigo-400 bg-neutral-900 px-2.5 py-0.5 rounded border border-neutral-800">
                {caseData.case_number}
              </span>
              <span className="text-xs text-neutral-500 font-mono">
                Created: {new Date(caseData.created_at).toLocaleString()}
              </span>
            </div>
            <h2 className="text-xl font-bold text-white">{caseData.title}</h2>
            <p className="text-xs text-neutral-400">{caseData.description}</p>
          </div>

          <button
            onClick={onClose}
            className="text-neutral-400 hover:text-white p-1 rounded-lg hover:bg-neutral-800 transition-colors cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          
          {/* Controls Bar */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-neutral-950 p-4 rounded-xl border border-neutral-800">
            <div>
              <label className="block text-xs font-mono text-neutral-400 mb-1">Investigation Status</label>
              <select
                value={status}
                onChange={(e) => handleStatusChange(e.target.value as CaseStatus)}
                className="w-full bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-xs font-bold text-white focus:outline-none"
              >
                <option value="OPEN">OPEN</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="RESOLVED">RESOLVED</option>
                <option value="CLOSED">CLOSED</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-mono text-neutral-400 mb-1">Triage Priority</label>
              <select
                value={priority}
                onChange={(e) => handlePriorityChange(e.target.value as CasePriority)}
                className="w-full bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-xs font-bold text-white focus:outline-none"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
          </div>

          {/* Associated Emails */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FileText className="h-4 w-4 text-indigo-400" />
              Ingested Evidence Streams ({associatedEmails.length})
            </h3>

            <div className="space-y-2">
              {associatedEmails.map((email) => (
                <div
                  key={email.id}
                  onClick={() => {
                    onClose();
                    onSelectEmail(email);
                  }}
                  className="bg-neutral-950 border border-neutral-800 hover:border-neutral-700 rounded-xl p-3.5 flex items-center justify-between cursor-pointer transition-colors group"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded ${
                        email.risk_score >= 80 ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'
                      }`}>
                        {email.classification} ({email.risk_score}/100)
                      </span>
                      <span className="text-xs font-mono text-neutral-400">{email.sender_email}</span>
                    </div>
                    <div className="text-sm font-semibold text-white group-hover:text-indigo-300 transition-colors">
                      {email.subject}
                    </div>
                  </div>

                  <ChevronRight className="h-5 w-5 text-neutral-600 group-hover:text-indigo-400 transition-transform" />
                </div>
              ))}
            </div>
          </div>

          {/* Analyst Case Notes & Audit */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <MessageSquare className="h-4 w-4 text-indigo-400" />
              Analyst Investigation Notes & Chain of Custody
            </h3>

            {/* Note form */}
            <form onSubmit={handleAddNote} className="space-y-2">
              <textarea
                rows={2}
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
                placeholder="Append forensic observation, containment action, or investigator findings..."
                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-indigo-500/50"
              />
              <button
                type="submit"
                disabled={!noteText.trim()}
                className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-md disabled:opacity-50 cursor-pointer"
              >
                + Append Note
              </button>
            </form>

            <div className="space-y-2 pt-2">
              {notes.map((note) => (
                <div key={note.id} className="bg-neutral-950 p-3 rounded-lg border border-neutral-800/80 text-xs space-y-1">
                  <div className="flex items-center justify-between text-neutral-400 font-mono text-[11px]">
                    <span className="text-indigo-400 font-semibold">{note.author} ({note.author_role})</span>
                    <span>{new Date(note.timestamp).toLocaleString()}</span>
                  </div>
                  <p className="text-neutral-200 leading-relaxed">{note.text}</p>
                </div>
              ))}
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};
