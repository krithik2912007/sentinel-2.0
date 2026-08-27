import React, { useState } from 'react';
import { AuditEvent } from '../types';
import {
  FileText,
  Search,
  Download,
  Filter,
  Shield,
  Clock,
  UserCheck,
} from 'lucide-react';

interface AuditLogViewProps {
  logs: AuditEvent[];
}

export const AuditLogView: React.FC<AuditLogViewProps> = ({ logs }) => {
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [filterType, setFilterType] = useState<string>('ALL');

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.details.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.user_email.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.target_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType === 'ALL' || log.target_type === filterType;
    return matchesSearch && matchesType;
  });

  const exportLogsAsJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(logs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `soc-audit-trail-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <FileText className="h-6 w-6 text-indigo-400" />
            Security & Compliance Audit Trail
          </h1>
          <p className="text-sm text-neutral-400 mt-1">
            Immutable cryptographic activity records for evidence handling, forensic analysis, and access events.
          </p>
        </div>

        <button
          onClick={exportLogsAsJson}
          className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 border border-neutral-700 text-xs font-semibold self-start sm:self-auto transition-colors cursor-pointer"
        >
          <Download className="h-4 w-4" />
          <span>Export Audit Log (JSON)</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="h-4 w-4 text-neutral-500 absolute left-3 top-3" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search action, user, or details..."
            className="w-full bg-neutral-950 border border-neutral-800 rounded-lg pl-9 pr-3 py-2 text-xs text-neutral-200 focus:outline-none focus:border-indigo-500/50"
          />
        </div>

        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-neutral-300 focus:outline-none w-full sm:w-auto"
        >
          <option value="ALL">All Event Targets</option>
          <option value="EMAIL">Email Events</option>
          <option value="CASE">Case Events</option>
          <option value="REPORT">Report Access</option>
          <option value="AUTH">Authentication / RBAC</option>
          <option value="CONFIG">Configuration</option>
        </select>
      </div>

      {/* Audit Log Table */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-neutral-950 text-neutral-400 uppercase text-[10px] border-b border-neutral-800">
              <tr>
                <th className="p-3.5">Timestamp (UTC)</th>
                <th className="p-3.5">Action</th>
                <th className="p-3.5">Target</th>
                <th className="p-3.5">Actor & Role</th>
                <th className="p-3.5">Details</th>
                <th className="p-3.5 text-right">Terminal IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800/80">
              {filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-neutral-800/40 transition-colors">
                  <td className="p-3.5 text-neutral-400 whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td className="p-3.5">
                    <span className="px-2 py-0.5 rounded bg-neutral-800 text-indigo-400 font-bold text-[10px]">
                      {log.action}
                    </span>
                  </td>
                  <td className="p-3.5 text-neutral-300">
                    <span className="text-neutral-500">{log.target_type}:</span> {log.target_id.slice(0, 15)}
                  </td>
                  <td className="p-3.5">
                    <span className="text-neutral-200 font-sans font-medium">{log.user_email}</span>
                    <span className="ml-1.5 px-1.5 py-0.2 rounded text-[9px] bg-neutral-800 text-neutral-400">
                      {log.user_role}
                    </span>
                  </td>
                  <td className="p-3.5 text-neutral-300 font-sans max-w-md truncate">
                    {log.details}
                  </td>
                  <td className="p-3.5 text-right text-neutral-500 font-mono">
                    {log.ip_address}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredLogs.length === 0 && (
          <div className="p-10 text-center text-neutral-500 text-sm">
            No audit log records match the search filter.
          </div>
        )}
      </div>

    </div>
  );
};
