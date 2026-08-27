import React from 'react';
import { AnalyzedEmail, CorrelationGraphData, GraphLink, GraphNode } from '../types';
import { CorrelationGraphCanvas } from './CorrelationGraphCanvas';
import { Share2, Radio, Layers } from 'lucide-react';

interface GlobalThreatGraphViewProps {
  emails: AnalyzedEmail[];
  onSelectEmail: (email: AnalyzedEmail) => void;
}

export const GlobalThreatGraphView: React.FC<GlobalThreatGraphViewProps> = ({
  emails,
  onSelectEmail,
}) => {
  // Aggregate graph data across all emails into a unified multi-case campaign graph
  const nodeMap = new Map<string, GraphNode>();
  const links: GraphLink[] = [];

  emails.forEach((email) => {
    if (email.graph_data?.nodes) {
      email.graph_data.nodes.forEach((node) => {
        if (!nodeMap.has(node.id)) {
          nodeMap.set(node.id, node);
        }
      });
    }
    if (email.graph_data?.links) {
      links.push(...email.graph_data.links);
    }
  });

  const combinedGraph: CorrelationGraphData = {
    nodes: Array.from(nodeMap.values()),
    links,
    campaign_name: 'Aggregated Threat & Infrastructure Knowledge Graph',
    related_cases_count: emails.length,
  };

  return (
    <div className="space-y-6">
      
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Share2 className="h-6 w-6 text-indigo-400" />
            Global Threat Actor & Infrastructure Knowledge Graph
          </h1>
          <p className="text-sm text-neutral-400 mt-1">
            Correlates active threat actors, lookalike domains, Tor relays, ASNs, payload hashes, and campaign clusters.
          </p>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="bg-neutral-900 px-3 py-1.5 rounded-lg border border-neutral-800 text-indigo-300">
            {nodeMap.size} Correlated Nodes
          </span>
          <span className="bg-neutral-900 px-3 py-1.5 rounded-lg border border-neutral-800 text-neutral-300">
            {links.length} Relations
          </span>
        </div>
      </div>

      {/* Interactive Graph Canvas */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5">
        <CorrelationGraphCanvas data={combinedGraph} />
      </div>

      {/* Connected Threat Clusters */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-3">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Layers className="h-4 w-4 text-indigo-400" />
          Active Incident Clusters in Knowledge Graph
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {emails.map((e) => (
            <div
              key={e.id}
              onClick={() => onSelectEmail(e)}
              className="bg-neutral-950 p-3 rounded-lg border border-neutral-800 hover:border-indigo-500/50 cursor-pointer transition-colors space-y-1"
            >
              <div className="flex items-center justify-between text-[11px]">
                <span className={`px-1.5 py-0.2 rounded font-mono font-bold ${
                  e.risk_score >= 80 ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'
                }`}>
                  {e.classification}
                </span>
                <span className="text-neutral-500 font-mono">Score: {e.risk_score}/100</span>
              </div>
              <div className="text-xs font-semibold text-white truncate">{e.subject}</div>
              <div className="text-[11px] text-neutral-400 font-mono truncate">{e.sender_email}</div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
};
