import React from 'react';
import { AnalyzedEmail, RelayHop, OriginCandidate } from '../types';
import { LeafletRelayMap } from './LeafletRelayMap';
import { Globe2, ShieldAlert, Radio } from 'lucide-react';

interface GlobalRelayMapViewProps {
  emails: AnalyzedEmail[];
  onSelectEmail: (email: AnalyzedEmail) => void;
}

export const GlobalRelayMapView: React.FC<GlobalRelayMapViewProps> = ({
  emails,
  onSelectEmail,
}) => {
  // Aggregate all relay hops across all emails
  const allHops: RelayHop[] = [];
  const allOriginCandidates: OriginCandidate[] = [];

  emails.forEach((e) => {
    if (e.relay_hops) allHops.push(...e.relay_hops);
    if (e.origin_candidates) allOriginCandidates.push(...e.origin_candidates);
  });

  return (
    <div className="space-y-6">
      
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Globe2 className="h-6 w-6 text-indigo-400" />
            Global Threat Infrastructure & Relay Geolocation
          </h1>
          <p className="text-sm text-neutral-400 mt-1">
            Aggregated global view of all detected Mail Transfer Agents (MTAs), bulletproof hostings, Tor exit relays, and intermediate hops.
          </p>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono bg-neutral-900 px-3 py-1.5 rounded-lg border border-neutral-800 text-indigo-300">
          <Radio className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
          <span>{allHops.length} Tracked Infrastructure Hops</span>
        </div>
      </div>

      {/* Interactive Map */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5">
        <LeafletRelayMap
          relayHops={allHops}
          originCandidates={allOriginCandidates}
        />
      </div>

      {/* Global Ingested Stream */}
      <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 space-y-3">
        <h3 className="text-sm font-semibold text-white">Investigated Mail Streams on Map</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
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
                  {e.classification} ({e.risk_score}/100)
                </span>
                <span className="text-neutral-500 font-mono">{e.relay_hops?.length || 0} hops</span>
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
