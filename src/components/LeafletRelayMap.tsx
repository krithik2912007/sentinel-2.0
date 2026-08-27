import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import { RelayHop, OriginCandidate } from '../types';
import { ShieldAlert, Info, MapPin } from 'lucide-react';

interface LeafletRelayMapProps {
  relayHops: RelayHop[];
  originCandidates: OriginCandidate[];
}

export const LeafletRelayMap: React.FC<LeafletRelayMapProps> = ({
  relayHops,
  originCandidates,
}) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);

  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Destroy existing instance if any
    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    // Default center (Global view)
    const map = L.map(mapContainerRef.current, {
      center: [20, 0],
      zoom: 2,
      minZoom: 1,
      maxZoom: 18,
      zoomControl: true,
      attributionControl: false,
    });

    mapInstanceRef.current = map;

    // Use dark CartoDB tile layer for high-contrast SOC aesthetic
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      maxZoom: 19,
      subdomains: 'abcd',
    }).addTo(map);

    // Filter hops that have valid coordinates (excluding LAN private IPs 0,0)
    const validGeoHops = relayHops.filter(
      (h) => h.geo && (h.geo.latitude !== 0 || h.geo.longitude !== 0) && !h.is_private
    );

    const latLngs: [number, number][] = [];

    // Add Hop Markers
    validGeoHops.forEach((hop) => {
      const geo = hop.geo!;
      const pos: [number, number] = [geo.latitude, geo.longitude];
      latLngs.push(pos);

      const isOrigin = hop.is_origin_candidate;
      const isVpn = geo.is_vpn_tor_proxy;

      const markerColor = isVpn ? '#f43f5e' : isOrigin ? '#f59e0b' : '#818cf8';
      const markerGlow = isVpn
        ? 'rgba(244, 63, 94, 0.6)'
        : isOrigin
        ? 'rgba(245, 158, 11, 0.6)'
        : 'rgba(129, 140, 248, 0.6)';

      const customIcon = L.divIcon({
        className: 'custom-geo-marker',
        html: `
          <div style="
            position: relative;
            width: 28px;
            height: 28px;
            background: #0a0a0a;
            border: 2px solid ${markerColor};
            box-shadow: 0 0 15px ${markerGlow};
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: bold;
            color: ${markerColor};
            font-family: monospace;
          ">
            ${hop.sequence}
          </div>
        `,
        iconSize: [28, 28],
        iconAnchor: [14, 14],
      });

      const popupContent = `
        <div style="font-family: inherit; font-size: 12px; line-height: 1.4; min-width: 200px; background: #171717; color: #e5e5e5; padding: 6px; border-radius: 8px;">
          <div style="font-weight: bold; font-size: 13px; color: ${markerColor}; margin-bottom: 4px; display: flex; align-items: center; justify-content: space-between;">
            <span>Hop #${hop.sequence} ${isOrigin ? '(Probable Origin)' : ''}</span>
            <span style="font-size: 10px; padding: 2px 6px; border-radius: 4px; background: rgba(255,255,255,0.1);">${hop.protocol}</span>
          </div>
          <div style="color: #a3a3a3; font-size: 11px; font-family: monospace; margin-bottom: 6px;">IP: <strong style="color: #f5f5f5;">${hop.ip_address}</strong></div>
          <div style="color: #d4d4d4; margin-bottom: 2px;">📍 <strong>${geo.city}, ${geo.country}</strong></div>
          <div style="color: #a3a3a3; font-size: 11px;">🏢 ISP: ${geo.isp} (${geo.asn})</div>
          ${isVpn ? `<div style="margin-top: 6px; padding: 4px 6px; background: rgba(244,63,94,0.2); border: 1px solid rgba(244,63,94,0.4); border-radius: 4px; color: #fda4af; font-size: 11px;">⚠️ ${geo.proxy_type || 'VPN/Tor Anonymizer'} Detected</div>` : ''}
        </div>
      `;

      L.marker(pos, { icon: customIcon }).bindPopup(popupContent).addTo(map);
    });

    // Draw Polyline Route between Hops
    if (latLngs.length > 1) {
      L.polyline(latLngs, {
        color: '#6366f1',
        weight: 3,
        opacity: 0.8,
        dashArray: '6, 8',
      }).addTo(map);

      // Fit bounds with padding
      map.fitBounds(L.latLngBounds(latLngs), { padding: [40, 40], maxZoom: 10 });
    } else if (latLngs.length === 1) {
      map.setView(latLngs[0], 5);
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [relayHops, originCandidates]);

  return (
    <div className="space-y-3">
      
      {/* Geolocation Legal & Technical Limitation Notice */}
      <div className="bg-neutral-900/90 border border-amber-500/30 rounded-xl p-3.5 flex items-start space-x-3 text-xs text-amber-200/90">
        <Info className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-amber-300">Technical Attribution & Geolocation Standard:</strong> Geolocation coordinates represent observed network infrastructure (Mail Transfer Agents, ASNs, BGP routes) and external routing nodes. It does <em>not</em> prove the physical domicile or identity of any human individual.
        </div>
      </div>

      {/* Map Canvas Frame */}
      <div className="h-[420px] w-full rounded-xl overflow-hidden border border-neutral-800 relative shadow-2xl bg-neutral-950">
        <div ref={mapContainerRef} className="h-full w-full" />
        
        {/* Map Legend Overlay */}
        <div className="absolute bottom-3 right-3 z-[1000] bg-neutral-900/90 backdrop-blur-md border border-neutral-800 rounded-lg p-3 text-[11px] font-mono space-y-1.5 shadow-lg">
          <div className="text-neutral-400 font-sans font-bold text-xs uppercase mb-1">Relay Legend</div>
          <div className="flex items-center space-x-2">
            <span className="h-3 w-3 rounded-full bg-rose-500 border border-rose-300" />
            <span className="text-neutral-300">Tor Exit / Bulletproof Host</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="h-3 w-3 rounded-full bg-amber-500 border border-amber-300" />
            <span className="text-neutral-300">Origin Candidate Node</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="h-3 w-3 rounded-full bg-indigo-400 border border-indigo-200" />
            <span className="text-neutral-300">Intermediary Mail Relay (MTA)</span>
          </div>
        </div>
      </div>

    </div>
  );
};
