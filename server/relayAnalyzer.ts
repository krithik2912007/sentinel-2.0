import { RelayHop, OriginCandidate, GeoLocationInfo } from '../src/types';
import { isPrivateIp, lookupIpIntelligence } from './mockGeoDb';

export interface RelayAnalysisResult {
  hops: RelayHop[];
  origin_candidates: OriginCandidate[];
  total_transit_seconds: number;
  anomalies_detected: string[];
}

export function reconstructRelayChain(receivedHeaders: string[]): RelayAnalysisResult {
  if (!receivedHeaders || receivedHeaders.length === 0) {
    return {
      hops: [],
      origin_candidates: [],
      total_transit_seconds: 0,
      anomalies_detected: ['No Received headers found in message. Possible forged or direct injection.'],
    };
  }

  // Received headers in RFC 5322 are stacked top-down (Top = latest recipient MX, Bottom = earliest originating client)
  // Reversing gives chronological order: index 0 is first origin hop, last is destination
  const chronologicalHeaders = [...receivedHeaders].reverse();
  const hops: RelayHop[] = [];
  const anomalies: string[] = [];

  let previousTimestamp: Date | null = null;
  let firstTimestamp: Date | null = null;
  let lastTimestamp: Date | null = null;

  chronologicalHeaders.forEach((rawHeader, idx) => {
    const hopNumber = idx + 1;
    const hopAnomalies: string[] = [];

    // Parse 'from ...'
    const fromMatch = rawHeader.match(/from\s+([^\s;]+(?:\s+\([^\)]+\))?)/i);
    let sourceHost = fromMatch ? fromMatch[1].trim() : 'Unknown Source';

    // Parse 'by ...'
    const byMatch = rawHeader.match(/by\s+([^\s;]+)/i);
    let destHost = byMatch ? byMatch[1].trim() : 'Unknown MTA';

    // Extract IP inside the 'from' segment or header
    const ipMatch = rawHeader.match(/\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]/) ||
      rawHeader.match(/\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/);

    const ipAddress = ipMatch ? ipMatch[1] : '';

    // Parse 'with ...' protocol
    const withMatch = rawHeader.match(/with\s+([A-Z0-9_-]+)/i);
    const protocol = withMatch ? withMatch[1].toUpperCase() : 'SMTP';

    // Parse encryption info (TLS / cipher)
    let encryption = undefined;
    if (/using\s+TLS|with\s+ESMTPS|version=TLS|TLSv1/i.test(rawHeader)) {
      const tlsMatch = rawHeader.match(/version=(TLSv[0-9\.]+).*cipher=([^\s;]+)/i) ||
        rawHeader.match(/(TLSv[0-9\.]+)/i);
      encryption = tlsMatch ? `TLS (${tlsMatch[1] || 'TLSv1.3'})` : 'ESMTPS (Encrypted)';
    } else if (protocol === 'ESMTPA' || protocol === 'SMTP') {
      encryption = 'Cleartext (Unencrypted)';
      if (hopNumber > 1) {
        hopAnomalies.push('Unencrypted relay hop detected between MTAs');
      }
    }

    // Parse timestamp (after the semicolon ';')
    const semiIdx = rawHeader.lastIndexOf(';');
    let hopDate: Date | null = null;
    let delaySeconds = 0;

    if (semiIdx !== -1) {
      const dateStr = rawHeader.slice(semiIdx + 1).trim();
      const parsedDate = new Date(dateStr);
      if (!isNaN(parsedDate.getTime())) {
        hopDate = parsedDate;
        if (!firstTimestamp) firstTimestamp = hopDate;
        lastTimestamp = hopDate;

        if (previousTimestamp) {
          const diffMs = hopDate.getTime() - previousTimestamp.getTime();
          delaySeconds = Math.round(diffMs / 1000);
          if (delaySeconds < -30) {
            hopAnomalies.push(`Time paradox: timestamp is ${Math.abs(delaySeconds)}s earlier than previous hop`);
            anomalies.push(`Hop #${hopNumber} exhibits negative relay transit time (${delaySeconds}s)`);
          }
        }
        previousTimestamp = hopDate;
      }
    }

    const isPrivate = isPrivateIp(ipAddress);
    const geoInfo: GeoLocationInfo | undefined = ipAddress ? lookupIpIntelligence(ipAddress) : undefined;

    // Calculate hop confidence
    let confidence = 95;
    if (!ipAddress) confidence -= 30;
    if (hopAnomalies.length > 0) confidence -= 25;
    if (!hopDate) confidence -= 15;
    confidence = Math.max(15, Math.min(100, confidence));

    hops.push({
      sequence: hopNumber,
      source_host: sourceHost,
      destination_host: destHost,
      ip_address: ipAddress || 'Unknown / Hidden',
      timestamp: hopDate ? hopDate.toISOString() : new Date().toISOString(),
      delay_seconds: delaySeconds >= 0 ? delaySeconds : 0,
      protocol,
      encryption,
      confidence,
      is_private: isPrivate,
      is_origin_candidate: hopNumber === 1 || (!isPrivate && hops.filter((h) => !h.is_private).length === 0),
      raw_header: rawHeader,
      geo: geoInfo,
      anomalies: hopAnomalies,
    });
  });

  // Calculate total transit time
  let totalTransit = 0;
  if (firstTimestamp && lastTimestamp) {
    totalTransit = Math.max(0, Math.round((lastTimestamp.getTime() - firstTimestamp.getTime()) / 1000));
  }

  // Origin Candidate Evaluation
  const originCandidates: OriginCandidate[] = [];

  // Filter hops that contain valid public or observable origin IPs
  const candidateHops = hops.filter((h) => h.ip_address && h.ip_address !== 'Unknown / Hidden');

  candidateHops.forEach((hop, i) => {
    const isFirstPublic = !hop.is_private && candidateHops.findIndex((x) => !x.is_private) === i;
    const isFirstOverall = hop.sequence === 1;

    let score = 50;
    let limitations = '';

    if (hop.is_private) {
      score = 30;
      limitations = 'Private LAN IP (RFC 1918) inside internal corporate network; not directly routable on public Internet.';
    } else if (isFirstPublic) {
      score = 88;
      limitations = 'First externally observed public MTA in Received chain. Highly probable injection point or mail submitter.';
    } else if (isFirstOverall) {
      score = 75;
      limitations = 'Initial hop recorded by transmitting client. Could be forged if first receiving MTA is untrusted.';
    } else {
      score = Math.max(20, 80 - (hop.sequence * 15));
      limitations = 'Intermediate relay / CDN / Email Gateway. Represents forwarding infrastructure rather than true sender.';
    }

    if (hop.geo?.is_vpn_tor_proxy) {
      score -= 20;
      limitations += ` [WARNING: ${hop.geo.proxy_type || 'VPN/Proxy'} detected - physical attribution obscured]`;
    }

    originCandidates.push({
      ip_address: hop.ip_address,
      hostname: hop.source_host,
      hop_number: hop.sequence,
      reliability_score: score,
      evidence_source: `Received Header Hop #${hop.sequence} (${hop.protocol})`,
      infrastructure_info: hop.geo ? `${hop.geo.isp} (${hop.geo.asn}), ${hop.geo.city}, ${hop.geo.country}` : 'Unknown Network',
      is_vpn_proxy: !!hop.geo?.is_vpn_tor_proxy,
      limitations,
      geo: hop.geo,
    });
  });

  // Sort candidates by reliability score descending
  originCandidates.sort((a, b) => b.reliability_score - a.reliability_score);

  return {
    hops,
    origin_candidates: originCandidates,
    total_transit_seconds: totalTransit,
    anomalies_detected: anomalies,
  };
}
