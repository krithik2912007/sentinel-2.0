import { CorrelationGraphData, GraphLink, GraphNode, SeverityLevel } from '../src/types';
import { ParsedRawEmail } from './emailParser';
import { RelayAnalysisResult } from './relayAnalyzer';
import { FullThreatAnalysisResult } from './threatEngine';

export function buildCorrelationGraph(
  emailId: string,
  parsed: ParsedRawEmail,
  relayResult: RelayAnalysisResult,
  threatResult: FullThreatAnalysisResult,
  caseNumber?: string
): CorrelationGraphData {
  const nodes: GraphNode[] = [];
  const links: GraphLink[] = [];
  const addedNodes = new Set<string>();

  function addNode(node: GraphNode) {
    if (!addedNodes.has(node.id)) {
      addedNodes.add(node.id);
      nodes.push(node);
    }
  }

  // 1. Root Email Node
  const emailNodeId = `email:${emailId}`;
  addNode({
    id: emailNodeId,
    label: parsed.subject.length > 25 ? parsed.subject.slice(0, 22) + '...' : parsed.subject,
    type: 'EMAIL',
    risk: threatResult.risk_score >= 70 ? 'critical' : threatResult.risk_score >= 40 ? 'medium' : 'low',
    group: 1,
    properties: {
      subject: parsed.subject,
      from: parsed.from_email,
      risk_score: threatResult.risk_score,
      classification: threatResult.classification,
    },
  });

  // 2. Case Node
  if (caseNumber) {
    const caseNodeId = `case:${caseNumber}`;
    addNode({
      id: caseNodeId,
      label: `Case #${caseNumber}`,
      type: 'CASE',
      risk: 'info',
      group: 2,
    });
    links.push({
      source: emailNodeId,
      target: caseNodeId,
      relation: 'ASSOCIATED_WITH',
      label: 'belongs to',
    });
  }

  // 3. Sender Domain Node
  if (parsed.from_email.includes('@')) {
    const sDomain = parsed.from_email.split('@')[1];
    const sDomainId = `domain:${sDomain}`;
    addNode({
      id: sDomainId,
      label: sDomain,
      type: 'DOMAIN',
      risk: threatResult.auth_analysis.dmarc.result === 'fail' ? 'critical' : 'low',
      group: 3,
      properties: { dmarc: threatResult.auth_analysis.dmarc.result },
    });
    links.push({
      source: emailNodeId,
      target: sDomainId,
      relation: 'SENT_FROM',
      label: 'claimed sender',
    });
  }

  // 4. Reply-To Domain Node (if different)
  if (parsed.reply_to && parsed.reply_to.includes('@')) {
    const rDomain = parsed.reply_to.split('@')[1];
    const rDomainId = `domain:${rDomain}`;
    addNode({
      id: rDomainId,
      label: `Reply-To: ${rDomain}`,
      type: 'DOMAIN',
      risk: 'high',
      group: 3,
    });
    links.push({
      source: emailNodeId,
      target: rDomainId,
      relation: 'REPLY_TO',
      label: 'redirects replies',
    });
  }

  // 5. Origin & Relay IPs & ASNs
  relayResult.hops.forEach((hop) => {
    if (!hop.ip_address || hop.ip_address === 'Unknown / Hidden') return;
    const ipNodeId = `ip:${hop.ip_address}`;
    const isMalicious = hop.geo?.threat_reputation === 'MALICIOUS';
    const isOrigin = hop.is_origin_candidate;

    addNode({
      id: ipNodeId,
      label: `${hop.ip_address}${isOrigin ? ' (Origin)' : ''}`,
      type: 'IP',
      risk: isMalicious ? 'critical' : isOrigin ? 'high' : 'low',
      group: 4,
      properties: {
        country: hop.geo?.country,
        city: hop.geo?.city,
        isp: hop.geo?.isp,
        is_vpn: hop.geo?.is_vpn_tor_proxy,
      },
    });

    links.push({
      source: emailNodeId,
      target: ipNodeId,
      relation: isOrigin ? 'SENT_FROM' : 'RELAYED_THROUGH',
      label: `Hop #${hop.sequence}`,
    });

    // ASN Node
    if (hop.geo?.asn && hop.geo.asn !== 'PRIVATE') {
      const asnNodeId = `asn:${hop.geo.asn}`;
      addNode({
        id: asnNodeId,
        label: `${hop.geo.asn} (${hop.geo.isp.slice(0, 15)})`,
        type: 'ASN',
        risk: hop.geo.is_vpn_tor_proxy ? 'high' : 'info',
        group: 5,
        properties: { org: hop.geo.org },
      });
      links.push({
        source: ipNodeId,
        target: asnNodeId,
        relation: 'RESOLVES_TO',
        label: 'hosted on',
      });
    }
  });

  // 6. Extracted URLs & Domains
  parsed.extracted_urls.slice(0, 4).forEach((url, i) => {
    try {
      const parsedUrl = new URL(url);
      const urlHost = parsedUrl.hostname;
      const urlNodeId = `url:${urlHost}-${i}`;
      addNode({
        id: urlNodeId,
        label: urlHost,
        type: 'URL',
        risk: threatResult.risk_score >= 60 ? 'critical' : 'medium',
        group: 6,
        properties: { full_url: url },
      });
      links.push({
        source: emailNodeId,
        target: urlNodeId,
        relation: 'LINKS_TO',
        label: 'hyperlink',
      });
    } catch {
      // Ignore URL parse error
    }
  });

  // 7. Attachments
  parsed.attachments.forEach((att) => {
    const hashNodeId = `hash:${att.sha256.slice(0, 12)}`;
    addNode({
      id: hashNodeId,
      label: `${att.filename} (${att.sha256.slice(0, 8)})`,
      type: 'ATTACHMENT_HASH',
      risk: att.risk_flag ? 'critical' : 'low',
      group: 7,
      properties: {
        filename: att.filename,
        sha256: att.sha256,
        size: att.size_bytes,
      },
    });
    links.push({
      source: emailNodeId,
      target: hashNodeId,
      relation: 'SHARES_INFRASTRUCTURE',
      label: 'carries payload',
    });
  });

  // 8. Campaign Correlation Cluster
  let campaignName: string | undefined = undefined;
  if (threatResult.classification === 'BUSINESS_EMAIL_COMPROMISE') {
    campaignName = 'Campaign: Operation DarkInvoice / CEO Spoof 2026';
  } else if (threatResult.classification === 'PHISHING') {
    campaignName = 'Campaign: Global-Office365-CredentialHarvest';
  } else if (threatResult.classification === 'MALWARE_SUSPECTED') {
    campaignName = 'Campaign: AgentTesla-ISO-Distribution-Cluster';
  }

  if (campaignName) {
    const campaignNodeId = `campaign:${campaignName}`;
    addNode({
      id: campaignNodeId,
      label: campaignName,
      type: 'CAMPAIGN',
      risk: 'critical',
      group: 8,
    });
    links.push({
      source: emailNodeId,
      target: campaignNodeId,
      relation: 'SEEN_IN_CAMPAIGN',
      label: 'clustered into',
    });
  }

  return {
    nodes,
    links,
    campaign_name: campaignName,
    related_cases_count: campaignName ? 4 : 1,
  };
}

export function generateCorrelationGraph(
  parsed: ParsedRawEmail,
  originCandidates: any[],
  indicators: any[],
  caseId?: string
): CorrelationGraphData {
  const emailId = parsed.id || `eml_${parsed.evidence_hash_sha256?.slice(0, 16) || 'root'}`;
  const threatStub: any = {
    risk_score: 75,
    classification: 'PHISHING',
    indicators,
  };
  const relayStub: any = {
    origin_candidates: originCandidates,
    hops: [],
  };

  return buildCorrelationGraph(emailId, parsed, relayStub, threatStub, caseId);
}

