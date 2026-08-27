import { intelligenceCacheRepository } from '../db/repositories/intelligenceCacheRepository';
import { virusTotalProvider } from './virusTotalProvider';
import { abuseIpdbProvider } from './abuseIpdbProvider';
import { ipqsProvider } from './ipqsProvider';
import { dnsProvider } from './dnsProvider';
import { whoisProvider } from './whoisProvider';
import { geoProvider } from './geoProvider';
import { IntelligenceResult, DnsIntelligence, WhoisIntelligence } from './types';
import { GeoLocationInfo } from '../../src/types';

export class IntelligenceProviderManager {
  async enrichIp(ip: string): Promise<{
    geo: GeoLocationInfo;
    abuse?: IntelligenceResult;
    ipqs?: IntelligenceResult;
  }> {
    const cleanIp = ip.trim();

    // 1. Resolve Geo
    const geoRes = await geoProvider.resolveIp(cleanIp);
    const geo = geoRes.geo;

    // 2. Check AbuseIPDB Cache or Query
    let abuseResult: IntelligenceResult | undefined;
    const abuseCacheKey = `AbuseIPDB:IP:${cleanIp}`;
    let cachedAbuse = null;
    try {
      cachedAbuse = await intelligenceCacheRepository.get(abuseCacheKey);
    } catch (e: any) {
      console.warn(`[Cache Error] Failed to read ${abuseCacheKey}:`, e.message);
    }

    if (cachedAbuse) {
      abuseResult = cachedAbuse.response_json;
    } else {
      abuseResult = await abuseIpdbProvider.lookupIp(cleanIp);
      if (abuseResult.status === 'LIVE') {
        try {
          await intelligenceCacheRepository.set('AbuseIPDB', 'IP', cleanIp, abuseResult);
        } catch (e: any) {
          console.warn(`[Cache Error] Failed to persist ${abuseCacheKey}:`, e.message);
        }
      }
    }

    // 3. Check IPQS Cache or Query
    let ipqsResult: IntelligenceResult | undefined;
    const ipqsCacheKey = `IPQualityScore:IP:${cleanIp}`;
    let cachedIpqs = null;
    try {
      cachedIpqs = await intelligenceCacheRepository.get(ipqsCacheKey);
    } catch (e: any) {
      console.warn(`[Cache Error] Failed to read ${ipqsCacheKey}:`, e.message);
    }

    if (cachedIpqs) {
      ipqsResult = cachedIpqs.response_json;
    } else {
      ipqsResult = await ipqsProvider.lookupIp(cleanIp);
      if (ipqsResult.status === 'LIVE') {
        try {
          await intelligenceCacheRepository.set('IPQualityScore', 'IP', cleanIp, ipqsResult);
        } catch (e: any) {
          console.warn(`[Cache Error] Failed to persist ${ipqsCacheKey}:`, e.message);
        }
      }
    }

    // Merge high-confidence threat data into Geo object if found
    if (abuseResult?.reputation === 'MALICIOUS' || ipqsResult?.reputation === 'MALICIOUS') {
      geo.threat_reputation = 'MALICIOUS';
    } else if (abuseResult?.reputation === 'SUSPICIOUS' || ipqsResult?.reputation === 'SUSPICIOUS') {
      if (geo.threat_reputation !== 'MALICIOUS') geo.threat_reputation = 'SUSPICIOUS';
    }

    if (ipqsResult?.data?.tor || ipqsResult?.data?.vpn || ipqsResult?.data?.proxy) {
      geo.is_vpn_tor_proxy = true;
      geo.proxy_type = ipqsResult.data.tor ? 'Tor Exit Node' : ipqsResult.data.vpn ? 'VPN Tunnel' : 'Proxy';
    }

    return { geo, abuse: abuseResult, ipqs: ipqsResult };
  }

  async enrichDomain(domain: string): Promise<{
    vt?: IntelligenceResult;
    dns?: DnsIntelligence;
    whois?: WhoisIntelligence;
  }> {
    const cleanDomain = domain.toLowerCase().trim();

    // 1. DNS Resolution
    const dns = await dnsProvider.lookupDomain(cleanDomain);

    // 2. VirusTotal Domain Check with Cache
    let vt: IntelligenceResult | undefined;
    const vtCacheKey = `VirusTotal:DOMAIN:${cleanDomain}`;
    let cachedVt = null;
    try {
      cachedVt = await intelligenceCacheRepository.get(vtCacheKey);
    } catch (e: any) {
      console.warn(`[Cache Error] Failed to read ${vtCacheKey}:`, e.message);
    }

    if (cachedVt) {
      vt = cachedVt.response_json;
    } else {
      vt = await virusTotalProvider.lookupDomain(cleanDomain);
      if (vt.status === 'LIVE') {
        try {
          await intelligenceCacheRepository.set('VirusTotal', 'DOMAIN', cleanDomain, vt);
        } catch (e: any) {
          console.warn(`[Cache Error] Failed to persist ${vtCacheKey}:`, e.message);
        }
      }
    }

    // 3. WHOIS Check with Cache
    let whois: WhoisIntelligence | undefined;
    const whoisCacheKey = `WhoisXMLAPI:DOMAIN:${cleanDomain}`;
    let cachedWhois = null;
    try {
      cachedWhois = await intelligenceCacheRepository.get(whoisCacheKey);
    } catch (e: any) {
      console.warn(`[Cache Error] Failed to read ${whoisCacheKey}:`, e.message);
    }

    if (cachedWhois) {
      whois = cachedWhois.response_json;
    } else {
      whois = await whoisProvider.lookupDomain(cleanDomain);
      if (whois.status === 'LIVE') {
        try {
          await intelligenceCacheRepository.set('WhoisXMLAPI', 'DOMAIN', cleanDomain, whois);
        } catch (e: any) {
          console.warn(`[Cache Error] Failed to persist ${whoisCacheKey}:`, e.message);
        }
      }
    }

    return { vt, dns, whois };
  }

  async enrichHash(sha256: string): Promise<IntelligenceResult> {
    const cleanHash = sha256.toLowerCase().trim();
    const cacheKey = `VirusTotal:HASH:${cleanHash}`;
    let cached = null;
    try {
      cached = await intelligenceCacheRepository.get(cacheKey);
    } catch (e: any) {
      console.warn(`[Cache Error] Failed to read ${cacheKey}:`, e.message);
    }

    if (cached) {
      return cached.response_json;
    }

    const res = await virusTotalProvider.lookupHash(cleanHash);
    if (res.status === 'LIVE') {
      try {
        await intelligenceCacheRepository.set('VirusTotal', 'HASH', cleanHash, res);
      } catch (e: any) {
        console.warn(`[Cache Error] Failed to persist ${cacheKey}:`, e.message);
      }
    }
    return res;
  }

  async enrichUrl(url: string): Promise<{
    vt?: IntelligenceResult;
    ipqs?: IntelligenceResult;
  }> {
    const cleanUrl = url.trim();

    // 1. VirusTotal URL check with cache
    let vt: IntelligenceResult | undefined;
    const vtCacheKey = `VirusTotal:URL:${cleanUrl}`;
    let cachedVt = null;
    try {
      cachedVt = await intelligenceCacheRepository.get(vtCacheKey);
    } catch (e: any) {
      console.warn(`[Cache Error] Failed to read ${vtCacheKey}:`, e.message);
    }

    if (cachedVt) {
      vt = cachedVt.response_json;
    } else {
      vt = await virusTotalProvider.lookupUrl(cleanUrl);
      if (vt.status === 'LIVE') {
        try {
          await intelligenceCacheRepository.set('VirusTotal', 'URL', cleanUrl, vt);
        } catch (e: any) {
          console.warn(`[Cache Error] Failed to persist ${vtCacheKey}:`, e.message);
        }
      }
    }

    // 2. IPQS URL check with cache
    let ipqs: IntelligenceResult | undefined;
    const ipqsCacheKey = `IPQualityScore:URL:${cleanUrl}`;
    let cachedIpqs = null;
    try {
      cachedIpqs = await intelligenceCacheRepository.get(ipqsCacheKey);
    } catch (e: any) {
      console.warn(`[Cache Error] Failed to read ${ipqsCacheKey}:`, e.message);
    }

    if (cachedIpqs) {
      ipqs = cachedIpqs.response_json;
    } else {
      ipqs = await ipqsProvider.lookupUrl(cleanUrl);
      if (ipqs.status === 'LIVE') {
        try {
          await intelligenceCacheRepository.set('IPQualityScore', 'URL', cleanUrl, ipqs);
        } catch (e: any) {
          console.warn(`[Cache Error] Failed to persist ${ipqsCacheKey}:`, e.message);
        }
      }
    }

    return { vt, ipqs };
  }

  async lookupIndicator(type: 'IP' | 'DOMAIN' | 'HASH' | 'URL', indicator: string): Promise<Record<string, any>> {
    const clean = indicator.trim();
    switch (type) {
      case 'IP':
        return await this.enrichIp(clean);
      case 'DOMAIN':
        return await this.enrichDomain(clean);
      case 'HASH':
        return { vt: await this.enrichHash(clean) };
      case 'URL':
        return await this.enrichUrl(clean);
      default:
        throw new Error(`Unsupported indicator type: ${type}`);
    }
  }

  getProviderStatuses(): Record<string, { configured: boolean; status: string; details?: string; capabilities?: string[] }> {
    return {
      virustotal: {
        configured: virusTotalProvider.isConfigured(),
        status: virusTotalProvider.isConfigured() ? 'CONFIGURED' : 'NOT_CONFIGURED',
        details: virusTotalProvider.isConfigured() ? 'Real v3 API active' : 'Awaiting VIRUSTOTAL_API_KEY',
        capabilities: ['HASH_SCAN', 'DOMAIN_REPUTATION', 'URL_SCAN'],
      },
      abuseipdb: {
        configured: abuseIpdbProvider.isConfigured(),
        status: abuseIpdbProvider.isConfigured() ? 'CONFIGURED' : 'NOT_CONFIGURED',
        details: abuseIpdbProvider.isConfigured() ? 'Real v2 API active' : 'Awaiting ABUSEIPDB_API_KEY',
        capabilities: ['IP_REPUTATION', 'CONFIDENCE_SCORE', 'REPORT_COUNT'],
      },
      ipqs: {
        configured: ipqsProvider.isConfigured(),
        status: ipqsProvider.isConfigured() ? 'CONFIGURED' : 'NOT_CONFIGURED',
        details: ipqsProvider.isConfigured() ? 'Real IPQS JSON API active' : 'Awaiting IPQS_API_KEY',
        capabilities: ['PROXY_DETECTION', 'VPN_DETECTION', 'TOR_DETECTION', 'FRAUD_SCORE', 'MALICIOUS_URL'],
      },
      whois: {
        configured: whoisProvider.isConfigured(),
        status: whoisProvider.isConfigured() ? 'CONFIGURED' : 'NOT_CONFIGURED',
        details: whoisProvider.isConfigured() ? 'WhoisXMLAPI active' : 'Awaiting WHOIS_API_KEY',
        capabilities: ['REGISTRAR_LOOKUP', 'DOMAIN_AGE', 'NAMESERVERS', 'EXPIRATION_DATE'],
      },
      dns: {
        configured: true,
        status: 'LIVE_NATIVE',
        details: 'Node.js async DNS resolver active',
        capabilities: ['A_RECORDS', 'AAAA_RECORDS', 'MX_RECORDS', 'TXT_SPF', 'DMARC_RECORD', 'NS_RECORDS'],
      },
      geoip: {
        configured: Boolean(process.env.IPINFO_TOKEN),
        status: process.env.IPINFO_TOKEN ? 'LIVE_IPINFO' : 'SIMULATION_SOC_DB',
        details: process.env.IPINFO_TOKEN ? 'Real IPinfo.io token active' : 'Deterministic SOC Threat Geo DB active',
        capabilities: ['GEOLOCATION', 'ASN_LOOKUP', 'ISP_IDENTIFICATION'],
      },
      gemini: {
        configured: Boolean(process.env.GEMINI_API_KEY),
        status: process.env.GEMINI_API_KEY ? 'CONFIGURED' : 'DETERMINISTIC_FALLBACK',
        details: process.env.GEMINI_API_KEY ? 'Gemini 2.5 Flash active' : 'Deterministic Forensic NLP active',
        capabilities: ['REASONING_SYNTHESIS', 'ADVERSARIAL_INTENT_EVALUATION'],
      },
    };
  }
}

export const intelligenceManager = new IntelligenceProviderManager();
