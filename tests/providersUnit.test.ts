import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { virusTotalProvider } from '../server/intelligence/virusTotalProvider';
import { abuseIpdbProvider } from '../server/intelligence/abuseIpdbProvider';
import { ipqsProvider } from '../server/intelligence/ipqsProvider';
import { geoProvider } from '../server/intelligence/geoProvider';
import { dnsProvider } from '../server/intelligence/dnsProvider';
import { whoisProvider } from '../server/intelligence/whoisProvider';

describe('External Intelligence Providers Unit Tests', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------
  // 1. VirusTotal Provider
  // -------------------------------------------------------------
  describe('VirusTotal Provider', () => {
    it('returns NOT_CONFIGURED status when VIRUSTOTAL_API_KEY is missing', async () => {
      delete process.env.VIRUSTOTAL_API_KEY;
      const res = await virusTotalProvider.lookupHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      expect(res.status).toBe('NOT_CONFIGURED');
      expect(res.provider).toBe('VirusTotal');
      expect(res.error).toContain('not configured');
    });

    it('parses malicious file hash detection response correctly in LIVE mode', async () => {
      process.env.VIRUSTOTAL_API_KEY = 'mock_vt_secret_api_key_12345';

      const mockVtResponse = {
        data: {
          attributes: {
            meaningful_name: 'trojan_payload.exe',
            type_description: 'Win32 EXE',
            last_analysis_stats: {
              malicious: 48,
              suspicious: 4,
              harmless: 0,
              undetected: 18,
            },
          },
        },
      };

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockVtResponse,
      } as any);

      const res = await virusTotalProvider.lookupHash('a23b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b');
      expect(res.status).toBe('LIVE');
      expect(res.reputation).toBe('MALICIOUS');
      expect(res.data?.malicious).toBe(48);
      expect(res.data?.meaningful_name).toBe('trojan_payload.exe');
      expect(res.confidence).toBeGreaterThan(0.9);
    });

    it('handles 404 clean hash response gracefully', async () => {
      process.env.VIRUSTOTAL_API_KEY = 'mock_vt_secret_api_key_12345';

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      } as any);

      const res = await virusTotalProvider.lookupHash('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
      expect(res.status).toBe('LIVE');
      expect(res.reputation).toBe('CLEAN');
      expect(res.data?.message).toContain('not seen');
    });

    it('handles HTTP 429 rate limits without throwing', async () => {
      process.env.VIRUSTOTAL_API_KEY = 'mock_vt_secret_api_key_12345';

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
      } as any);

      const res = await virusTotalProvider.lookupHash('a23b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b');
      expect(res.status).toBe('ERROR');
      expect(res.error).toContain('rate limit');
    });

    it('handles request timeouts gracefully', async () => {
      process.env.VIRUSTOTAL_API_KEY = 'mock_vt_secret_api_key_12345';

      const timeoutError = new Error('The operation was aborted');
      timeoutError.name = 'TimeoutError';
      global.fetch = vi.fn().mockRejectedValueOnce(timeoutError);

      const res = await virusTotalProvider.lookupDomain('suspicious-login.com');
      expect(res.status).toBe('ERROR');
      expect(res.error).toContain('timed out');
    });

    it('encodes and queries URL indicators in VirusTotal format', async () => {
      process.env.VIRUSTOTAL_API_KEY = 'mock_vt_secret_api_key_12345';

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            attributes: {
              last_analysis_stats: { malicious: 12, suspicious: 2, harmless: 10 },
            },
          },
        }),
      } as any);

      const res = await virusTotalProvider.lookupUrl('http://phishing-portal.com/login?token=abc');
      expect(res.status).toBe('LIVE');
      expect(res.reputation).toBe('MALICIOUS');
      expect(global.fetch).toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------
  // 2. AbuseIPDB Provider
  // -------------------------------------------------------------
  describe('AbuseIPDB Provider', () => {
    it('bypasses external API for private RFC 1918 addresses and returns CLEAN LIVE', async () => {
      const fetchSpy = vi.fn();
      global.fetch = fetchSpy;

      const res = await abuseIpdbProvider.lookupIp('192.168.1.1');
      expect(res.status).toBe('LIVE');
      expect(res.reputation).toBe('CLEAN');
      expect(res.data?.isPublic).toBe(false);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('returns NOT_CONFIGURED status when ABUSEIPDB_API_KEY is absent', async () => {
      delete process.env.ABUSEIPDB_API_KEY;
      const res = await abuseIpdbProvider.lookupIp('185.220.101.5');
      expect(res.status).toBe('NOT_CONFIGURED');
      expect(res.error).toContain('not configured');
    });

    it('parses high abuse confidence scores and threat reports correctly', async () => {
      process.env.ABUSEIPDB_API_KEY = 'mock_abuse_ipdb_key_998877';

      const mockResponse = {
        data: {
          ipAddress: '185.220.101.5',
          isPublic: true,
          abuseConfidenceScore: 92,
          countryCode: 'DE',
          usageType: 'Data Center/Web Hosting/Transit',
          isp: 'Tor Exit Network',
          domain: 'tor-node.org',
          totalReports: 147,
          lastReportedAt: '2026-08-26T19:00:00Z',
        },
      };

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      } as any);

      const res = await abuseIpdbProvider.lookupIp('185.220.101.5');
      expect(res.status).toBe('LIVE');
      expect(res.reputation).toBe('MALICIOUS');
      expect(res.data?.abuseConfidenceScore).toBe(92);
      expect(res.data?.totalReports).toBe(147);
    });

    it('handles AbuseIPDB HTTP 429 rate limiting', async () => {
      process.env.ABUSEIPDB_API_KEY = 'mock_abuse_ipdb_key_998877';

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
      } as any);

      const res = await abuseIpdbProvider.lookupIp('185.220.101.5');
      expect(res.status).toBe('ERROR');
      expect(res.error).toContain('rate limit');
    });
  });

  // -------------------------------------------------------------
  // 3. IPQualityScore Provider
  // -------------------------------------------------------------
  describe('IPQualityScore Provider', () => {
    it('bypasses external API for localhost and returns CLEAN LIVE', async () => {
      const fetchSpy = vi.fn();
      global.fetch = fetchSpy;

      const res = await ipqsProvider.lookupIp('127.0.0.1');
      expect(res.status).toBe('LIVE');
      expect(res.reputation).toBe('CLEAN');
      expect(res.data?.proxy).toBe(false);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('returns NOT_CONFIGURED status when IPQS_API_KEY is missing', async () => {
      delete process.env.IPQS_API_KEY;
      const res = await ipqsProvider.lookupIp('45.142.214.22');
      expect(res.status).toBe('NOT_CONFIGURED');
    });

    it('parses Proxy / Tor / VPN threat detection correctly', async () => {
      process.env.IPQS_API_KEY = 'mock_ipqs_api_key_443322';

      const mockResponse = {
        success: true,
        fraud_score: 95,
        proxy: true,
        vpn: true,
        tor: true,
        country_code: 'NL',
        city: 'Amsterdam',
        ISP: 'HostKey B.V.',
        ASN: 200019,
        organization: 'Tor Anonymizing Proxy',
      };

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      } as any);

      const res = await ipqsProvider.lookupIp('45.142.214.22');
      expect(res.status).toBe('LIVE');
      expect(res.reputation).toBe('MALICIOUS');
      expect(res.data?.tor).toBe(true);
      expect(res.data?.fraud_score).toBe(95);
    });

    it('handles IPQS API success=false errors gracefully', async () => {
      process.env.IPQS_API_KEY = 'mock_ipqs_api_key_443322';

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          success: false,
          message: 'Quota exceeded for current billing period',
        }),
      } as any);

      const res = await ipqsProvider.lookupIp('45.142.214.22');
      expect(res.status).toBe('ERROR');
      expect(res.error).toContain('Quota exceeded');
    });
  });

  // -------------------------------------------------------------
  // 4. IPinfo Geo Provider
  // -------------------------------------------------------------
  describe('Geo Provider', () => {
    it('uses LIVE IPinfo API when IPINFO_TOKEN is present', async () => {
      process.env.IPINFO_TOKEN = 'mock_ipinfo_token_556677';

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          ip: '198.51.100.24',
          country: 'US',
          region: 'Virginia',
          city: 'Ashburn',
          loc: '39.0437,-77.4875',
          org: 'AS16509 Amazon.com, Inc.',
        }),
      } as any);

      const res = await geoProvider.resolveIp('198.51.100.24');
      expect(res.status).toBe('LIVE');
      expect(res.geo.country_code).toBe('US');
      expect(res.geo.city).toBe('Ashburn');
      expect(res.geo.latitude).toBe(39.0437);
      expect(res.geo.longitude).toBe(-77.4875);
    });

    it('falls back to SOC database simulation mode when IPINFO_TOKEN is absent', async () => {
      delete process.env.IPINFO_TOKEN;
      const res = await geoProvider.resolveIp('185.220.101.5');
      expect(res.status).toBe('SIMULATION');
      expect(res.geo.ip).toBe('185.220.101.5');
      expect(res.geo.threat_reputation).toBe('MALICIOUS');
    });
  });

  // -------------------------------------------------------------
  // 5. DNS Provider
  // -------------------------------------------------------------
  describe('DNS Provider', () => {
    it('queries and normalizes DNS records safely', async () => {
      const dnsRes = await dnsProvider.lookupDomain('example.com');
      expect(dnsRes.status).toBe('LIVE');
      expect(dnsRes.domain).toBe('example.com');
      expect(Array.isArray(dnsRes.a_records)).toBe(true);
      expect(Array.isArray(dnsRes.mx_records)).toBe(true);
      expect(Array.isArray(dnsRes.txt_records)).toBe(true);
    });
  });

  // -------------------------------------------------------------
  // 6. WHOIS Provider
  // -------------------------------------------------------------
  describe('WHOIS Provider', () => {
    it('returns NOT_CONFIGURED status when WHOIS_API_KEY is not set', async () => {
      delete process.env.WHOIS_API_KEY;
      const res = await whoisProvider.lookupDomain('phishing-test-domain.net');
      expect(res.status).toBe('NOT_CONFIGURED');
      expect(res.domain).toBe('phishing-test-domain.net');
    });

    it('calculates domain age and registrar data from normalized WHOIS response', async () => {
      process.env.WHOIS_API_KEY = 'mock_whois_api_key_778899';

      const pastDate = new Date(Date.now() - 45 * 24 * 3600 * 1000).toISOString();
      const mockWhoisRecord = {
        WhoisRecord: {
          createdDateNormalized: pastDate,
          updatedDateNormalized: pastDate,
          expiresDateNormalized: '2027-08-26T00:00:00Z',
          registrarName: 'NameCheap, Inc.',
          registrant: { country: 'PA' },
          nameServers: { hostNames: ['ns1.anonymousdns.com', 'ns2.anonymousdns.com'] },
        },
      };

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockWhoisRecord,
      } as any);

      const res = await whoisProvider.lookupDomain('newly-registered-spoof.com');
      expect(res.status).toBe('LIVE');
      expect(res.registrar).toBe('NameCheap, Inc.');
      expect(res.domain_age_days).toBeGreaterThanOrEqual(44);
      expect(res.domain_age_days).toBeLessThanOrEqual(46);
      expect(res.registrant_country).toBe('PA');
      expect(res.nameservers).toHaveLength(2);
    });
  });
});
