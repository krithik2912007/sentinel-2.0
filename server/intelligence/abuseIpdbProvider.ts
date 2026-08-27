import { IntelligenceResult } from './types';
import { isPrivateIp } from './geoProvider';

export class AbuseIpdbProvider {
  private getApiKey(): string | undefined {
    return process.env.ABUSEIPDB_API_KEY?.trim();
  }

  isConfigured(): boolean {
    const key = this.getApiKey();
    return Boolean(key && key.length > 5);
  }

  async lookupIp(ip: string): Promise<IntelligenceResult> {
    const cleanIp = ip.trim();

    if (isPrivateIp(cleanIp)) {
      return {
        provider: 'AbuseIPDB',
        status: 'LIVE',
        indicator_type: 'IP',
        indicator: cleanIp,
        reputation: 'CLEAN',
        confidence: 1.0,
        data: { abuseConfidenceScore: 0, totalReports: 0, isPublic: false, usageType: 'Reserved/Private RFC1918' },
        fetched_at: new Date().toISOString(),
      };
    }

    if (!this.isConfigured()) {
      return {
        provider: 'AbuseIPDB',
        status: 'NOT_CONFIGURED',
        indicator_type: 'IP',
        indicator: cleanIp,
        error: 'ABUSEIPDB_API_KEY is not configured in server environment',
        fetched_at: new Date().toISOString(),
      };
    }

    try {
      const apiKey = this.getApiKey()!;
      const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(cleanIp)}&maxAgeInDays=90&verbose`, {
        headers: {
          'Key': apiKey,
          'Accept': 'application/json',
        },
        signal: AbortSignal.timeout(5000),
      });

      if (response.status === 429) {
        return {
          provider: 'AbuseIPDB',
          status: 'ERROR',
          indicator_type: 'IP',
          indicator: cleanIp,
          error: 'AbuseIPDB rate limit exceeded (HTTP 429)',
          fetched_at: new Date().toISOString(),
        };
      }

      if (!response.ok) {
        return {
          provider: 'AbuseIPDB',
          status: 'ERROR',
          indicator_type: 'IP',
          indicator: cleanIp,
          error: `AbuseIPDB HTTP ${response.status}: ${response.statusText}`,
          fetched_at: new Date().toISOString(),
        };
      }

      const json = await response.json();
      const data = json.data || {};
      const score = data.abuseConfidenceScore || 0;
      const totalReports = data.totalReports || 0;

      let reputation: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' = 'CLEAN';
      if (score >= 50) reputation = 'MALICIOUS';
      else if (score > 10 || totalReports > 2) reputation = 'SUSPICIOUS';

      return {
        provider: 'AbuseIPDB',
        status: 'LIVE',
        indicator_type: 'IP',
        indicator: cleanIp,
        reputation,
        confidence: 0.9,
        data: {
          abuseConfidenceScore: score,
          totalReports,
          countryCode: data.countryCode,
          usageType: data.usageType,
          isp: data.isp,
          domain: data.domain,
          lastReportedAt: data.lastReportedAt,
        },
        fetched_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        provider: 'AbuseIPDB',
        status: 'ERROR',
        indicator_type: 'IP',
        indicator: cleanIp,
        error: err.name === 'TimeoutError' ? 'AbuseIPDB request timed out' : (err.message || 'Failed to query AbuseIPDB'),
        fetched_at: new Date().toISOString(),
      };
    }
  }
}

export const abuseIpdbProvider = new AbuseIpdbProvider();
