import { IntelligenceResult } from './types';
import { isPrivateIp } from './geoProvider';

export class IpqsProvider {
  private getApiKey(): string | undefined {
    return process.env.IPQS_API_KEY?.trim();
  }

  isConfigured(): boolean {
    const key = this.getApiKey();
    return Boolean(key && key.length > 5);
  }

  async lookupIp(ip: string): Promise<IntelligenceResult> {
    const cleanIp = ip.trim();

    if (isPrivateIp(cleanIp)) {
      return {
        provider: 'IPQualityScore',
        status: 'LIVE',
        indicator_type: 'IP',
        indicator: cleanIp,
        reputation: 'CLEAN',
        confidence: 1.0,
        data: { proxy: false, vpn: false, tor: false, fraud_score: 0, is_private: true },
        fetched_at: new Date().toISOString(),
      };
    }

    if (!this.isConfigured()) {
      return {
        provider: 'IPQualityScore',
        status: 'NOT_CONFIGURED',
        indicator_type: 'IP',
        indicator: cleanIp,
        error: 'IPQS_API_KEY is not configured in server environment',
        fetched_at: new Date().toISOString(),
      };
    }

    try {
      const apiKey = this.getApiKey()!;
      const response = await fetch(
        `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(apiKey)}/${encodeURIComponent(cleanIp)}?strictness=1`,
        { signal: AbortSignal.timeout(5000) }
      );

      if (response.status === 429) {
        return {
          provider: 'IPQualityScore',
          status: 'ERROR',
          indicator_type: 'IP',
          indicator: cleanIp,
          error: 'IPQualityScore rate limit exceeded (HTTP 429)',
          fetched_at: new Date().toISOString(),
        };
      }

      if (!response.ok) {
        return {
          provider: 'IPQualityScore',
          status: 'ERROR',
          indicator_type: 'IP',
          indicator: cleanIp,
          error: `IPQS HTTP ${response.status}: ${response.statusText}`,
          fetched_at: new Date().toISOString(),
        };
      }

      const json = await response.json();
      if (!json.success) {
        return {
          provider: 'IPQualityScore',
          status: 'ERROR',
          indicator_type: 'IP',
          indicator: cleanIp,
          error: json.message || 'IPQS query failed',
          fetched_at: new Date().toISOString(),
        };
      }

      const fraudScore = json.fraud_score || 0;
      let reputation: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' = 'CLEAN';
      if (fraudScore >= 80 || json.tor) reputation = 'MALICIOUS';
      else if (fraudScore >= 40 || json.vpn || json.proxy) reputation = 'SUSPICIOUS';

      return {
        provider: 'IPQualityScore',
        status: 'LIVE',
        indicator_type: 'IP',
        indicator: cleanIp,
        reputation,
        confidence: 0.9,
        data: {
          fraud_score: fraudScore,
          proxy: json.proxy || false,
          vpn: json.vpn || false,
          tor: json.tor || false,
          country_code: json.country_code,
          city: json.city,
          ISP: json.ISP,
          ASN: json.ASN,
          organization: json.organization,
        },
        fetched_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        provider: 'IPQualityScore',
        status: 'ERROR',
        indicator_type: 'IP',
        indicator: cleanIp,
        error: err.name === 'TimeoutError' ? 'IPQualityScore request timed out' : (err.message || 'Failed to query IPQualityScore'),
        fetched_at: new Date().toISOString(),
      };
    }
  }

  async lookupUrl(url: string): Promise<IntelligenceResult> {
    const cleanUrl = url.trim();

    if (!this.isConfigured()) {
      return {
        provider: 'IPQualityScore',
        status: 'NOT_CONFIGURED',
        indicator_type: 'URL',
        indicator: cleanUrl,
        error: 'IPQS_API_KEY is not configured in server environment',
        fetched_at: new Date().toISOString(),
      };
    }

    try {
      const apiKey = this.getApiKey()!;
      const response = await fetch(
        `https://ipqualityscore.com/api/json/url/${encodeURIComponent(apiKey)}/${encodeURIComponent(cleanUrl)}`,
        { signal: AbortSignal.timeout(5000) }
      );

      if (response.status === 429) {
        return {
          provider: 'IPQualityScore',
          status: 'ERROR',
          indicator_type: 'URL',
          indicator: cleanUrl,
          error: 'IPQualityScore rate limit exceeded (HTTP 429)',
          fetched_at: new Date().toISOString(),
        };
      }

      if (!response.ok) {
        return {
          provider: 'IPQualityScore',
          status: 'ERROR',
          indicator_type: 'URL',
          indicator: cleanUrl,
          error: `IPQS HTTP ${response.status}: ${response.statusText}`,
          fetched_at: new Date().toISOString(),
        };
      }

      const json = await response.json();
      if (!json.success) {
        return {
          provider: 'IPQualityScore',
          status: 'ERROR',
          indicator_type: 'URL',
          indicator: cleanUrl,
          error: json.message || 'IPQS URL query failed',
          fetched_at: new Date().toISOString(),
        };
      }

      const riskScore = json.risk_score || 0;
      let reputation: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' = 'CLEAN';
      if (riskScore >= 75 || json.phishing || json.malware) reputation = 'MALICIOUS';
      else if (riskScore >= 40 || json.suspicious) reputation = 'SUSPICIOUS';

      return {
        provider: 'IPQualityScore',
        status: 'LIVE',
        indicator_type: 'URL',
        indicator: cleanUrl,
        reputation,
        confidence: 0.9,
        data: {
          risk_score: riskScore,
          phishing: json.phishing || false,
          malware: json.malware || false,
          domain_age: json.domain_age,
          category: json.category,
        },
        fetched_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        provider: 'IPQualityScore',
        status: 'ERROR',
        indicator_type: 'URL',
        indicator: cleanUrl,
        error: err.name === 'TimeoutError' ? 'IPQualityScore request timed out' : (err.message || 'Failed to query IPQualityScore URL scanner'),
        fetched_at: new Date().toISOString(),
      };
    }
  }
}

export const ipqsProvider = new IpqsProvider();
