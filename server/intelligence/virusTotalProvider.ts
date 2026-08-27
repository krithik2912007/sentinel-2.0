import { IntelligenceResult } from './types';

export class VirusTotalProvider {
  private getApiKey(): string | undefined {
    return process.env.VIRUSTOTAL_API_KEY?.trim();
  }

  isConfigured(): boolean {
    const key = this.getApiKey();
    return Boolean(key && key.length > 5);
  }

  async lookupHash(sha256Hash: string): Promise<IntelligenceResult> {
    const cleanHash = sha256Hash.toLowerCase().trim();
    if (!this.isConfigured()) {
      return {
        provider: 'VirusTotal',
        status: 'NOT_CONFIGURED',
        indicator_type: 'HASH',
        indicator: cleanHash,
        error: 'VIRUSTOTAL_API_KEY is not configured in server environment',
        fetched_at: new Date().toISOString(),
      };
    }

    try {
      const apiKey = this.getApiKey()!;
      const response = await fetch(`https://www.virustotal.com/api/v3/files/${encodeURIComponent(cleanHash)}`, {
        headers: {
          'x-apikey': apiKey,
          'Accept': 'application/json',
        },
        signal: AbortSignal.timeout(6000),
      });

      if (response.status === 404) {
        return {
          provider: 'VirusTotal',
          status: 'LIVE',
          indicator_type: 'HASH',
          indicator: cleanHash,
          reputation: 'CLEAN',
          confidence: 0.8,
          data: { harmless: 0, malicious: 0, suspicious: 0, undetected: 0, total: 0, message: 'Hash not seen in VirusTotal dataset' },
          fetched_at: new Date().toISOString(),
        };
      }

      if (response.status === 429) {
        return {
          provider: 'VirusTotal',
          status: 'ERROR',
          indicator_type: 'HASH',
          indicator: cleanHash,
          error: 'VirusTotal rate limit exceeded (HTTP 429)',
          fetched_at: new Date().toISOString(),
        };
      }

      if (!response.ok) {
        return {
          provider: 'VirusTotal',
          status: 'ERROR',
          indicator_type: 'HASH',
          indicator: cleanHash,
          error: `VirusTotal API error: HTTP ${response.status} ${response.statusText}`,
          fetched_at: new Date().toISOString(),
        };
      }

      const json = await response.json();
      const stats = json.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const harmless = stats.harmless || 0;
      const undetected = stats.undetected || 0;

      let reputation: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' = 'CLEAN';
      if (malicious >= 3) reputation = 'MALICIOUS';
      else if (malicious > 0 || suspicious > 1) reputation = 'SUSPICIOUS';

      return {
        provider: 'VirusTotal',
        status: 'LIVE',
        indicator_type: 'HASH',
        indicator: cleanHash,
        reputation,
        confidence: 0.95,
        data: {
          malicious,
          suspicious,
          harmless,
          undetected,
          meaningful_name: json.data?.attributes?.meaningful_name,
          type_description: json.data?.attributes?.type_description,
        },
        fetched_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        provider: 'VirusTotal',
        status: 'ERROR',
        indicator_type: 'HASH',
        indicator: cleanHash,
        error: err.name === 'TimeoutError' ? 'VirusTotal API request timed out' : (err.message || 'Network error querying VirusTotal'),
        fetched_at: new Date().toISOString(),
      };
    }
  }

  async lookupDomain(domain: string): Promise<IntelligenceResult> {
    const cleanDomain = domain.toLowerCase().trim();
    if (!this.isConfigured()) {
      return {
        provider: 'VirusTotal',
        status: 'NOT_CONFIGURED',
        indicator_type: 'DOMAIN',
        indicator: cleanDomain,
        error: 'VIRUSTOTAL_API_KEY is not configured in server environment',
        fetched_at: new Date().toISOString(),
      };
    }

    try {
      const apiKey = this.getApiKey()!;
      const response = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(cleanDomain)}`, {
        headers: {
          'x-apikey': apiKey,
          'Accept': 'application/json',
        },
        signal: AbortSignal.timeout(6000),
      });

      if (response.status === 404) {
        return {
          provider: 'VirusTotal',
          status: 'LIVE',
          indicator_type: 'DOMAIN',
          indicator: cleanDomain,
          reputation: 'CLEAN',
          confidence: 0.8,
          data: { harmless: 0, malicious: 0, suspicious: 0, undetected: 0, message: 'Domain not indexed in VirusTotal' },
          fetched_at: new Date().toISOString(),
        };
      }

      if (response.status === 429) {
        return {
          provider: 'VirusTotal',
          status: 'ERROR',
          indicator_type: 'DOMAIN',
          indicator: cleanDomain,
          error: 'VirusTotal rate limit exceeded (HTTP 429)',
          fetched_at: new Date().toISOString(),
        };
      }

      if (!response.ok) {
        return {
          provider: 'VirusTotal',
          status: 'ERROR',
          indicator_type: 'DOMAIN',
          indicator: cleanDomain,
          error: `VirusTotal API error: HTTP ${response.status} ${response.statusText}`,
          fetched_at: new Date().toISOString(),
        };
      }

      const json = await response.json();
      const stats = json.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;

      let reputation: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' = 'CLEAN';
      if (malicious >= 3) reputation = 'MALICIOUS';
      else if (malicious > 0 || suspicious > 1) reputation = 'SUSPICIOUS';

      return {
        provider: 'VirusTotal',
        status: 'LIVE',
        indicator_type: 'DOMAIN',
        indicator: cleanDomain,
        reputation,
        confidence: 0.9,
        data: {
          malicious,
          suspicious,
          harmless: stats.harmless || 0,
          categories: json.data?.attributes?.categories || {},
        },
        fetched_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        provider: 'VirusTotal',
        status: 'ERROR',
        indicator_type: 'DOMAIN',
        indicator: cleanDomain,
        error: err.name === 'TimeoutError' ? 'VirusTotal API request timed out' : (err.message || 'Network error querying VirusTotal'),
        fetched_at: new Date().toISOString(),
      };
    }
  }

  async lookupUrl(url: string): Promise<IntelligenceResult> {
    const cleanUrl = url.trim();
    if (!this.isConfigured()) {
      return {
        provider: 'VirusTotal',
        status: 'NOT_CONFIGURED',
        indicator_type: 'URL',
        indicator: cleanUrl,
        error: 'VIRUSTOTAL_API_KEY is not configured in server environment',
        fetched_at: new Date().toISOString(),
      };
    }

    try {
      const apiKey = this.getApiKey()!;
      // VirusTotal URL identifier is base64url string without trailing '='
      const urlId = Buffer.from(cleanUrl)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

      const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: {
          'x-apikey': apiKey,
          'Accept': 'application/json',
        },
        signal: AbortSignal.timeout(6000),
      });

      if (response.status === 404) {
        return {
          provider: 'VirusTotal',
          status: 'LIVE',
          indicator_type: 'URL',
          indicator: cleanUrl,
          reputation: 'CLEAN',
          confidence: 0.8,
          data: { harmless: 0, malicious: 0, suspicious: 0, message: 'URL not seen in VirusTotal dataset' },
          fetched_at: new Date().toISOString(),
        };
      }

      if (response.status === 429) {
        return {
          provider: 'VirusTotal',
          status: 'ERROR',
          indicator_type: 'URL',
          indicator: cleanUrl,
          error: 'VirusTotal rate limit exceeded (HTTP 429)',
          fetched_at: new Date().toISOString(),
        };
      }

      if (!response.ok) {
        return {
          provider: 'VirusTotal',
          status: 'ERROR',
          indicator_type: 'URL',
          indicator: cleanUrl,
          error: `VirusTotal API error: HTTP ${response.status} ${response.statusText}`,
          fetched_at: new Date().toISOString(),
        };
      }

      const json = await response.json();
      const stats = json.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;

      let reputation: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' = 'CLEAN';
      if (malicious >= 3) reputation = 'MALICIOUS';
      else if (malicious > 0 || suspicious > 1) reputation = 'SUSPICIOUS';

      return {
        provider: 'VirusTotal',
        status: 'LIVE',
        indicator_type: 'URL',
        indicator: cleanUrl,
        reputation,
        confidence: 0.9,
        data: {
          malicious,
          suspicious,
          harmless: stats.harmless || 0,
          categories: json.data?.attributes?.categories || {},
        },
        fetched_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        provider: 'VirusTotal',
        status: 'ERROR',
        indicator_type: 'URL',
        indicator: cleanUrl,
        error: err.name === 'TimeoutError' ? 'VirusTotal API request timed out' : (err.message || 'Network error querying VirusTotal'),
        fetched_at: new Date().toISOString(),
      };
    }
  }
}

export const virusTotalProvider = new VirusTotalProvider();
