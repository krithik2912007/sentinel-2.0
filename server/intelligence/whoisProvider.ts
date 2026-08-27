import { WhoisIntelligence } from './types';

export class WhoisProvider {
  private getApiKey(): string | undefined {
    return process.env.WHOIS_API_KEY?.trim();
  }

  isConfigured(): boolean {
    const key = this.getApiKey();
    return Boolean(key && key.length > 5);
  }

  async lookupDomain(domain: string): Promise<WhoisIntelligence> {
    const cleanDomain = domain.toLowerCase().trim();

    if (!this.isConfigured()) {
      return {
        domain: cleanDomain,
        nameservers: [],
        provider: 'WhoisXMLAPI',
        status: 'NOT_CONFIGURED',
        error: 'WHOIS_API_KEY is not configured in server environment',
      };
    }

    try {
      const apiKey = this.getApiKey()!;
      const response = await fetch(
        `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${encodeURIComponent(apiKey)}&domainName=${encodeURIComponent(cleanDomain)}&outputFormat=JSON`,
        { signal: AbortSignal.timeout(6000) }
      );

      if (response.status === 429) {
        return {
          domain: cleanDomain,
          nameservers: [],
          provider: 'WhoisXMLAPI',
          status: 'ERROR',
          error: 'WhoisXMLAPI rate limit exceeded (HTTP 429)',
        };
      }

      if (!response.ok) {
        return {
          domain: cleanDomain,
          nameservers: [],
          provider: 'WhoisXMLAPI',
          status: 'ERROR',
          error: `WHOIS HTTP ${response.status}: ${response.statusText}`,
        };
      }

      const json = await response.json();
      const record = json.WhoisRecord || {};
      const creationDate = record.createdDateNormalized || record.createdDate;
      const updatedDate = record.updatedDateNormalized || record.updatedDate;
      const expiresDate = record.expiresDateNormalized || record.expiresDate;
      const registrar = record.registrarName;
      const registrantCountry = record.registrant?.country;
      const nameservers = record.nameServers?.hostNames || [];

      let domainAgeDays: number | undefined;
      if (creationDate) {
        const createdMs = new Date(creationDate).getTime();
        if (!isNaN(createdMs)) {
          domainAgeDays = Math.floor((Date.now() - createdMs) / (1000 * 3600 * 24));
        }
      }

      return {
        domain: cleanDomain,
        registrar,
        creation_date: creationDate,
        updated_date: updatedDate,
        expiration_date: expiresDate,
        nameservers,
        registrant_country: registrantCountry,
        domain_age_days: domainAgeDays,
        provider: 'WhoisXMLAPI',
        status: 'LIVE',
      };
    } catch (err: any) {
      return {
        domain: cleanDomain,
        nameservers: [],
        provider: 'WhoisXMLAPI',
        status: 'ERROR',
        error: err.name === 'TimeoutError' ? 'WhoisXMLAPI request timed out' : (err.message || 'Failed to query WHOIS'),
      };
    }
  }
}

export const whoisProvider = new WhoisProvider();
