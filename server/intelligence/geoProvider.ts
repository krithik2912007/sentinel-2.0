import { GeoLocationInfo } from '../../src/types';
import { MOCK_IP_GEO_DB, generateDeterministicGeoFallback } from '../mockGeoDb';

export function isPrivateIp(ip: string): boolean {
  if (!ip) return true;
  const clean = ip.trim();
  if (clean === 'localhost' || clean === '127.0.0.1' || clean === '::1') return true;
  if (clean.startsWith('10.') || clean.startsWith('192.168.')) return true;
  if (clean.startsWith('172.')) {
    const parts = clean.split('.');
    if (parts.length >= 2) {
      const second = parseInt(parts[1], 10);
      if (second >= 16 && second <= 31) return true;
    }
  }
  if (clean.startsWith('169.254.')) return true;
  if (clean.startsWith('fc00:') || clean.startsWith('fe80:')) return true;
  return false;
}

export class GeoProvider {
  private getToken(): string | undefined {
    return process.env.IPINFO_TOKEN?.trim();
  }

  isConfigured(): boolean {
    const token = this.getToken();
    return Boolean(token && token.length > 5);
  }

  async resolveIp(ip: string): Promise<{ geo: GeoLocationInfo; status: 'LIVE' | 'SIMULATION' | 'ERROR' }> {
    const cleanIp = ip.trim();

    // 1. Private RFC 1918 / Localhost check
    if (isPrivateIp(cleanIp)) {
      return {
        geo: {
          ip: cleanIp,
          country: 'Internal Network',
          country_code: 'INT',
          region: 'Private RFC1918',
          city: 'Non-routable',
          latitude: 0,
          longitude: 0,
          asn: 'AS-PRIVATE',
          isp: 'Internal Enterprise Routing',
          org: 'Private Local Subnet',
          is_vpn_tor_proxy: false,
          threat_reputation: 'CLEAN',
        },
        status: 'LIVE',
      };
    }

    // 2. Real IPinfo Lookup if token configured
    if (this.isConfigured()) {
      try {
        const token = this.getToken()!;
        const response = await fetch(`https://ipinfo.io/${encodeURIComponent(cleanIp)}?token=${encodeURIComponent(token)}`, {
          signal: AbortSignal.timeout(4000),
        });
        if (response.ok) {
          const data = await response.json();
          const [lat, lon] = (data.loc || '0,0').split(',').map((v: string) => parseFloat(v));
          return {
            geo: {
              ip: cleanIp,
              country: data.country || 'Unknown',
              country_code: data.country || 'XX',
              region: data.region || 'Unknown',
              city: data.city || 'Unknown',
              latitude: lat || 0,
              longitude: lon || 0,
              asn: data.org ? data.org.split(' ')[0] : 'AS0',
              isp: data.org || 'Internet Service Provider',
              org: data.org || data.company?.name || 'Autonomous System',
              threat_reputation: 'UNKNOWN',
            },
            status: 'LIVE',
          };
        }
      } catch {
        // Graceful fallback to deterministic SOC dataset if external call fails
      }
    }

    // 3. Known SOC Threat Intelligence Mock Database
    if (MOCK_IP_GEO_DB[cleanIp]) {
      return {
        geo: { ...MOCK_IP_GEO_DB[cleanIp] },
        status: 'SIMULATION',
      };
    }

    // 4. Deterministic Geo Fallback for simulation
    return {
      geo: generateDeterministicGeoFallback(cleanIp),
      status: 'SIMULATION',
    };
  }
}

export const geoProvider = new GeoProvider();
