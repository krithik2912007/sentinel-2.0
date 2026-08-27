import { describe, it, expect } from 'vitest';
import { isPrivateIp, geoProvider } from '../server/intelligence/geoProvider';
import { intelligenceManager } from '../server/intelligence/providerManager';

describe('Threat Intelligence Layer', () => {
  it('should identify private RFC 1918 IPs safely without geolocating to random countries', async () => {
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('10.0.4.15')).toBe(true);
    expect(isPrivateIp('192.168.1.100')).toBe(true);
    expect(isPrivateIp('172.16.5.2')).toBe(true);
    expect(isPrivateIp('185.220.101.5')).toBe(false);

    const res = await geoProvider.resolveIp('10.0.4.15');
    expect(res.geo.country).toBe('Internal Network');
    expect(res.geo.latitude).toBe(0);
    expect(res.geo.longitude).toBe(0);
  });

  it('should return normalized provider statuses', () => {
    const statuses = intelligenceManager.getProviderStatuses();
    expect(statuses.dns).toBeDefined();
    expect(statuses.geoip).toBeDefined();
    expect(statuses.virustotal).toBeDefined();
    expect(statuses.abuseipdb).toBeDefined();
  });
});
