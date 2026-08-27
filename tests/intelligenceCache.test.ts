import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { intelligenceCacheRepository } from '../server/db/repositories/intelligenceCacheRepository';
import { intelligenceManager } from '../server/intelligence/providerManager';
import { virusTotalProvider } from '../server/intelligence/virusTotalProvider';
import * as poolModule from '../server/db/pool';

describe('Intelligence Cache Layer', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    intelligenceCacheRepository.clearInMemoryL1();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  it('stores and retrieves indicator intelligence in explicit DEMO_MODE without false persistence reporting', async () => {
    process.env.IN_MEMORY_DEMO_MODE = 'true';
    vi.spyOn(poolModule, 'getDatabaseStatus').mockReturnValue({
      connected: false,
      demoMode: true,
      error: null,
    });

    const testPayload = {
      provider: 'VirusTotal',
      status: 'LIVE',
      indicator_type: 'HASH',
      indicator: 'c801b73e5bf029e0839e557ee6c764e5fae16d40cc1d56715f2095c52e42f9b8',
      reputation: 'MALICIOUS',
      confidence: 0.95,
      data: { malicious: 55, suspicious: 2 },
      fetched_at: new Date().toISOString(),
    };

    const setResult = await intelligenceCacheRepository.set(
      'VirusTotal',
      'HASH',
      'c801b73e5bf029e0839e557ee6c764e5fae16d40cc1d56715f2095c52e42f9b8',
      testPayload,
      24
    );

    expect(setResult.persisted).toBe(false);
    expect(setResult.storage).toBe('IN_MEMORY_DEMO');

    const cached = await intelligenceCacheRepository.get(
      'VirusTotal:HASH:c801b73e5bf029e0839e557ee6c764e5fae16d40cc1d56715f2095c52e42f9b8'
    );

    expect(cached).not.toBeNull();
    expect(cached?.provider).toBe('VirusTotal');
    expect(cached?.persisted_to_db).toBe(false);
    expect(cached?.response_json.reputation).toBe('MALICIOUS');
    expect(cached?.response_json.data.malicious).toBe(55);
  });

  it('fails fast and refuses to silently claim persistence in normal MVP mode when PostgreSQL is disconnected', async () => {
    delete process.env.DEMO_MODE;
    delete process.env.IN_MEMORY_DEMO_MODE;

    vi.spyOn(poolModule, 'getDatabaseStatus').mockReturnValue({
      connected: false,
      demoMode: false,
      error: 'PostgreSQL connection failed',
    });

    await expect(
      intelligenceCacheRepository.set(
        'VirusTotal',
        'HASH',
        'c801b73e5bf029e0839e557ee6c764e5fae16d40cc1d56715f2095c52e42f9b8',
        { status: 'LIVE' },
        24
      )
    ).rejects.toThrow(/PostgreSQL connection required in normal MVP mode/);
  });

  it('persists to PostgreSQL when connected in normal MVP mode and marks persisted_to_db true', async () => {
    delete process.env.DEMO_MODE;
    delete process.env.IN_MEMORY_DEMO_MODE;

    vi.spyOn(poolModule, 'getDatabaseStatus').mockReturnValue({
      connected: true,
      demoMode: false,
      error: null,
    });
    vi.spyOn(poolModule, 'assertDatabaseAccessible').mockReturnValue();

    const querySpy = vi.spyOn(poolModule, 'query').mockResolvedValueOnce({
      rows: [],
      rowCount: 1,
      command: 'INSERT',
      oid: 0,
      fields: [],
    } as any);

    const setResult = await intelligenceCacheRepository.set(
      'VirusTotal',
      'HASH',
      'c801b73e5bf029e0839e557ee6c764e5fae16d40cc1d56715f2095c52e42f9b8',
      { status: 'LIVE', reputation: 'MALICIOUS' },
      24
    );

    expect(setResult.persisted).toBe(true);
    expect(setResult.storage).toBe('POSTGRESQL');
    expect(querySpy).toHaveBeenCalled();
  });

  it('avoids duplicate external API queries when cached result is valid in L1 performance layer', async () => {
    process.env.VIRUSTOTAL_API_KEY = 'mock_vt_key';
    process.env.IN_MEMORY_DEMO_MODE = 'true';
    vi.spyOn(poolModule, 'getDatabaseStatus').mockReturnValue({
      connected: false,
      demoMode: true,
      error: null,
    });

    const vtSpy = vi.spyOn(virusTotalProvider, 'lookupHash').mockResolvedValueOnce({
      provider: 'VirusTotal',
      status: 'LIVE',
      indicator_type: 'HASH',
      indicator: 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234',
      reputation: 'MALICIOUS',
      confidence: 0.9,
      data: { malicious: 20 },
      fetched_at: new Date().toISOString(),
    });

    // First call -> invokes provider and caches
    const firstResult = await intelligenceManager.enrichHash('abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234');
    expect(firstResult.status).toBe('LIVE');
    expect(vtSpy).toHaveBeenCalledTimes(1);

    // Second call -> should hit cache without calling provider
    const secondResult = await intelligenceManager.enrichHash('abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234');
    expect(secondResult.status).toBe('LIVE');
    expect(secondResult.reputation).toBe('MALICIOUS');
    expect(vtSpy).toHaveBeenCalledTimes(1); // Provider not called second time
  });

  it('expires stale entries according to TTL', async () => {
    process.env.IN_MEMORY_DEMO_MODE = 'true';
    vi.spyOn(poolModule, 'getDatabaseStatus').mockReturnValue({
      connected: false,
      demoMode: true,
      error: null,
    });

    // Write an entry with negative TTL (already expired)
    await intelligenceCacheRepository.set(
      'VirusTotal',
      'HASH',
      'expiredhash1234567890',
      { status: 'LIVE', reputation: 'CLEAN' },
      -1 // Expired 1 hour ago
    );

    const result = await intelligenceCacheRepository.get('VirusTotal:HASH:expiredhash1234567890');
    expect(result).toBeNull();
  });
});

