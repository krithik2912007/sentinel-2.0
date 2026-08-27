import { query, getDatabaseStatus, assertDatabaseAccessible, isDemoModeExplicit } from '../pool';

export interface CachedIntelligence {
  cache_key: string;
  provider: string;
  indicator_type: string;
  indicator_value: string;
  response_json: any;
  created_at: string;
  expires_at: string;
  persisted_to_db: boolean;
}

export interface CacheSetResult {
  persisted: boolean;
  storage: 'POSTGRESQL' | 'IN_MEMORY_DEMO';
  cache_key: string;
}

const inMemoryL1Cache: Map<string, CachedIntelligence> = new Map();

export class IntelligenceCacheRepository {
  async get(cacheKey: string): Promise<CachedIntelligence | null> {
    const cleanKey = cacheKey.trim();

    // 1. Check L1 In-Memory performance layer
    const l1Item = inMemoryL1Cache.get(cleanKey);
    if (l1Item) {
      if (new Date(l1Item.expires_at).getTime() < Date.now()) {
        inMemoryL1Cache.delete(cleanKey);
      } else {
        return l1Item;
      }
    }

    // 2. Authoritative PostgreSQL lookup
    const status = getDatabaseStatus();
    if (!status.connected) {
      if (isDemoModeExplicit()) {
        return null;
      }
      // Normal MVP mode: Must not silently pretend database is fine if unaccessible
      assertDatabaseAccessible();
      return null;
    }

    const res = await query(
      `SELECT * FROM intelligence_cache WHERE cache_key = $1 AND expires_at > NOW()`,
      [cleanKey]
    );

    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    const cachedItem: CachedIntelligence = {
      cache_key: r.cache_key,
      provider: r.provider,
      indicator_type: r.indicator_type,
      indicator_value: r.indicator_value,
      response_json: typeof r.response_json === 'string' ? JSON.parse(r.response_json) : r.response_json,
      created_at: new Date(r.created_at).toISOString(),
      expires_at: new Date(r.expires_at).toISOString(),
      persisted_to_db: true,
    };

    // Populate L1 cache for subsequent fast reads
    inMemoryL1Cache.set(cleanKey, cachedItem);
    return cachedItem;
  }

  async set(
    provider: string,
    indicatorType: string,
    indicatorValue: string,
    responseJson: any,
    ttlHours = 24
  ): Promise<CacheSetResult> {
    const cacheKey = `${provider}:${indicatorType}:${indicatorValue.toLowerCase().trim()}`;
    const expiresAt = new Date(Date.now() + ttlHours * 3600 * 1000).toISOString();
    const createdAt = new Date().toISOString();

    const status = getDatabaseStatus();

    // If explicit in-memory demo mode, store in L1 only and mark as demo
    if (isDemoModeExplicit() && !status.connected) {
      inMemoryL1Cache.set(cacheKey, {
        cache_key: cacheKey,
        provider,
        indicator_type: indicatorType,
        indicator_value: indicatorValue,
        response_json: responseJson,
        created_at: createdAt,
        expires_at: expiresAt,
        persisted_to_db: false,
      });
      return {
        persisted: false,
        storage: 'IN_MEMORY_DEMO',
        cache_key: cacheKey,
      };
    }

    // Normal MVP mode: PostgreSQL is the authoritative persistent store
    assertDatabaseAccessible();

    try {
      await query(
        `
        INSERT INTO intelligence_cache (
          cache_key, provider, indicator_type, indicator_value, response_json, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (cache_key) DO UPDATE SET
          response_json = EXCLUDED.response_json,
          expires_at = EXCLUDED.expires_at
      `,
        [
          cacheKey,
          provider,
          indicatorType,
          indicatorValue,
          JSON.stringify(responseJson),
          expiresAt,
        ]
      );

      // Populate L1 cache as short-lived performance layer
      inMemoryL1Cache.set(cacheKey, {
        cache_key: cacheKey,
        provider,
        indicator_type: indicatorType,
        indicator_value: indicatorValue,
        response_json: responseJson,
        created_at: createdAt,
        expires_at: expiresAt,
        persisted_to_db: true,
      });

      return {
        persisted: true,
        storage: 'POSTGRESQL',
        cache_key: cacheKey,
      };
    } catch (err: any) {
      // In normal MVP mode, database write failures must not be silently masked
      throw new Error(`Failed to persist intelligence cache entry to PostgreSQL: ${err.message}`);
    }
  }

  clearInMemoryL1(): void {
    inMemoryL1Cache.clear();
  }
}

export const intelligenceCacheRepository = new IntelligenceCacheRepository();


