import pg from 'pg';
const { Pool } = pg;

let pool: pg.Pool | null = null;
let isConnected = false;
let lastError: string | null = null;

export function isDemoModeExplicit(): boolean {
  return process.env.DEMO_MODE === 'true' || process.env.IN_MEMORY_DEMO_MODE === 'true';
}

export function getDatabasePool(): pg.Pool {
  if (pool) return pool;

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    lastError = 'DATABASE_URL is not defined in environment';
    if (!isDemoModeExplicit()) {
      console.error('[DB] DATABASE_URL is missing and DEMO_MODE is not enabled. PostgreSQL is required for normal MVP operation.');
    }
    // Return an unconfigured pool that will fail queries if called
    pool = new Pool({ connectionString: 'postgresql://localhost:5432/unconfigured' });
    return pool;
  }

  const useSsl = process.env.DB_SSL === 'true' || connectionString.includes('sslmode=require');
  
  pool = new Pool({
    connectionString,
    ssl: useSsl ? { rejectUnauthorized: false } : undefined,
    max: parseInt(process.env.DB_POOL_MAX || '10', 10),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  pool.on('error', (err) => {
    console.error('[DB Pool Error]', err);
    isConnected = false;
    lastError = err.message;
  });

  return pool;
}

export async function testDatabaseConnection(): Promise<{ connected: boolean; error?: string }> {
  if (isDemoModeExplicit() && !process.env.DATABASE_URL) {
    return { connected: false, error: 'Running in explicit DEMO_MODE without DATABASE_URL' };
  }

  try {
    const p = getDatabasePool();
    const client = await p.connect();
    try {
      await client.query('SELECT 1 AS health_check');
      isConnected = true;
      lastError = null;
      return { connected: true };
    } finally {
      client.release();
    }
  } catch (err: any) {
    isConnected = false;
    lastError = err?.message || 'Failed to connect to PostgreSQL';
    return { connected: false, error: lastError || undefined };
  }
}

export function getDatabaseStatus(): { connected: boolean; demoMode: boolean; error: string | null } {
  return {
    connected: isConnected,
    demoMode: isDemoModeExplicit(),
    error: lastError,
  };
}

export function assertDatabaseAccessible(): void {
  const status = getDatabaseStatus();
  if (!status.connected && !status.demoMode) {
    throw new Error(
      'Database unavailable: PostgreSQL connection required in normal MVP mode. Set IN_MEMORY_DEMO_MODE=true only for standalone demo/testing.'
    );
  }
}

export function resetDatabasePool(): void {
  if (pool) {
    try {
      pool.end();
    } catch {}
    pool = null;
  }
  isConnected = false;
  lastError = null;
}

export async function query<T = any>(text: string, params?: any[]): Promise<pg.QueryResult<T>> {
  assertDatabaseAccessible();
  const p = getDatabasePool();
  return p.query<T>(text, params);
}

