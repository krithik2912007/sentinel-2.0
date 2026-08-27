import fs from 'fs';
import path from 'path';
import { getDatabasePool, isDemoModeExplicit } from './pool';

export async function runMigrations(): Promise<{ success: boolean; applied: string[]; error?: string }> {
  if (isDemoModeExplicit() && !process.env.DATABASE_URL) {
    console.log('[Migrations] Skipping PostgreSQL migrations: DEMO_MODE is explicitly enabled without DATABASE_URL.');
    return { success: true, applied: [] };
  }

  const pool = getDatabasePool();
  const client = await pool.connect();
  const applied: string[] = [];

  try {
    // 1. Create migrations tracking table
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(255) PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // 2. Read all migration files
    const migrationsDir = path.join(process.cwd(), 'server', 'db', 'migrations');
    if (!fs.existsSync(migrationsDir)) {
      console.warn(`[Migrations] Directory not found: ${migrationsDir}`);
      return { success: true, applied: [] };
    }

    const files = fs.readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql'))
      .sort();

    // 3. Query already applied migrations
    const res = await client.query<{ version: string }>('SELECT version FROM schema_migrations');
    const existing = new Set(res.rows.map((r) => r.version));

    // 4. Apply each missing migration in transaction
    for (const file of files) {
      if (!existing.has(file)) {
        console.log(`[Migrations] Applying ${file}...`);
        const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
        
        await client.query('BEGIN');
        try {
          await client.query(sql);
          await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [file]);
          await client.query('COMMIT');
          applied.push(file);
          console.log(`[Migrations] Applied ${file} successfully.`);
        } catch (err: any) {
          await client.query('ROLLBACK');
          console.error(`[Migrations] Failed on ${file}:`, err);
          throw new Error(`Migration ${file} failed: ${err.message}`);
        }
      }
    }

    return { success: true, applied };
  } catch (err: any) {
    console.error('[Migrations Error]', err);
    return { success: false, applied, error: err.message };
  } finally {
    client.release();
  }
}
