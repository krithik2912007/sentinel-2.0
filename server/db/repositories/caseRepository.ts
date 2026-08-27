import { query, getDatabaseStatus, assertDatabaseAccessible } from '../pool';
import { CaseRecord, CaseNote, CasePriority, CaseStatus } from '../../../src/types';

const inMemoryCases: Map<string, CaseRecord> = new Map();

export class CaseRepository {
  async getAll(): Promise<CaseRecord[]> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      return Array.from(inMemoryCases.values()).sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      );
    }


    const res = await query(`
      SELECT 
        c.id, c.case_number, c.title, c.description, c.status, c.priority,
        c.created_by, c.created_by_name, c.assigned_to, c.tags, c.notes,
        c.created_at, c.updated_at,
        COALESCE(ARRAY_AGG(ce.email_id) FILTER (WHERE ce.email_id IS NOT NULL), '{}') as email_ids
      FROM cases c
      LEFT JOIN case_emails ce ON c.id = ce.case_id
      GROUP BY c.id
      ORDER BY c.created_at DESC
    `);

    return res.rows.map((r) => ({
      id: r.id,
      case_number: r.case_number,
      title: r.title,
      description: r.description,
      status: r.status as CaseStatus,
      priority: r.priority as CasePriority,
      created_by: r.created_by,
      created_by_name: r.created_by_name,
      assigned_to: r.assigned_to,
      tags: r.tags || [],
      notes: r.notes || [],
      created_at: new Date(r.created_at).toISOString(),
      updated_at: new Date(r.updated_at).toISOString(),
      email_ids: r.email_ids || [],
    }));
  }

  async getById(id: string): Promise<CaseRecord | null> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      return inMemoryCases.get(id) || null;
    }

    const res = await query(

      `
      SELECT 
        c.id, c.case_number, c.title, c.description, c.status, c.priority,
        c.created_by, c.created_by_name, c.assigned_to, c.tags, c.notes,
        c.created_at, c.updated_at,
        COALESCE(ARRAY_AGG(ce.email_id) FILTER (WHERE ce.email_id IS NOT NULL), '{}') as email_ids
      FROM cases c
      LEFT JOIN case_emails ce ON c.id = ce.case_id
      WHERE c.id = $1
      GROUP BY c.id
    `,
      [id]
    );

    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
      id: r.id,
      case_number: r.case_number,
      title: r.title,
      description: r.description,
      status: r.status as CaseStatus,
      priority: r.priority as CasePriority,
      created_by: r.created_by,
      created_by_name: r.created_by_name,
      assigned_to: r.assigned_to,
      tags: r.tags || [],
      notes: r.notes || [],
      created_at: new Date(r.created_at).toISOString(),
      updated_at: new Date(r.updated_at).toISOString(),
      email_ids: r.email_ids || [],
    };
  }

  async save(c: CaseRecord): Promise<CaseRecord> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      inMemoryCases.set(c.id, c);
      return c;
    }

    await query(

      `
      INSERT INTO cases (
        id, case_number, title, description, status, priority,
        created_by, created_by_name, assigned_to, tags, notes,
        created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        status = EXCLUDED.status,
        priority = EXCLUDED.priority,
        assigned_to = EXCLUDED.assigned_to,
        tags = EXCLUDED.tags,
        notes = EXCLUDED.notes,
        updated_at = NOW()
    `,
      [
        c.id,
        c.case_number,
        c.title,
        c.description,
        c.status,
        c.priority,
        c.created_by,
        c.created_by_name,
        c.assigned_to || null,
        c.tags,
        JSON.stringify(c.notes || []),
        c.created_at,
        c.updated_at,
      ]
    );

    if (c.email_ids && c.email_ids.length > 0) {
      for (const emailId of c.email_ids) {
        await query(
          'INSERT INTO case_emails (case_id, email_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [c.id, emailId]
        );
      }
    }

    return c;
  }

  async patch(
    id: string,
    updates: Partial<{ status: CaseStatus; priority: CasePriority; assigned_to: string; tags: string[] }>
  ): Promise<CaseRecord | null> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      const c = inMemoryCases.get(id);
      if (!c) return null;
      if (updates.status) c.status = updates.status;
      if (updates.priority) c.priority = updates.priority;
      if (updates.assigned_to !== undefined) c.assigned_to = updates.assigned_to;
      if (updates.tags) c.tags = updates.tags;
      c.updated_at = new Date().toISOString();
      return c;
    }

    const current = await this.getById(id);
    if (!current) return null;

    const newStatus = updates.status || current.status;
    const newPriority = updates.priority || current.priority;
    const newAssigned = updates.assigned_to !== undefined ? updates.assigned_to : current.assigned_to;
    const newTags = updates.tags || current.tags;

    await query(
      `
      UPDATE cases SET
        status = $1,
        priority = $2,
        assigned_to = $3,
        tags = $4,
        updated_at = NOW()
      WHERE id = $5
    `,
      [newStatus, newPriority, newAssigned, newTags, id]
    );

    return this.getById(id);
  }

  async addNote(id: string, note: CaseNote): Promise<CaseRecord | null> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      const c = inMemoryCases.get(id);
      if (!c) return null;
      if (!c.notes) c.notes = [];
      c.notes.push(note);
      c.updated_at = new Date().toISOString();
      return c;
    }

    const current = await this.getById(id);
    if (!current) return null;

    const notes = current.notes || [];
    notes.push(note);

    await query(
      'UPDATE cases SET notes = $1, updated_at = NOW() WHERE id = $2',
      [JSON.stringify(notes), id]
    );

    return this.getById(id);
  }

  async attachEmail(caseId: string, emailId: string): Promise<void> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      const c = inMemoryCases.get(caseId);
      if (c && !c.email_ids.includes(emailId)) {
        c.email_ids.push(emailId);
      }
      return;
    }

    await query(
      'INSERT INTO case_emails (case_id, email_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [caseId, emailId]
    );
  }

  async count(): Promise<number> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      return inMemoryCases.size;
    }
    const res = await query('SELECT COUNT(*) as cnt FROM cases');
    return parseInt(res.rows[0].cnt, 10);
  }

}

export const caseRepository = new CaseRepository();
