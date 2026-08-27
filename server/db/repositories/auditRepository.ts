import { query, getDatabaseStatus, assertDatabaseAccessible } from '../pool';
import { AuditEvent, UserRole } from '../../../src/types';

const inMemoryLogs: AuditEvent[] = [];

export class AuditRepository {
  async getAll(limit = 100): Promise<AuditEvent[]> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      return [...inMemoryLogs].sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      ).slice(0, limit);
    }

    const res = await query(
      `SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT $1`,
      [limit]
    );

    return res.rows.map((r) => ({
      id: r.id,
      timestamp: new Date(r.timestamp).toISOString(),
      user_id: r.user_id,
      user_email: r.user_email,
      user_role: r.user_role as UserRole,
      action: r.action,
      target_type: r.target_type,
      target_id: r.target_id,
      details: r.details,
      ip_address: r.ip_address,
    }));
  }

  async log(event: AuditEvent): Promise<AuditEvent> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      inMemoryLogs.unshift(event);
      return event;
    }

    await query(
      `
      INSERT INTO audit_events (
        id, timestamp, user_id, user_email, user_role,
        action, target_type, target_id, details, ip_address
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `,
      [
        event.id,
        event.timestamp,
        event.user_id,
        event.user_email,
        event.user_role,
        event.action,
        event.target_type,
        event.target_id,
        event.details,
        event.ip_address,
      ]
    );

    return event;
  }
}

export const auditRepository = new AuditRepository();

