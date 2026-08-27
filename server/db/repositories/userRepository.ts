import { query, getDatabaseStatus, assertDatabaseAccessible } from '../pool';
import { UserProfile, UserRole } from '../../../src/types';

const inMemoryUsers: Map<string, UserProfile> = new Map([
  [
    'usr_soc_01',
    {
      id: 'usr_soc_01',
      name: 'Agent Krithik (Lead Forensics)',
      email: 'krithik.forensics@defense.gov.in',
      role: 'ADMIN',
      avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150',
      department: 'CERT / Cyber Defense Incident Response',
    },
  ],
  [
    'usr_soc_02',
    {
      id: 'usr_soc_02',
      name: 'Analyst Sarah Chen',
      email: 'sarah.chen@defense.gov.in',
      role: 'ANALYST',
      avatar: 'https://images.unsplash.com/photo-1580489944761-15a19d654956?w=150',
      department: 'SOC Tier 2 Forensics',
    },
  ],
  [
    'usr_soc_03',
    {
      id: 'usr_soc_03',
      name: 'Auditor David Vance',
      email: 'david.vance@defense.gov.in',
      role: 'VIEWER',
      avatar: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150',
      department: 'Compliance & Audit',
    },
  ],
]);

export class UserRepository {
  async getById(id: string): Promise<UserProfile | null> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      return inMemoryUsers.get(id) || null;
    }

    const res = await query(
      'SELECT id, name, email, role, department FROM users WHERE id = $1',
      [id]
    );
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
      id: r.id,
      name: r.name,
      email: r.email,
      role: r.role as UserRole,
      department: r.department,
    };
  }

  async getByEmail(email: string): Promise<UserProfile | null> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      for (const u of inMemoryUsers.values()) {
        if (u.email.toLowerCase() === email.toLowerCase()) return u;
      }
      return null;
    }

    const res = await query(
      'SELECT id, name, email, role, department FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
      id: r.id,
      name: r.name,
      email: r.email,
      role: r.role as UserRole,
      department: r.department,
    };
  }

  async save(user: UserProfile): Promise<UserProfile> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      inMemoryUsers.set(user.id, user);
      return user;
    }

    await query(
      `INSERT INTO users (id, name, email, role, department, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (id) DO UPDATE SET
         name = EXCLUDED.name,
         email = EXCLUDED.email,
         role = EXCLUDED.role,
         department = EXCLUDED.department,
         updated_at = NOW()`,
      [user.id, user.name, user.email, user.role, user.department]
    );
    return user;
  }

  async updateRole(id: string, role: UserRole): Promise<UserProfile | null> {
    const status = getDatabaseStatus();
    if (!status.connected) {
      assertDatabaseAccessible();
      const u = inMemoryUsers.get(id);
      if (u) {
        u.role = role;
        return u;
      }
      return null;
    }

    const res = await query(
      'UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2 RETURNING id, name, email, role, department',
      [role, id]
    );
    if (res.rows.length === 0) return null;
    const r = res.rows[0];
    return {
      id: r.id,
      name: r.name,
      email: r.email,
      role: r.role as UserRole,
      department: r.department,
    };
  }
}


export const userRepository = new UserRepository();
