import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { getDatabaseStatus, assertDatabaseAccessible, isDemoModeExplicit, resetDatabasePool } from '../server/db/pool';
import { caseRepository } from '../server/db/repositories/caseRepository';
import { userRepository } from '../server/db/repositories/userRepository';
import { emailRepository } from '../server/db/repositories/emailRepository';
import { auditRepository } from '../server/db/repositories/auditRepository';
import { CaseRecord, UserProfile } from '../src/types';

describe('Database Persistence & Mandatory PostgreSQL Enforcement', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    resetDatabasePool();
  });

  afterEach(() => {
    process.env = originalEnv;
    resetDatabasePool();
  });

  it('CRITICAL: Should throw an error when DB is unavailable and IN_MEMORY_DEMO_MODE is false (No silent fallback)', async () => {
    // Simulate normal MVP production environment where PostgreSQL is not connected
    process.env = {
      ...originalEnv,
      DEMO_MODE: 'false',
      IN_MEMORY_DEMO_MODE: 'false',
      DATABASE_URL: '',
    };

    expect(isDemoModeExplicit()).toBe(false);

    // Calling assertDatabaseAccessible directly must throw
    expect(() => assertDatabaseAccessible()).toThrow(/Database unavailable: PostgreSQL connection required/i);

    // Repository operations must fail clearly with an error rather than silently falling back
    await expect(caseRepository.getAll()).rejects.toThrow(/PostgreSQL connection required/i);
    await expect(userRepository.getById('usr_soc_01')).rejects.toThrow(/PostgreSQL connection required/i);
    await expect(emailRepository.getAll()).rejects.toThrow(/PostgreSQL connection required/i);
    await expect(auditRepository.getAll()).rejects.toThrow(/PostgreSQL connection required/i);
  });

  it('Should activate in-memory store ONLY when explicitly enabled via IN_MEMORY_DEMO_MODE=true', async () => {
    process.env = {
      ...originalEnv,
      IN_MEMORY_DEMO_MODE: 'true',
      DEMO_MODE: 'false',
    };

    expect(isDemoModeExplicit()).toBe(true);

    const status = getDatabaseStatus();
    expect(status.demoMode).toBe(true);

    // In demo mode, assertDatabaseAccessible does not throw
    expect(() => assertDatabaseAccessible()).not.toThrow();

    // In-memory repositories function as expected in explicit demo mode
    const testUser: UserProfile = {
      id: 'usr_test_demo_01',
      name: 'Demo Tester',
      email: 'demo@tester.corp',
      role: 'ANALYST',
      department: 'SOC',
    };

    await userRepository.save(testUser);
    const retrieved = await userRepository.getById('usr_test_demo_01');
    expect(retrieved).toBeDefined();
    expect(retrieved?.email).toBe('demo@tester.corp');
  });

  it('Should store, retrieve, and update case records with relational email attachments', async () => {
    process.env = {
      ...originalEnv,
      IN_MEMORY_DEMO_MODE: 'true',
    };

    const caseId = `case_persist_${Date.now()}`;
    const newCase: CaseRecord = {
      id: caseId,
      case_number: 'SEC-2026-999',
      title: 'Phishing Campaign Persistence Test',
      description: 'Verifying case lifecycle',
      status: 'OPEN',
      priority: 'HIGH',
      created_by: 'usr_soc_01',
      created_by_name: 'Agent Krithik',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      email_ids: ['email_persisted_01'],
      tags: ['Test', 'Forensics'],
      notes: [],
    };

    await caseRepository.save(newCase);

    const fetched = await caseRepository.getById(caseId);
    expect(fetched).toBeDefined();
    expect(fetched?.title).toBe('Phishing Campaign Persistence Test');
    expect(fetched?.email_ids).toContain('email_persisted_01');

    // Patch status and priority
    await caseRepository.patch(caseId, { status: 'RESOLVED', priority: 'CRITICAL' });
    const updated = await caseRepository.getById(caseId);
    expect(updated?.status).toBe('RESOLVED');
    expect(updated?.priority).toBe('CRITICAL');

    // Add case note
    await caseRepository.addNote(caseId, {
      id: 'note_101',
      author: 'Agent Krithik',
      author_role: 'ADMIN',
      text: 'Incident contained.',
      timestamp: new Date().toISOString(),
    });

    const withNote = await caseRepository.getById(caseId);
    expect(withNote?.notes.length).toBe(1);
    expect(withNote?.notes[0].text).toBe('Incident contained.');
  });
});
