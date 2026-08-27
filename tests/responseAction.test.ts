import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { responseManager } from '../server/response/responseManager';

describe('Response Action Execution', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv, IN_MEMORY_DEMO_MODE: 'true' };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should execute simulation quarantine and return SIMULATED status', async () => {
    const res = await responseManager.quarantine({
      emailId: 'email_test_101',
      senderEmail: 'attacker@bad.com',
      actorId: 'usr_soc_01',
      actorEmail: 'admin@soc.corp',
      actorRole: 'ADMIN',
    });

    expect(res.status).toBe('SIMULATED');
    expect(res.action).toBe('QUARANTINE');
    expect(res.target_id).toBe('email_test_101');
  });

  it('should execute simulation block sender and return SIMULATED status', async () => {
    const res = await responseManager.blockSender({
      emailId: 'email_test_102',
      senderEmail: 'scammer@fake-domain.xyz',
      actorId: 'usr_soc_01',
      actorEmail: 'admin@soc.corp',
      actorRole: 'ADMIN',
    });

    expect(res.status).toBe('SIMULATED');
    expect(res.action).toBe('BLOCK_SENDER');
  });
});

