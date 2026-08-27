import { describe, it, expect } from 'vitest';
import { logger, sanitize } from '../server/logger';
import { auditRepository } from '../server/db/repositories/auditRepository';
import { AuditEvent } from '../src/types';

describe('Audit Logging & Secret Redaction', () => {
  it('should redact sensitive keys (password, token, apiKey, secret) in log payloads', () => {
    const sensitiveData = {
      user_id: 'usr_soc_01',
      api_key: 'vt_live_secret_key_abcdef123456',
      token: 'jwt.bearer.secret_token',
      password: 'super_secure_pass_123',
      nested: {
        authorization: 'Bearer secret_token_value',
        normal_data: 'safe_to_log',
      },
    };

    const sanitized = sanitize(sensitiveData);
    expect(sanitized.api_key).toBe('[REDACTED]');
    expect(sanitized.token).toBe('[REDACTED]');
    expect(sanitized.password).toBe('[REDACTED]');
    expect(sanitized.nested.authorization).toBe('[REDACTED]');
    expect(sanitized.nested.normal_data).toBe('safe_to_log');
  });

  it('should record structured audit events with actor and target', async () => {
    process.env.IN_MEMORY_DEMO_MODE = 'true';

    const event: AuditEvent = {
      id: `audit_test_${Date.now()}`,
      timestamp: new Date().toISOString(),
      user_id: 'usr_soc_01',
      user_email: 'krithik.forensics@defense.gov.in',
      user_role: 'ADMIN',
      action: 'QUARANTINE_EMAIL',
      target_type: 'EMAIL',
      target_id: 'email_target_123',
      details: 'Quarantined malicious payload email',
      ip_address: '192.168.1.50',
    };

    await auditRepository.log(event);
    const logs = await auditRepository.getAll(10);
    const found = logs.find((l) => l.id === event.id);

    expect(found).toBeDefined();
    expect(found?.user_role).toBe('ADMIN');
    expect(found?.action).toBe('QUARANTINE_EMAIL');
    expect(found?.target_id).toBe('email_target_123');
  });
});
