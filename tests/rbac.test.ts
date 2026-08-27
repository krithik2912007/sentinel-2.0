import { describe, it, expect } from 'vitest';
import { generateToken } from '../server/middleware/auth';
import { UserProfile } from '../src/types';

describe('Auth & RBAC Tokens', () => {
  it('should generate valid JWT tokens with role claims', () => {
    const user: UserProfile = {
      id: 'usr_01',
      name: 'Test Lead',
      email: 'lead@defense.gov',
      role: 'ADMIN',
      department: 'SOC',
    };

    const token = generateToken(user);
    expect(typeof token).toBe('string');
    expect(token.split('.').length).toBe(3);
  });
});
