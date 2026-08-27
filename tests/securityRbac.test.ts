import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import jwt from 'jsonwebtoken';
import { generateToken, authenticateToken, requireAuth, requireRole, AuthenticatedRequest } from '../server/middleware/auth';
import { userRepository } from '../server/db/repositories/userRepository';
import { UserProfile, UserRole } from '../src/types';

describe('Security & RBAC Protection', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv, IN_MEMORY_DEMO_MODE: 'true' };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should authenticate valid user from signed JWT and load server-side authoritative role', async () => {
    const viewerUser: UserProfile = {
      id: 'usr_soc_03',
      name: 'Auditor David Vance',
      email: 'david.vance@defense.gov.in',
      role: 'VIEWER',
      department: 'Compliance & Audit',
    };
    await userRepository.save(viewerUser);

    const token = generateToken(viewerUser);

    const req: Partial<AuthenticatedRequest> = {
      headers: {
        authorization: `Bearer ${token}`,
      },
    };
    let nextCalled = false;
    const res: any = {};

    await authenticateToken(req as AuthenticatedRequest, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(true);
    expect(req.user).toBeDefined();
    expect(req.user?.id).toBe('usr_soc_03');
    expect(req.user?.role).toBe('VIEWER');
  });

  it('CRITICAL SECURITY: VIEWER cannot become ANALYST or ADMIN by modifying request headers', async () => {
    const viewerUser: UserProfile = {
      id: 'usr_soc_03',
      name: 'Auditor David Vance',
      email: 'david.vance@defense.gov.in',
      role: 'VIEWER',
      department: 'Compliance & Audit',
    };
    await userRepository.save(viewerUser);
    const viewerToken = generateToken(viewerUser);

    // Attacker attempts header injection with various role spoofing headers
    const maliciousHeaders = {
      authorization: `Bearer ${viewerToken}`,
      'x-sentinel-role': 'ADMIN',
      'x-user-role': 'ADMIN',
      'x-role': 'ANALYST',
      'x-forwarded-role': 'ADMIN',
    };

    const req: Partial<AuthenticatedRequest> = {
      headers: maliciousHeaders,
    };
    let nextCalled = false;
    const res: any = {};

    await authenticateToken(req as AuthenticatedRequest, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(true);
    // Role MUST stay strictly VIEWER as derived authoritatively from server-side DB
    expect(req.user?.role).toBe('VIEWER');
    expect(req.user?.role).not.toBe('ADMIN');
    expect(req.user?.role).not.toBe('ANALYST');
  });

  it('CRITICAL SECURITY: ANALYST cannot become ADMIN by modifying request headers', async () => {
    const analystUser: UserProfile = {
      id: 'usr_soc_02',
      name: 'Analyst Sarah Chen',
      email: 'sarah.chen@defense.gov.in',
      role: 'ANALYST',
      department: 'SOC Tier 2 Forensics',
    };
    await userRepository.save(analystUser);
    const analystToken = generateToken(analystUser);

    const req: Partial<AuthenticatedRequest> = {
      headers: {
        authorization: `Bearer ${analystToken}`,
        'x-sentinel-role': 'ADMIN',
        'x-user-role': 'ADMIN',
      },
    };
    let nextCalled = false;
    const res: any = {};

    await authenticateToken(req as AuthenticatedRequest, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(true);
    // Must remain ANALYST
    expect(req.user?.role).toBe('ANALYST');
    expect(req.user?.role).not.toBe('ADMIN');
  });

  it('CRITICAL SECURITY: Forged JWT claims with invalid signature are rejected', async () => {
    // Attacker crafts a token with role ADMIN signed with a different secret
    const forgedToken = jwt.sign(
      {
        id: 'usr_attacker',
        email: 'attacker@evil.com',
        role: 'ADMIN',
      },
      'attacker-secret-key-123'
    );

    const req: Partial<AuthenticatedRequest> = {
      headers: {
        authorization: `Bearer ${forgedToken}`,
      },
    };
    let nextCalled = false;
    const res: any = {};

    await authenticateToken(req as AuthenticatedRequest, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(true);
    // req.user must remain undefined because signature verification failed
    expect(req.user).toBeUndefined();
  });

  it('CRITICAL SECURITY: requireAuth rejects unauthenticated requests with 401', () => {
    const req: Partial<AuthenticatedRequest> = {
      user: undefined,
      requestId: 'req_test_401',
    };

    let statusCode: number | null = null;
    let jsonBody: any = null;
    let nextCalled = false;

    const res: any = {
      status: (code: number) => {
        statusCode = code;
        return {
          json: (body: any) => {
            jsonBody = body;
          },
        };
      },
    };

    requireAuth(req as AuthenticatedRequest, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(false);
    expect(statusCode).toBe(401);
    expect(jsonBody?.error?.code).toBe('UNAUTHORIZED');
  });

  it('CRITICAL SECURITY: requireRole rejects unauthorized role with 403 Forbidden', () => {
    const req: Partial<AuthenticatedRequest> = {
      user: {
        id: 'usr_soc_03',
        name: 'Auditor Vance',
        email: 'vance@soc.gov',
        role: 'VIEWER',
        department: 'Audit',
      },
      requestId: 'req_test_403',
    };

    let statusCode: number | null = null;
    let jsonBody: any = null;
    let nextCalled = false;

    const res: any = {
      status: (code: number) => {
        statusCode = code;
        return {
          json: (body: any) => {
            jsonBody = body;
          },
        };
      },
    };

    // Guard requiring ADMIN or ANALYST
    const rbacGuard = requireRole(['ADMIN', 'ANALYST']);
    rbacGuard(req as AuthenticatedRequest, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(false);
    expect(statusCode).toBe(403);
    expect(jsonBody?.error?.code).toBe('FORBIDDEN');
    expect(jsonBody?.error?.message).toContain('VIEWER');
  });

  it('CRITICAL SECURITY: requireRole allows authorized roles to proceed', () => {
    const req: Partial<AuthenticatedRequest> = {
      user: {
        id: 'usr_soc_01',
        name: 'Agent Krithik',
        email: 'krithik@soc.gov',
        role: 'ADMIN',
        department: 'Forensics',
      },
      requestId: 'req_test_ok',
    };

    let nextCalled = false;
    const res: any = {};

    const rbacGuard = requireRole(['ADMIN']);
    rbacGuard(req as AuthenticatedRequest, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(true);
  });
});
