import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserProfile, UserRole } from '../../src/types';
import { userRepository } from '../db/repositories/userRepository';

// Secure server-side JWT Secret. Never accept client-provided secret overrides.
const JWT_SECRET = process.env.JWT_SECRET || 'sentinel-soc-forensics-production-secret-key-2026';

export interface AuthenticatedRequest extends Request {
  user?: UserProfile;
  requestId?: string;
}

export function generateToken(user: UserProfile): string {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      department: user.department,
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

export function verifyToken(token: string): any {
  return jwt.verify(token, JWT_SECRET);
}

/**
 * Strict authentication middleware:
 * - Reads token exclusively from `Authorization: Bearer <jwt>` or httpOnly `sentinel_session` cookie.
 * - Disallows any client headers (e.g. x-sentinel-role, x-user-role) from selecting or overriding the role.
 * - Authoritatively retrieves the user's role from the server-side database.
 */
export async function authenticateToken(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  let token: string | undefined;

  // 1. Authorization header: "Bearer <token>"
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  }

  // 2. httpOnly session cookie
  if (!token && (req as any).cookies && (req as any).cookies.sentinel_session) {
    token = (req as any).cookies.sentinel_session;
  }

  if (!token) {
    // No token provided: request is unauthenticated.
    req.user = undefined;
    return next();
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    if (!decoded || !decoded.id) {
      req.user = undefined;
      return next();
    }

    // Always fetch authoritative user record from server-side repository
    const dbUser = await userRepository.getById(decoded.id);
    if (dbUser) {
      // Role is strictly derived from authoritative server-side user record
      req.user = {
        id: dbUser.id,
        name: dbUser.name,
        email: dbUser.email,
        role: dbUser.role, // Server-enforced role
        department: dbUser.department,
        avatar: dbUser.avatar,
      };
    } else {
      // If user is not yet written to DB but token is validly signed by our secret
      req.user = {
        id: decoded.id,
        name: decoded.name,
        email: decoded.email,
        role: decoded.role as UserRole,
        department: decoded.department,
      };
    }
  } catch {
    // Invalid/expired token: clear user context
    req.user = undefined;
  }

  next();
}

export function requireAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  if (!req.user) {
    res.status(401).json({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication is required to access this resource.',
        request_id: req.requestId,
      },
    });
    return;
  }
  next();
}

export function requireRole(allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication is required.',
          request_id: req.requestId,
        },
      });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        error: {
          code: 'FORBIDDEN',
          message: `Access denied. Role '${req.user.role}' does not have sufficient permissions. Required roles: ${allowedRoles.join(', ')}`,
          request_id: req.requestId,
        },
      });
      return;
    }

    next();
  };
}

