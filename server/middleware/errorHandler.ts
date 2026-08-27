import { Request, Response, NextFunction } from 'express';
import { logger } from '../logger';

export function errorHandler(
  err: any,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  const requestId = (req as any).requestId || `req_${Date.now()}`;
  const status = err.status || err.statusCode || 500;
  const code = err.code || 'INTERNAL_SERVER_ERROR';

  logger.error(`Unhandled error on ${req.method} ${req.path}`, err, {
    request_id: requestId,
    status,
    method: req.method,
    path: req.path,
  });

  // Never leak internal stack traces to clients in production
  res.status(status).json({
    error: {
      code,
      message: err.isPublic ? err.message : 'An internal error occurred during forensic processing.',
      request_id: requestId,
    },
  });
}
