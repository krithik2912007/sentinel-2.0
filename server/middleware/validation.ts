import { Request, Response, NextFunction } from 'express';
import { z, ZodError } from 'zod';

export function validateBody(schema: z.ZodTypeAny) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (err) {
      if (err instanceof ZodError) {
        res.status(400).json({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid request payload format or missing required fields.',
            details: err.issues.map((e) => ({
              path: e.path.join('.'),
              message: e.message,
            })),
            request_id: (req as any).requestId,
          },
        });
        return;
      }
      next(err);
    }
  };
}

export function validateQuery(schema: z.ZodTypeAny) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      req.query = schema.parse(req.query) as any;
      next();
    } catch (err) {
      if (err instanceof ZodError) {
        res.status(400).json({
          error: {
            code: 'QUERY_VALIDATION_ERROR',
            message: 'Invalid query parameters.',
            details: err.issues.map((e) => ({
              path: e.path.join('.'),
              message: e.message,
            })),
            request_id: (req as any).requestId,
          },
        });
        return;
      }
      next(err);
    }
  };
}

// Common Zod Schemas
export const AnalyzeEmailSchema = z.object({
  raw_eml: z.string().min(10, 'Raw EML source is required and must exceed 10 bytes'),
  case_id: z.string().optional(),
});

export const BatchAnalyzeSchema = z.object({
  emails: z
    .array(
      z.object({
        raw_eml: z.string().min(10, 'Each email must contain raw EML text'),
        case_id: z.string().optional(),
        file_name: z.string().optional(),
      })
    )
    .min(1, 'Batch must contain at least 1 email')
    .max(50, 'Batch maximum is 50 emails per submission')
    .optional(),
  raw_emls: z
    .array(z.string().min(10, 'Each email must contain raw EML text'))
    .min(1, 'Batch must contain at least 1 email')
    .max(50, 'Batch maximum is 50 emails per submission')
    .optional(),
  case_id: z.string().optional(),
}).refine((data) => (data.emails && data.emails.length > 0) || (data.raw_emls && data.raw_emls.length > 0), {
  message: 'Either emails array or raw_emls array must be provided.',
});

export const CreateCaseSchema = z.object({
  title: z.string().min(3, 'Title must be at least 3 characters'),
  description: z.string().optional().default(''),
  priority: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).default('MEDIUM'),
  tags: z.array(z.string()).optional().default([]),
  assigned_to: z.string().optional(),
});

export const PatchCaseSchema = z.object({
  status: z.enum(['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED']).optional(),
  priority: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).optional(),
  assigned_to: z.string().optional(),
  tags: z.array(z.string()).optional(),
});

export const AddCaseNoteSchema = z.object({
  text: z.string().min(1, 'Note content cannot be empty'),
});

export const ResponseActionSchema = z.object({
  reason: z.string().optional(),
  target_mailbox: z.string().optional(),
  preferred_provider: z.enum(['m365', 'google', 'simulation', 'auto']).optional(),
  simulation_mode: z.boolean().optional(),
});

export const BulkResponseActionSchema = z.object({
  action: z.enum(['QUARANTINE', 'BLOCK_SENDER', 'PURGE']),
  email_ids: z.array(z.string()).min(1, 'At least 1 email ID is required'),
  reason: z.string().optional(),
  preferred_provider: z.enum(['m365', 'google', 'simulation', 'auto']).optional(),
  simulation_mode: z.boolean().optional(),
});

export const IntelligenceLookupSchema = z.object({
  type: z.enum(['IP', 'DOMAIN', 'HASH', 'URL']),
  indicator: z.string().min(1, 'Indicator value is required'),
});
