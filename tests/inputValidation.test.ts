import { describe, it, expect } from 'vitest';
import {
  AnalyzeEmailSchema,
  CreateCaseSchema,
  PatchCaseSchema,
  ResponseActionSchema,
} from '../server/middleware/validation';

describe('Zod Input Validation Middleware Schemas', () => {
  it('should validate valid raw email analysis payload', () => {
    const valid = {
      raw_eml: 'From: a@b.com\nTo: c@d.com\nSubject: Test\n\nHello world',
      case_id: 'case_123',
    };

    const res = AnalyzeEmailSchema.safeParse(valid);
    expect(res.success).toBe(true);
  });

  it('should reject empty or missing raw_eml in analysis request', () => {
    const invalid = {
      raw_eml: '',
    };

    const res = AnalyzeEmailSchema.safeParse(invalid);
    expect(res.success).toBe(false);
  });

  it('should validate case creation with valid priorities and reject invalid priority', () => {
    const valid = {
      title: 'Investigate BEC Incident',
      description: 'Urgent investigation',
      priority: 'HIGH',
      tags: ['BEC', 'Finance'],
    };
    expect(CreateCaseSchema.safeParse(valid).success).toBe(true);

    const invalid = {
      title: 'Short',
      priority: 'SUPER_URGENT_INVALID',
    };
    expect(CreateCaseSchema.safeParse(invalid).success).toBe(false);
  });

  it('should validate case patch payload', () => {
    const validPatch = {
      status: 'INVESTIGATING',
      priority: 'CRITICAL',
    };
    expect(PatchCaseSchema.safeParse(validPatch).success).toBe(true);

    const invalidStatus = {
      status: 'NOT_A_VALID_STATUS',
    };
    expect(PatchCaseSchema.safeParse(invalidStatus).success).toBe(false);
  });

  it('should validate response actions (QUARANTINE, BLOCK_SENDER, PURGE)', () => {
    expect(ResponseActionSchema.safeParse({ reason: 'Malicious IOC verified' }).success).toBe(true);
  });
});
