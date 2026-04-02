import { z } from 'zod';

export const queryStringValue = (value: unknown) => {
  if (Array.isArray(value)) {
    return value.length ? String(value[0]) : undefined;
  }
  if (typeof value === 'string') {
    return value;
  }
  return undefined;
};

export const TransactionIssueSchema = z.object({
  reason: z.string().min(5).max(500),
});

export const TransactionAuditDecisionSchema = z.object({
  passed: z.boolean(),
  notes: z.string().min(3).max(500),
});
