import { AsyncLocalStorage } from 'node:async_hooks';
import type { Request } from 'express';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'fatal';
export type LogContext = Record<string, any>;

const contextStore = new AsyncLocalStorage<LogContext>();

const SECRET_KEY_PATTERNS = [
  'password',
  'passcode',
  'pin',
  'secret',
  'token',
  'authorization',
  'api_key',
  'apikey',
  'client_secret',
  'connection_secret',
  'webhook_secret',
  'refresh_token',
  'access_token',
  'otp',
  'cvv',
  'cvc',
  'card',
  'pan',
  'jwt',
  'cookie',
  'session',
];

const PII_KEY_PATTERNS = [
  'email',
  'phone',
  'mobile',
  'full_name',
  'address',
  'dob',
  'birth',
  'national_id',
  'passport',
  'account_number',
  'accountnumber',
  'recipient',
  'contact',
];

function isPlainObject(value: unknown): value is Record<string, any> {
  return !!value && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Error) && !(value instanceof Date);
}

function maskEmail(value: string): string {
  const [local, domain] = value.split('@');
  if (!domain) return '[REDACTED_EMAIL]';
  const head = local.slice(0, 2);
  return `${head || '*'}***@${domain}`;
}

function maskPhone(value: string): string {
  const digits = value.replace(/\D/g, '');
  if (digits.length < 4) return '[REDACTED_PHONE]';
  return `***${digits.slice(-4)}`;
}

function keyLooksSensitive(key: string): boolean {
  const normalized = key.toLowerCase();
  return SECRET_KEY_PATTERNS.some(pattern => normalized.includes(pattern));
}

function keyLooksPII(key: string): boolean {
  const normalized = key.toLowerCase();
  return PII_KEY_PATTERNS.some(pattern => normalized.includes(pattern));
}

function redactScalar(key: string, value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value !== 'string') return value;

  if (keyLooksSensitive(key)) return '[REDACTED]';
  if (keyLooksPII(key)) {
    if (value.includes('@')) return maskEmail(value);
    if (/^[+\d\s().-]{7,}$/.test(value)) return maskPhone(value);
    return '[REDACTED_PII]';
  }

  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return maskEmail(value);
  if (/^\+?[\d\s().-]{10,}$/.test(value)) return maskPhone(value);
  return value;
}

function serializeError(error: unknown): Record<string, any> {
  if (error instanceof Error) {
    const anyError = error as any;
    return redactObject({
      name: error.name,
      message: error.message,
      stack: error.stack,
      code: anyError.code,
      statusCode: anyError.statusCode,
      details: anyError.details,
      cause: anyError.cause,
    }) as Record<string, any>;
  }
  return { message: String(error) };
}

function redactObject(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[TRUNCATED]';
  if (value === null || value === undefined) return value;
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Error) return serializeError(value);
  if (Array.isArray(value)) return value.map(item => redactObject(item, depth + 1));
  if (!isPlainObject(value)) return value;

  const out: Record<string, any> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (keyLooksSensitive(key)) {
      out[key] = '[REDACTED]';
      continue;
    }
    if (typeof raw === 'string') {
      out[key] = redactScalar(key, raw);
      continue;
    }
    out[key] = redactObject(raw, depth + 1);
  }
  return out;
}

function write(level: LogLevel, payload: Record<string, any>) {
  const line = JSON.stringify(redactObject(payload));
  if (level === 'error' || level === 'fatal') {
    process.stderr.write(`${line}\n`);
    return;
  }
  process.stdout.write(`${line}\n`);
}

function currentContext(): LogContext {
  return contextStore.getStore() || {};
}

export function withLogContext<T>(context: LogContext, fn: () => T): T {
  return contextStore.run({ ...currentContext(), ...context }, fn);
}

export function mergeLogContext(context: LogContext) {
  const next = { ...currentContext(), ...context };
  contextStore.enterWith(next);
}

export function getLogContext(): LogContext {
  return currentContext();
}

export class StructuredLogger {
  constructor(private readonly baseContext: LogContext = {}) {}

  child(context: LogContext) {
    return new StructuredLogger({ ...this.baseContext, ...context });
  }

  debug(message: string, context?: LogContext) {
    this.log('debug', message, context);
  }

  info(message: string, context?: LogContext) {
    this.log('info', message, context);
  }

  warn(message: string, context?: LogContext) {
    this.log('warn', message, context);
  }

  error(message: string, context?: LogContext, error?: unknown) {
    this.log('error', message, context, error);
  }

  fatal(message: string, context?: LogContext, error?: unknown) {
    this.log('fatal', message, context, error);
  }

  private log(level: LogLevel, message: string, context?: LogContext, error?: unknown) {
    write(level, {
      timestamp: new Date().toISOString(),
      level,
      message,
      service: 'orbi-sovereign-backend',
      environment: process.env.NODE_ENV || 'development',
      ...currentContext(),
      ...this.baseContext,
      ...(context ? (redactObject(context) as Record<string, any>) : {}),
      ...(error ? { error: serializeError(error) } : {}),
    });
  }
}

export const logger = new StructuredLogger();

export function buildRequestLogContext(req: Request, extra: LogContext = {}): LogContext {
  const body = (req as any).body || {};
  const session = (req as any).session || {};
  return {
    trace_id: (req as any).traceId || req.get('x-trace-id') || req.get('x-request-id'),
    request_id: req.get('x-request-id') || undefined,
    correlation_id: req.get('x-correlation-id') || body.correlationId || body.correlation_id,
    transaction_id: body.transactionId || body.transaction_id || req.params?.transactionId,
    reference_id: body.referenceId || body.reference_id || body.reference,
    actor_id: session.sub || session.user?.id || body.userId || body.user_id,
    route: req.originalUrl,
    method: req.method,
    ...extra,
  };
}
