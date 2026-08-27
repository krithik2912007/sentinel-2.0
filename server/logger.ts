export interface LogContext {
  request_id?: string;
  user_id?: string;
  method?: string;
  path?: string;
  status?: number;
  duration_ms?: number;
  [key: string]: any;
}

const REDACT_KEYS = ['password', 'token', 'authorization', 'secret', 'api_key', 'apikey', 'key'];

export function sanitize(obj: any): any {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sanitize);

  const copy: Record<string, any> = {};
  for (const [k, v] of Object.entries(obj)) {
    const isSensitive = REDACT_KEYS.some((rk) => k.toLowerCase().includes(rk));
    if (isSensitive) {
      copy[k] = '[REDACTED]';
    } else if (typeof v === 'object' && v !== null) {
      copy[k] = sanitize(v);
    } else {
      copy[k] = v;
    }
  }
  return copy;
}


export class Logger {
  info(message: string, context?: LogContext): void {
    const entry = {
      level: 'INFO',
      timestamp: new Date().toISOString(),
      message,
      ...(context ? sanitize(context) : {}),
    };
    console.log(JSON.stringify(entry));
  }

  warn(message: string, context?: LogContext): void {
    const entry = {
      level: 'WARN',
      timestamp: new Date().toISOString(),
      message,
      ...(context ? sanitize(context) : {}),
    };
    console.warn(JSON.stringify(entry));
  }

  error(message: string, error?: Error | any, context?: LogContext): void {
    const entry = {
      level: 'ERROR',
      timestamp: new Date().toISOString(),
      message,
      error: error instanceof Error ? { message: error.message, stack: error.stack } : error,
      ...(context ? sanitize(context) : {}),
    };
    console.error(JSON.stringify(entry));
  }

  audit(action: string, actor: string, target: string, details?: any): void {
    const entry = {
      level: 'AUDIT',
      timestamp: new Date().toISOString(),
      action,
      actor,
      target,
      details: sanitize(details),
    };
    console.log(JSON.stringify(entry));
  }
}

export const logger = new Logger();
