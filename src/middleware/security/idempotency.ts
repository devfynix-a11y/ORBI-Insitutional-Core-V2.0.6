import { NextFunction, Request, Response } from 'express';

type CachedResponse = { status: number; body: any };

type CreateIdempotencyOptions = {
  redisClient: any;
  allowProcessLocalIdempotency: boolean;
  idempotencyTtlSeconds: number;
};

export const resolveIdempotencyHeader = (req: Request) =>
  req.header('Idempotency-Key') || req.header('x-idempotency-key');

export const createIdempotencyMiddleware = ({
  redisClient,
  allowProcessLocalIdempotency,
  idempotencyTtlSeconds,
}: CreateIdempotencyOptions) => {
  const idempotencyCache = new Map<string, CachedResponse>();

  const readIdempotencyCache = async (key: string) => {
    if (redisClient) {
      try {
        const cached = await redisClient.get(`idempotency:${key}`);
        if (cached) {
          return JSON.parse(String(cached)) as CachedResponse;
        }
      } catch (e) {
        console.warn('[Idempotency] Redis read failed:', e);
      }
    }

    if (allowProcessLocalIdempotency) {
      return idempotencyCache.get(key);
    }

    return null;
  };

  const writeIdempotencyCache = async (key: string, value: CachedResponse) => {
    if (redisClient) {
      try {
        await redisClient.set(
          `idempotency:${key}`,
          JSON.stringify(value),
          'EX',
          idempotencyTtlSeconds,
        );
        return;
      } catch (e) {
        console.warn('[Idempotency] Redis write failed:', e);
      }
    }

    if (!allowProcessLocalIdempotency) {
      console.warn(
        `[Idempotency] Redis unavailable and process-local fallback disabled. Key ${key} will not be cached.`,
      );
      return;
    }

    idempotencyCache.set(key, value);
    if (idempotencyCache.size > 1000) {
      const firstKey = idempotencyCache.keys().next().value;
      if (firstKey !== undefined) idempotencyCache.delete(firstKey);
    }
  };

  return async (req: Request, res: Response, next: NextFunction) => {
    const key = resolveIdempotencyHeader(req);
    if (!key) return next();

    const cached = await readIdempotencyCache(key);
    if (cached) {
      console.info(`[Idempotency] Duplicate request detected for key: ${key}`);
      return res.status(cached.status).json(cached.body);
    }

    const originalJson = res.json;
    res.json = function (body: any) {
      void writeIdempotencyCache(key, { status: res.statusCode, body });
      return originalJson.call(this, body);
    };

    next();
  };
};
