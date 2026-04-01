import express, { type Express } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import { appTrustMiddleware } from '../../../backend/middleware/appTrust.js';
import { createIdempotencyMiddleware } from './idempotency.js';
import { wafInspect } from './wafInspect.js';
import { sanitizeContent } from './sanitize.js';
import { riskAssessment } from './riskAssessment.js';

export const ALLOWED_ORIGINS = [
  'https://orbi-financial-technologies-c0re-v2026.onrender.com',
  'https://orbi-backend-v2-0-1.onrender.com',
  'https://fynix-backend-v2-0-1.onrender.com',
  'https://ais-dev-otadbk3zs67js4adfe3zhb-131722823335.europe-west2.run.app',
  'https://ais-pre-otadbk3zs67js4adfe3zhb-131722823335.europe-west2.run.app',
  'https://ais-dev-egx2rrccp653yh67wk47za-20006156269.europe-west2.run.app',
  'https://ais-pre-egx2rrccp653yh67wk47za-20006156269.europe-west2.run.app',
];

type SecuritySetupOptions = {
  redisAvailable: boolean;
  redisClient: any;
  allowProcessLocalIdempotency: boolean;
  idempotencyTtlSeconds: number;
};

export const configureCoreSecurityMiddleware = (app: Express, options: SecuritySetupOptions) => {
  const { redisClient, allowProcessLocalIdempotency, idempotencyTtlSeconds } = options;

  app.use(createIdempotencyMiddleware({
    redisClient,
    allowProcessLocalIdempotency,
    idempotencyTtlSeconds,
  }));

  app.use(cors({
    origin: (origin, callback) => {
      if (!origin) {
        return callback(null, true);
      }

      if (ALLOWED_ORIGINS.includes(origin)) {
        callback(null, true);
      } else {
        console.warn(`[CORS] Rejection for origin: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Accept',
      'Authorization',
      'x-orbi-app-id',
      'x-orbi-app-origin',
      'x-orbi-registry-type',
      'x-orbi-trace',
      'x-idempotency-key',
      'x-orbi-apk-hash',
      'x-orbi-fingerprint',
      'x-orbi-attestation',
      'x-orbi-device-state',
    ],
  }));

  app.use(helmet({
    hsts: process.env.NODE_ENV === 'production'
      ? {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: true,
        }
      : false,
  }));

  app.use(appTrustMiddleware);

  app.use(express.json({
    limit: '20mb',
    verify: (req: any, _res, buf) => {
      if (buf?.length) {
        req.rawBody = buf.toString('utf8');
      }
    },
  }) as any);

  app.use(wafInspect);
  app.use(sanitizeContent);
  app.use(riskAssessment);
};

export const createGlobalIpLimiter = (redisAvailable: boolean, redisClient: any) => rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 2000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'INFRA_RATE_LIMIT_EXCEEDED' },
  validate: { xForwardedForHeader: false },
  store: (redisAvailable && redisClient)
    ? new RedisStore({
        sendCommand: (...args: string[]) => redisClient.call(args[0], ...args.slice(1)) as any,
      })
    : undefined,
});
