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

const isProd = process.env.NODE_ENV === 'production';
const enforceHttps = String(process.env.ORBI_ENFORCE_HTTPS || (isProd ? 'true' : 'false'))
  .trim()
  .toLowerCase() === 'true';

const configuredOrigins = [
  process.env.ORIGIN,
  process.env.ORBI_WEB_ORIGIN,
  process.env.BACKEND_URL,
  ...(process.env.ORBI_ALLOWED_ORIGINS || '').split(','),
]
  .map((value) => String(value || '').trim())
  .filter(Boolean);

const devOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
];

export const ALLOWED_ORIGINS = Array.from(
  new Set([...(isProd ? configuredOrigins : [...configuredOrigins, ...devOrigins])]),
);

type SecuritySetupOptions = {
  redisAvailable: boolean;
  redisClient: any;
  allowProcessLocalIdempotency: boolean;
  idempotencyTtlSeconds: number;
};

export const configureCoreSecurityMiddleware = (app: Express, options: SecuritySetupOptions) => {
  const { redisClient, allowProcessLocalIdempotency, idempotencyTtlSeconds } = options;

  if (enforceHttps) {
    app.use((req, res, next) => {
      const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
      const isHttps = req.secure || forwardedProto === 'https';

      if (isHttps) {
        return next();
      }

      const host = req.get('host');
      if (!host) {
        return res.status(400).json({ success: false, error: 'HTTPS_REQUIRED' });
      }

      const redirectTarget = `https://${host}${req.originalUrl || req.url || '/'}`;
      if (req.method === 'GET' || req.method === 'HEAD') {
        return res.redirect(308, redirectTarget);
      }

      return res.status(426).json({
        success: false,
        error: 'HTTPS_REQUIRED',
        redirect_to: redirectTarget,
      });
    });
  }

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
