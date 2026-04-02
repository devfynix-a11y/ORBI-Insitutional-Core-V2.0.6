import assert from 'node:assert/strict';
import test from 'node:test';

import { LoginSchema, WalletCreateSchema } from '../backend/security/schemas.js';
import { WAF } from '../backend/security/waf.js';
import { Server } from '../backend/server.js';
import { RedisManager } from '../backend/enterprise/infrastructure/RedisManager.js';
import { validate } from '../src/middleware/validation/validate.ts';

const createResponse = () => {
  const response: any = {
    statusCode: 200,
    body: null,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: any) {
      this.body = payload;
      return this;
    },
  };
  return response;
};

test('validation middleware rejects malformed login payloads with stable validation details', () => {
  const middleware = validate(LoginSchema);
  const req: any = {
    body: {
      email: 'not-an-email-object',
      password: 12345678,
    },
  };
  const res = createResponse();
  let nextCalled = false;

  middleware(req, res as any, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.success, false);
  assert.equal(res.body.error, 'VALIDATION_FAILED');
  assert.ok(Array.isArray(res.body.details));
});

test('validation middleware accepts well-formed wallet payloads', () => {
  const middleware = validate(WalletCreateSchema);
  const req: any = {
    body: {
      name: 'Operations Wallet',
      currency: 'TZS',
      type: 'operating',
    },
  };
  const res = createResponse();
  let nextCalled = false;

  middleware(req, res as any, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, 200);
});

test('waf rejects oversized payloads before route logic executes', async () => {
  const oversized = { data: 'x'.repeat(10 * 1024 * 1024 + 1) };
  await assert.rejects(() => WAF.inspect(oversized, 'test-node'), /Payload capacity exceeded/);
});

test('waf throttle enforces login rate limits and emits audit logging on breach', async () => {
  const originalGet = RedisManager.get;
  const originalSet = RedisManager.set;
  const originalLogActivity = (Server as any).logActivity;
  const store = new Map<string, any>();
  const logged: Array<{ userId: string; type: string; status: string; details: string }> = [];

  (RedisManager as any).get = async (key: string) => store.get(key) ?? null;
  (RedisManager as any).set = async (key: string, value: any) => {
    store.set(key, value);
  };
  (Server as any).logActivity = async (
    userId: string,
    type: string,
    status: string,
    details: string,
  ) => {
    logged.push({ userId, type, status, details });
  };

  try {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await WAF.throttle('user-1', 'iam_login');
    }

    await assert.rejects(
      () => WAF.throttle('user-1', 'iam_login'),
      /RATE_LIMIT_EXCEEDED:IAM_LOGIN:RETRY_AFTER_/,
    );

    assert.equal(logged.length, 1);
    assert.equal(logged[0]?.userId, 'user-1');
    assert.equal(logged[0]?.type, 'WAF_INTERCEPT');
    assert.match(logged[0]?.details || '', /RATE_LIMIT_BREACH/);
  } finally {
    (RedisManager as any).get = originalGet;
    (RedisManager as any).set = originalSet;
    (Server as any).logActivity = originalLogActivity;
  }
});
