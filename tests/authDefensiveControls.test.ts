import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { BruteForceService } from '../backend/src/services/bruteForce.service.js';
import { RedisClusterFactory } from '../backend/infrastructure/RedisClusterFactory.js';

const authServiceSource = readFileSync(join(process.cwd(), 'iam', 'authService.ts'), 'utf8');
const authControllerSource = readFileSync(
  join(process.cwd(), 'backend', 'src', 'modules', 'auth', 'auth.controller.ts'),
  'utf8',
);

type FakeRedisValue = string | number;

class FakeRedisClient {
  store = new Map<string, FakeRedisValue>();
  expirations = new Map<string, number>();

  async get(key: string) {
    return this.store.has(key) ? String(this.store.get(key)) : null;
  }

  async ttl(key: string) {
    return this.expirations.get(key) ?? -1;
  }

  async incr(key: string) {
    const current = Number(this.store.get(key) ?? 0) + 1;
    this.store.set(key, current);
    return current;
  }

  async expire(key: string, seconds: number) {
    this.expirations.set(key, seconds);
    return 1;
  }

  async set(key: string, value: string, ...args: any[]) {
    this.store.set(key, value);
    const pxIndex = args.findIndex((entry) => entry === 'PX');
    if (pxIndex >= 0 && typeof args[pxIndex + 1] === 'number') {
      this.expirations.set(key, Math.ceil(Number(args[pxIndex + 1]) / 1000));
    }
    return 'OK';
  }

  async del(key: string) {
    this.store.delete(key);
    this.expirations.delete(key);
    return 1;
  }
}

test('refresh-session flow contains replay detection, chain revocation, and rotation markers', () => {
  assert.match(authServiceSource, /async refreshSession\(refreshToken: string/);
  assert.match(authServiceSource, /if \(sessionRecord\.replaced_by\)/);
  assert.match(authServiceSource, /await this\.revokeSessionChain\(sessionRecord\.user_id, tokenHash\)/);
  assert.match(authServiceSource, /if \(sessionRecord\.is_revoked\)/);
  assert.match(authServiceSource, /sessionRecord\.device_fingerprint !== metadata\.fingerprint/);
  assert.match(authServiceSource, /await sb\.from\('user_sessions'\)\s*\.update\(\{ replaced_by: newTokenHash \}\)/);
  assert.match(authServiceSource, /await sb\.from\('user_sessions'\)\.insert\(\{/);
});

test('pin login flow increments failed attempts and locks the credential after repeated failures', () => {
  assert.match(authControllerSource, /const PIN_MAX_ATTEMPTS = 3;/);
  assert.match(authControllerSource, /const PIN_LOCK_MINUTES = 15;/);
  assert.match(authControllerSource, /failed_attempts: nextAttempts/);
  assert.match(authControllerSource, /locked_until: lockNow/);
  assert.match(authControllerSource, /throw new Error\(lockNow \? 'PIN_LOCKED_USE_BIOMETRIC' : 'PIN_INVALID'\)/);
  assert.match(authControllerSource, /failed_attempts: 0,\s*locked_until: null,/);
});

test('brute-force service locks after repeated failures and escalates on repeated lock cycles', async () => {
  const previousGetClient = RedisClusterFactory.getClient;
  const fakeRedis = new FakeRedisClient();
  (RedisClusterFactory as any).getClient = () => fakeRedis;

  try {
    const service = new BruteForceService();

    for (let attempt = 0; attempt < 4; attempt += 1) {
      const result = await service.recordFailedAttempt('user-1');
      assert.equal(result.locked, false);
    }

    const firstLock = await service.recordFailedAttempt('user-1');
    assert.equal(firstLock.locked, true);
    assert.equal(firstLock.lockDuration, 15 * 60 * 1000);
    assert.equal(await fakeRedis.get('lock_status:user-1'), '15min');
    assert.equal(await fakeRedis.get('login_attempts:user-1'), null);

    for (let attempt = 0; attempt < 4; attempt += 1) {
      const result = await service.recordFailedAttempt('user-1');
      assert.equal(result.locked, false);
    }

    await fakeRedis.set('lock_status:user-1', '15min', 'PX', 15 * 60 * 1000);
    const escalatedLock = await service.recordFailedAttempt('user-1');
    assert.equal(escalatedLock.locked, true);
    assert.equal(escalatedLock.lockDuration, 24 * 60 * 60 * 1000);
    assert.equal(await fakeRedis.get('lock_status:user-1'), '24h');
  } finally {
    (RedisClusterFactory as any).getClient = previousGetClient;
  }
});
