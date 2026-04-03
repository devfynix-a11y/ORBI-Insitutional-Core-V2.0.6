import assert from 'node:assert/strict';
import test from 'node:test';

import { SecureKMSService, isRecoverableActiveKeyInsertConflict } from '../backend/security/kms.js';

test('kms recoverable insert conflict detector only accepts active-key uniqueness races', () => {
  assert.equal(
    isRecoverableActiveKeyInsertConflict({
      code: '23505',
      message: 'duplicate key value violates unique constraint "kms_keys_one_active_per_type"',
    }),
    true,
  );

  assert.equal(
    isRecoverableActiveKeyInsertConflict({
      code: '23505',
      message: 'duplicate key value violates unique constraint "some_other_constraint"',
    }),
    false,
  );
});

test('kms provisioning adopts the winner key after an active-key uniqueness race', async () => {
  const kms = new SecureKMSService() as any;
  const wrappingKey = await kms.getWrappingKey('test-master-secret');
  let adopted = false;

  kms.hydrateExistingActiveKeyForType = async (type: string) => {
    adopted = true;
    kms.activeKeyIds[type] = 'winner-key';
    return true;
  };

  const fakeSb = {
    from: () => ({
      insert: async () => ({
        error: {
          code: '23505',
          message: 'duplicate key value violates unique constraint "kms_keys_one_active_per_type"',
        },
      }),
    }),
  };

  await kms.provisionNewKey('ENCRYPTION', wrappingKey, fakeSb, 2, ['test-master-secret']);

  assert.equal(adopted, true);
  assert.equal(kms.activeKeyIds.ENCRYPTION, 'winner-key');
});

test('kms duplicate active-key recovery keeps the newest winner and rotates losers', async () => {
  const kms = new SecureKMSService() as any;
  const retiredKeyIds: string[] = [];

  kms.retireDbKeys = async (_sb: unknown, dbKeys: Array<{ key_id: string }>) => {
    retiredKeyIds.push(...dbKeys.map((key) => key.key_id));
  };

  const winner = await kms.resolveDuplicateUsableActiveKeysForType(
    'ENCRYPTION',
    [
      {
        key_id: 'key-v2-encryption-deb9a394',
        version: 2,
        created_at: '2026-04-03T04:51:10.000Z',
      },
      {
        key_id: 'key-v2-encryption-175b5963',
        version: 2,
        created_at: '2026-04-03T04:52:11.000Z',
      },
      {
        key_id: 'key-v1-encryption-legacy',
        version: 1,
        created_at: '2026-04-02T00:00:00.000Z',
      },
    ],
    {},
  );

  assert.equal(winner, 'key-v2-encryption-175b5963');
  assert.deepEqual(retiredKeyIds, [
    'key-v2-encryption-deb9a394',
    'key-v1-encryption-legacy',
  ]);
  assert.equal(kms.activeKeyIds.ENCRYPTION, 'key-v2-encryption-175b5963');
});
