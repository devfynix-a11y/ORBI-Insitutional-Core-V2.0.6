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
