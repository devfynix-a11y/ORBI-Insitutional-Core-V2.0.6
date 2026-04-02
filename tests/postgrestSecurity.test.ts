import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildPostgrestEqualsFilter,
  buildPostgrestLikeFilter,
  buildPostgrestOrFilter,
  quotePostgrestFilterValue,
} from '../backend/security/postgrest.js';

test('postgrest filter helpers quote and escape untrusted values', () => {
  const raw = 'abc",status.eq.failed';
  assert.equal(
    quotePostgrestFilterValue(raw),
    '"abc\\",status.eq.failed"',
  );
  assert.equal(
    buildPostgrestEqualsFilter('reference_id', raw),
    'reference_id.eq."abc\\",status.eq.failed"',
  );
  assert.equal(
    buildPostgrestLikeFilter('description', raw),
    'description.ilike."%abc\\",status.eq.failed%"',
  );
});

test('postgrest or helper builds comma-separated safe predicates', () => {
  const filter = buildPostgrestOrFilter([
    { column: 'email', operator: 'eq', value: 'person@example.com' },
    { column: 'phone', operator: 'eq', value: '+255700000000' },
  ]);

  assert.equal(
    filter,
    'email.eq."person@example.com",phone.eq."+255700000000"',
  );
});
