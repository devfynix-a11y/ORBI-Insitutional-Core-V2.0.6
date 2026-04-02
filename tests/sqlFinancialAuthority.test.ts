import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const schemaPath = join(process.cwd(), 'database', 'main.sql');
const schema = readFileSync(schemaPath, 'utf8');

const sliceBetween = (source: string, startNeedle: string, endNeedle: string): string => {
    const start = source.indexOf(startNeedle);
    assert.notEqual(start, -1, `Missing start marker: ${startNeedle}`);
    const end = source.indexOf(endNeedle, start);
    assert.notEqual(end, -1, `Missing end marker after ${startNeedle}: ${endNeedle}`);
    return source.slice(start, end);
};

test('post_transaction_v2 documents SQL ownership of balance computation', () => {
    const fn = sliceBetween(
        schema,
        'CREATE OR REPLACE FUNCTION public.post_transaction_v2(',
        'CREATE OR REPLACE FUNCTION public.append_ledger_entries_v1(',
    );

    assert.match(fn, /leg\.balance_before is ignored as authoritative/i);
    assert.match(fn, /leg\.balance_after is ignored; SQL computes the next balance internally/i);
    assert.match(fn, /leg\.amount_plain is the authoritative arithmetic input/i);
    assert.doesNotMatch(fn, /INSERT INTO public\.financial_ledger[\s\S]*balance_before/i);
});

test('post_transaction_v2 enforces authoritative financial safety in SQL', () => {
    const fn = sliceBetween(
        schema,
        'CREATE OR REPLACE FUNCTION public.post_transaction_v2(',
        'CREATE OR REPLACE FUNCTION public.append_ledger_entries_v1(',
    );

    assert.match(fn, /RAISE EXCEPTION 'IDEMPOTENCY_VIOLATION:/);
    assert.match(fn, /RAISE EXCEPTION 'WALLET_LOCKED:/);
    assert.match(fn, /RAISE EXCEPTION 'INSUFFICIENT_FUNDS:/);
    assert.match(fn, /RAISE EXCEPTION 'LEDGER_OUT_OF_BALANCE:/);
});

test('append_ledger_entries_v1 keeps SQL in charge of append safety and idempotency', () => {
    const fn = sliceBetween(
        schema,
        'CREATE OR REPLACE FUNCTION public.append_ledger_entries_v1(',
        'CREATE OR REPLACE FUNCTION public.card_settle_v1(',
    );

    assert.match(fn, /APPEND_ALREADY_APPLIED:/);
    assert.match(fn, /leg\.balance_before is ignored as authoritative/i);
    assert.match(fn, /leg\.balance_after is ignored; SQL computes the next balance internally/i);
    assert.match(fn, /RAISE EXCEPTION 'WALLET_LOCKED:/);
    assert.match(fn, /RAISE EXCEPTION 'INSUFFICIENT_FUNDS:/);
    assert.match(fn, /RAISE EXCEPTION 'LEDGER_OUT_OF_BALANCE:/);
});
