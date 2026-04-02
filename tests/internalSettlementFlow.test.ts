import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const schemaPath = join(process.cwd(), 'database', 'main.sql');
const enginePath = join(process.cwd(), 'backend', 'ledger', 'transactionEngine.ts');
const routesPath = join(process.cwd(), 'src', 'routes', 'internal', 'index.ts');

const schema = readFileSync(schemaPath, 'utf8');
const engineSource = readFileSync(enginePath, 'utf8');
const routesSource = readFileSync(routesPath, 'utf8');

const sliceBetween = (source: string, startNeedle: string, endNeedle: string): string => {
    const start = source.indexOf(startNeedle);
    assert.notEqual(start, -1, `Missing start marker: ${startNeedle}`);
    const end = source.indexOf(endNeedle, start);
    assert.notEqual(end, -1, `Missing end marker after ${startNeedle}: ${endNeedle}`);
    return source.slice(start, end);
};

test('internal settlement SQL claim path verifies status under lock and uses durable markers', () => {
    const fn = sliceBetween(
        schema,
        'CREATE OR REPLACE FUNCTION public.claim_internal_transfer_settlement(',
        'CREATE OR REPLACE FUNCTION public.complete_internal_transfer_settlement(',
    );

    assert.match(fn, /FROM public\.transactions[\s\S]*FOR UPDATE/i);
    assert.match(fn, /INSERT INTO public\.settlement_lifecycle/i);
    assert.match(fn, /ledger_append_markers/i);
    assert.match(fn, /PAYSAFE_SETTLEMENT/);
    assert.match(fn, /settlement:.*paysafe_release:v2/i);
    assert.match(fn, /CONCURRENCY_CONFLICT:/);
    assert.match(fn, /expected processing under settlement lock/i);
});

test('internal settlement SQL completion path finalizes state with worker claim ownership', () => {
    const fn = sliceBetween(
        schema,
        'CREATE OR REPLACE FUNCTION public.complete_internal_transfer_settlement(',
        'CREATE TABLE IF NOT EXISTS public.merchant_fees',
    );

    assert.match(fn, /FROM public\.transactions[\s\S]*FOR UPDATE/i);
    assert.match(fn, /WHERE lifecycle_key = v_lifecycle_key[\s\S]*FOR UPDATE/i);
    assert.match(fn, /worker_claim_id/i);
    assert.match(fn, /status = 'completed'/i);
    assert.match(fn, /status = 'held_for_review'/i);
    assert.match(fn, /CONCURRENCY_CONFLICT:/);
});

test('engine settlement flow no longer relies on ledger description string matching', () => {
    const settlementBlock = sliceBetween(
        engineSource,
        'public async completeSettlement(',
        'public async sendTransferNotifications(',
    );

    assert.doesNotMatch(settlementBlock, /description\?\.includes\('PaySafe Settlement'\)/);
    assert.match(settlementBlock, /claimInternalTransferSettlement/i);
    assert.match(settlementBlock, /finalizeInternalTransferSettlement/i);
    assert.match(settlementBlock, /appendAlreadyApplied/i);
    assert.match(settlementBlock, /workerClaimId/i);
});

test('internal worker route forwards worker identity and maps settlement conflicts to 409', () => {
    assert.match(routesSource, /x-worker-id/i);
    assert.match(routesSource, /completeSettlement\(id, undefined, workerId\)/);
    assert.match(routesSource, /CONCURRENCY_CONFLICT/);
    assert.match(routesSource, /INVALID_SETTLEMENT_STATE/);
    assert.match(routesSource, /409/);
});
