import assert from 'node:assert/strict';

import { dbIntegrationEnabled, dbIntegrationTest, hasDbIntegrationConfig } from './helpers/dbIntegration.js';

const integrationDiagnostic = {
  enabled: dbIntegrationEnabled,
  configured: hasDbIntegrationConfig(),
  writesEnabled: process.env.ORBI_DB_INTEGRATION_ALLOW_WRITES === 'true',
};

const exactCount = async (client: any, table: string, apply?: (query: any) => any): Promise<number> => {
  let query = client.from(table).select('*', { count: 'exact', head: true });
  if (apply) {
    query = apply(query);
  }
  const { count, error } = await query;
  assert.ifError(error);
  return Number(count || 0);
};

dbIntegrationTest('db integration scaffold can reach core financial tables in read-only mode', async (_t, client) => {
  const [transactions, ledgerEntries, settlements, webhooks, reconciliations] = await Promise.all([
    exactCount(client, 'transactions'),
    exactCount(client, 'financial_ledger'),
    exactCount(client, 'settlement_lifecycle'),
    exactCount(client, 'provider_webhook_events'),
    exactCount(client, 'reconciliation_reports'),
  ]);

  assert.ok(transactions >= 0);
  assert.ok(ledgerEntries >= 0);
  assert.ok(settlements >= 0);
  assert.ok(webhooks >= 0);
  assert.ok(reconciliations >= 0);
});

dbIntegrationTest('db integration scaffold can read live financial exception counts', async (_t, client) => {
  const [heldForReview, walletDrift, mismatches, failedWebhooks] = await Promise.all([
    exactCount(client, 'transactions', (query) => query.eq('status', 'held_for_review')),
    exactCount(client, 'reconciliation_reports', (query) => query.eq('status', 'MISMATCH').eq('type', 'WALLET_DRIFT')),
    exactCount(client, 'reconciliation_reports', (query) => query.eq('status', 'MISMATCH').neq('type', 'WALLET_DRIFT')),
    exactCount(client, 'provider_webhook_events', (query) => query.in('application_status', ['failed', 'rejected'])),
  ]);

  assert.ok(heldForReview >= 0);
  assert.ok(walletDrift >= 0);
  assert.ok(mismatches >= 0);
  assert.ok(failedWebhooks >= 0);
});

dbIntegrationTest('db integration scaffold can inspect settlement backlog phases safely', async (_t, client) => {
  const pendingPhases = [
    'EXTERNAL_PENDING',
    'RECONCILIATION_RUNNING',
    'READY_FOR_INTERNAL_COMMIT',
    'FAILED',
    'DISPUTE_UNDER_REVIEW',
  ];

  for (const phase of pendingPhases) {
    const count = await exactCount(client, 'settlement_lifecycle', (query) => query.eq('current_phase', phase));
    assert.ok(count >= 0, `Expected non-negative count for phase ${phase}`);
  }
});

if (!dbIntegrationEnabled || !hasDbIntegrationConfig()) {
  console.info('[financial-db-integration] Skipped. Set ORBI_RUN_DB_INTEGRATION=true and provide Supabase service-role env vars to enable.');
  console.info('[financial-db-integration] Current config:', integrationDiagnostic);
}
