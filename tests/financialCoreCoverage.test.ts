import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const transactionServicePath = join(process.cwd(), 'ledger', 'transactionService.ts');
const webhookHandlerPath = join(process.cwd(), 'backend', 'payments', 'webhookHandler.ts');
const enginePath = join(process.cwd(), 'backend', 'ledger', 'transactionEngine.ts');
const schemaPath = join(process.cwd(), 'database', 'main.sql');

const transactionServiceSource = readFileSync(transactionServicePath, 'utf8');
const webhookHandlerSource = readFileSync(webhookHandlerPath, 'utf8');
const engineSource = readFileSync(enginePath, 'utf8');
const schemaSource = readFileSync(schemaPath, 'utf8');

const sliceBetween = (source: string, startNeedle: string, endNeedle: string): string => {
  const start = source.indexOf(startNeedle);
  assert.notEqual(start, -1, `Missing start marker: ${startNeedle}`);
  const end = source.indexOf(endNeedle, start);
  assert.notEqual(end, -1, `Missing end marker after ${startNeedle}: ${endNeedle}`);
  return source.slice(start, end);
};

test('transaction posting stays SQL-authoritative and normalizes commit failures', () => {
  const block = sliceBetween(
    transactionServiceSource,
    'async postTransactionWithLedger(t: Partial<Transaction>, ledgerEntries: LedgerEntry[]) {',
    '    async addLedgerEntries(',
  );

  assert.match(block, /sb\.rpc\('post_transaction_v2'/);
  assert.match(block, /throw this\.normalizeFinancialAuthorityError\(rpcError, 'LEDGER_COMMIT_FAULT'\)/);
  assert.match(block, /logTransactionEvent\(txId, null, 'created'/);
  assert.match(block, /emitFinancialEvent\('TRANSACTION_POSTED'/);
});

test('append-only ledger updates preserve idempotency and wallet safety through SQL', () => {
  const block = sliceBetween(
    transactionServiceSource,
    '    async addLedgerEntries(',
    '    public async verifyWalletBalance(walletId: string): Promise<{ valid: boolean, drift: number }> {',
  );

  assert.match(block, /sb\.rpc\('append_ledger_entries_v1'/);
  assert.match(block, /p_append_key: options\?\.appendKey \|\| null/);
  assert.match(block, /p_append_phase: options\?\.appendPhase \|\| null/);
  assert.match(block, /throw this\.normalizeFinancialAuthorityError\(rpcError, 'LEDGER_APPEND_FAULT'\)/);
});

test('reversal flows remain eligibility-gated and persist explicit reversal metadata', () => {
  const reverseBlock = sliceBetween(
    transactionServiceSource,
    '    public async reverseTransaction(txId: string, actorId: string): Promise<void> {',
    '    public async lockTransactionForReview(',
  );
  const reverseWithReasonBlock = sliceBetween(
    transactionServiceSource,
    '    public async reverseTransactionWithReason(',
    '    public async autoReverseHeldTransactions()',
  );

  assert.match(reverseBlock, /FORENSIC_REVERSAL:/);
  assert.match(reverseBlock, /await this\.updateTransactionStatus\(txId, 'reversed'/);
  assert.match(reverseWithReasonBlock, /assertReversalEligible\(tx\.status\)/);
  assert.match(reverseWithReasonBlock, /reversal_reason: reason/);
  assert.match(reverseWithReasonBlock, /reversed_by: actorId/);
  assert.match(reverseWithReasonBlock, /reversed_by_role: actorRole/);
});

test('held_for_review flows require explicit lock metadata, audit pass, and timed auto-reversal', () => {
  const lockBlock = sliceBetween(
    transactionServiceSource,
    '    public async lockTransactionForReview(',
    '    public async recordAuditDecision(',
  );
  const approveBlock = sliceBetween(
    transactionServiceSource,
    '    public async approveReviewedTransaction(',
    '    public async approveAllAuditPassedTransactions(',
  );
  const autoReverseBlock = sliceBetween(
    transactionServiceSource,
    '    public async autoReverseHeldTransactions(): Promise<number> {',
    '    private async notifyTransactionIssueStakeholders(',
  );

  assert.match(lockBlock, /status:\s*'held_for_review'/);
  assert.match(lockBlock, /transaction_lock:/);
  assert.match(lockBlock, /audit_status: 'PENDING'/);
  assert.match(lockBlock, /auto_reverse_at: autoReverseAt/);
  assert.match(approveBlock, /if \(auditStatus !== 'PASSED'\)/);
  assert.match(approveBlock, /throw new Error\('AUDIT_PASS_REQUIRED'\)/);
  assert.match(autoReverseBlock, /reverseTransactionWithReason\(/);
  assert.match(autoReverseBlock, /AUTO_REVERSAL_AFTER_24_HOURS/);
});

test('webhook processing deduplicates receipts before applying provider callbacks', () => {
  const block = sliceBetween(
    webhookHandlerSource,
    '    public async handleCallback(',
    '    private async applyNormalizedCallback(',
  );

  assert.match(block, /providerWebhookEventLedger\.recordReceipt/);
  assert.match(block, /receipt\.duplicate && \['applied', 'processing', 'rejected'\]\.includes/);
  assert.match(block, /providerWebhookEventLedger\.claimForApplication/);
  assert.match(block, /WEBHOOK_DUPLICATE_IGNORED/);
  assert.match(block, /providerWebhookEventLedger\.markApplied/);
});

test('webhook processing records verification, parse, and application failures in both ledger and audit trail', () => {
  const block = sliceBetween(
    webhookHandlerSource,
    '    public async handleCallback(',
    '    private async applyNormalizedCallback(',
  );

  assert.match(block, /providerWebhookEventLedger\.markRejected\(receipt\.record\.id, message, message\)/);
  assert.match(block, /WEBHOOK_SIGNATURE_FAILED/);
  assert.match(block, /WEBHOOK_SIGNATURE_MISSING/);
  assert.match(block, /WEBHOOK_SECRET_MISSING/);
  assert.match(block, /WEBHOOK_REPLAY_BLOCKED/);
  assert.match(block, /WEBHOOK_TIMESTAMP_REJECTED/);
  assert.match(block, /providerWebhookEventLedger\.markFailed\([\s\S]*WEBHOOK_PARSE_FAILED/);
  assert.match(block, /WEBHOOK_PARSE_FAILED/);
  assert.match(block, /providerWebhookEventLedger\.markFailed\([\s\S]*WEBHOOK_APPLICATION_FAILED/);
  assert.match(block, /WEBHOOK_APPLICATION_FAILED/);
  assert.match(block, /WEBHOOK_PROCESSED/);
});

test('duplicate settlement prevention keeps durable append keys and worker-claimed completion', () => {
  const claimBlock = sliceBetween(
    engineSource,
    '    private async claimInternalTransferSettlement(txId: string, workerId: string) {',
    '    private async finalizeInternalTransferSettlement(',
  );
  const completeBlock = sliceBetween(
    engineSource,
    '    public async completeSettlement(txId: string, txData?: any, workerId?: string): Promise<boolean> {',
    '    public async sendTransferNotifications(',
  );

  assert.match(claimBlock, /buildInternalTransferSettlementAppendKey/);
  assert.match(claimBlock, /FINANCIAL_INVARIANTS\.internalTransferSettlementAppendPhase/);
  assert.match(claimBlock, /workerClaimId/);
  assert.match(completeBlock, /claimInternalTransferSettlement/);
  assert.match(completeBlock, /appendAlreadyApplied/);
  assert.match(completeBlock, /appendPhase: claim\.appendPhase/);
  assert.match(completeBlock, /finalizeInternalTransferSettlement/);
});

test('wallet lock and insufficient funds remain first-class SQL financial faults', () => {
  const postFn = sliceBetween(
    schemaSource,
    'CREATE OR REPLACE FUNCTION public.post_transaction_v2(',
    'CREATE OR REPLACE FUNCTION public.append_ledger_entries_v1(',
  );

  assert.match(postFn, /RAISE EXCEPTION 'WALLET_LOCKED:/);
  assert.match(postFn, /RAISE EXCEPTION 'INSUFFICIENT_FUNDS:/);
  assert.match(postFn, /RAISE EXCEPTION 'IDEMPOTENCY_VIOLATION:/);
});

test('wallet balance reconciliation records drift and privileged repair stays explicit', () => {
  const verifyBlock = sliceBetween(
    transactionServiceSource,
    '    public async verifyWalletBalance(walletId: string): Promise<{ valid: boolean, drift: number }> {',
    '    public async updateTransactionStatus(id: string, status: TransactionStatus, notes?: string) {',
  );
  const repairBlock = sliceBetween(
    transactionServiceSource,
    '    public async fixWalletBalance(walletId: string, actorId: string, repairReason?: string, incidentReference?: string): Promise<void> {',
    '    public async reverseTransaction(txId: string, actorId: string): Promise<void> {',
  );

  assert.match(verifyBlock, /from\('reconciliation_reports'\)\.insert/);
  assert.match(verifyBlock, /type:\s*'WALLET_DRIFT'/);
  assert.match(verifyBlock, /difference:\s*drift/);
  assert.match(repairBlock, /repair_wallet_balance_emergency/);
  assert.match(repairBlock, /PRIVILEGED_WALLET_BALANCE_REPAIR_EXECUTED/);
  assert.match(repairBlock, /repairReason/);
});
