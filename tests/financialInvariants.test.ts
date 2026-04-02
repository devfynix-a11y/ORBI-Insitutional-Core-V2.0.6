import assert from 'node:assert/strict';
import test from 'node:test';

import {
    FINANCIAL_INVARIANTS,
    assertReversalEligible,
    assertSettlementEligible,
    buildInternalTransferSettlementAppendKey,
    buildInternalTransferSettlementLifecycleKey,
    createBalancePreview,
    isReversalEligibleStatus,
    isSettlementEligibleStatus,
    violatesInternalWalletNonNegativeRule,
} from '../backend/ledger/financialInvariants.js';

test('financial invariants define ledger as the financial source of truth', () => {
    assert.equal(FINANCIAL_INVARIANTS.sourceOfTruth, 'ledger');
    assert.equal(FINANCIAL_INVARIANTS.appendOnlyLedger, true);
    assert.equal(FINANCIAL_INVARIANTS.internalWalletMinimumBalance, 0);
    assert.equal(FINANCIAL_INVARIANTS.internalTransferSettlementAppendPhase, 'PAYSAFE_SETTLEMENT');
});

test('financial invariants expose non-authoritative balance preview metadata', () => {
    const preview = createBalancePreview({
        available: 120,
        required: 150,
        walletName: 'Operating Wallet',
        walletId: 'wallet-1',
    });

    assert.equal(preview.available, 120);
    assert.equal(preview.required, 150);
    assert.equal(preview.sufficient, false);
    assert.equal(preview.authoritative, false);
    assert.equal(preview.source_of_truth, 'ledger');
});

test('financial invariants enforce settlement and reversal eligibility centrally', () => {
    assert.equal(isSettlementEligibleStatus('processing'), true);
    assert.equal(isSettlementEligibleStatus('completed'), false);
    assert.equal(isReversalEligibleStatus('completed'), true);
    assert.equal(isReversalEligibleStatus('reversed'), false);
    assert.equal(violatesInternalWalletNonNegativeRule(-0.01), true);
    assert.equal(violatesInternalWalletNonNegativeRule(0), false);

    assert.doesNotThrow(() => assertSettlementEligible({ txId: 'tx-1', txExists: true, status: 'processing', hasInternalVault: true }));
    assert.throws(() => assertSettlementEligible({ txId: 'tx-1', txExists: false }), /INVALID_SETTLEMENT_STATE/);
    assert.throws(() => assertReversalEligible('reversed'), /TRANSACTION_NOT_REVERSIBLE/);
});

test('financial invariants build stable internal settlement markers', () => {
    assert.equal(
        buildInternalTransferSettlementAppendKey('tx-1'),
        'settlement:tx-1:paysafe_release:v2',
    );
    assert.equal(
        buildInternalTransferSettlementLifecycleKey('tx-1'),
        'INTERNAL_TRANSFER:tx-1:PAYSAFE_SETTLEMENT',
    );
});
