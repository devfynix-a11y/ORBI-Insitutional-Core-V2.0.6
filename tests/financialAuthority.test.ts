import assert from 'node:assert/strict';
import test from 'node:test';

import { TransactionService } from '../ledger/transactionService.js';
import { BankingEngineService } from '../backend/ledger/transactionEngine.js';
import { RegulatoryService } from '../backend/ledger/regulatoryService.js';
import { TransactionStateMachine } from '../backend/ledger/stateMachine.js';

test('normalizeFinancialAuthorityError maps SQL authority failures into stable domain errors', () => {
    const service = new TransactionService();

    assert.match(
        service.normalizeFinancialAuthorityError(new Error('INSUFFICIENT_FUNDS: Internal entity would go negative')).message,
        /^INSUFFICIENT_FUNDS:/
    );
    assert.match(
        service.normalizeFinancialAuthorityError({ message: 'IDEMPOTENCY_VIOLATION: duplicate reference', code: '23505' }).message,
        /^IDEMPOTENCY_VIOLATION:/
    );
    assert.match(
        service.normalizeFinancialAuthorityError(new Error('WALLET_LOCKED: Wallet abc is locked or unavailable')).message,
        /^LOCKED_WALLET:/
    );
    assert.match(
        service.normalizeFinancialAuthorityError(new Error('INVALID_SETTLEMENT_STATE: Transaction is already completed')).message,
        /^INVALID_SETTLEMENT_STATE:/
    );
    assert.match(
        service.normalizeFinancialAuthorityError({ message: 'could not serialize access due to concurrent update', code: '40001' }).message,
        /^CONCURRENCY_CONFLICT:/
    );
});

test('process exposes preview balances as non-authoritative UX hints during simulation', async () => {
    const engine = new BankingEngineService();

    const originalCalculateFees = RegulatoryService.calculateFees;
    const originalTransition = TransactionStateMachine.transition;
    const originalDeriveLegs = (BankingEngineService as any).prototype.deriveLegs;

    RegulatoryService.calculateFees = async () => ({
        vat: 0,
        fee: 0,
        gov_fee: 0,
        rate: 0,
        total: 0,
    } as any);
    TransactionStateMachine.transition = (() => undefined) as any;
    (BankingEngineService as any).prototype.deriveLegs = async function () {
        return {
            legs: [],
            balanceHint: 125.5,
        };
    };

    try {
        const result = await engine.process(
            { id: 'user-1' } as any,
            {
                amount: 50,
                currency: 'USD',
                description: 'Simulation payment',
                type: 'WITHDRAWAL',
                sourceWalletId: 'wallet-1',
                targetWalletId: null,
                categoryId: null,
                isSimulation: true,
                metadata: {},
            },
        );

        assert.equal(result.success, true);
        assert.equal(result.transaction?.metadata?.available_balance, 125.5);
        assert.equal(result.transaction?.metadata?.available_balance_authoritative, false);
    } finally {
        RegulatoryService.calculateFees = originalCalculateFees;
        TransactionStateMachine.transition = originalTransition;
        (BankingEngineService as any).prototype.deriveLegs = originalDeriveLegs;
    }
});

test('process normalizes locked-wallet failures instead of leaking raw lower-level errors', async () => {
    const engine = new BankingEngineService();

    const originalCalculateFees = RegulatoryService.calculateFees;
    const originalTransition = TransactionStateMachine.transition;
    const originalDeriveLegs = (BankingEngineService as any).prototype.deriveLegs;

    RegulatoryService.calculateFees = async () => ({
        vat: 0,
        fee: 0,
        gov_fee: 0,
        rate: 0,
        total: 0,
    } as any);
    TransactionStateMachine.transition = (() => undefined) as any;
    (BankingEngineService as any).prototype.deriveLegs = async function () {
        throw new Error('WALLET_LOCKED: Wallet wallet-1 is locked or unavailable');
    };

    try {
        const result = await engine.process(
            { id: 'user-1' } as any,
            {
                amount: 50,
                currency: 'USD',
                description: 'Locked wallet payment',
                type: 'WITHDRAWAL',
                sourceWalletId: 'wallet-1',
                targetWalletId: null,
                categoryId: null,
                isSimulation: false,
                metadata: {},
            },
        );

        assert.equal(result.success, false);
        assert.match(result.error || '', /^LOCKED_WALLET:/);
    } finally {
        RegulatoryService.calculateFees = originalCalculateFees;
        TransactionStateMachine.transition = originalTransition;
        (BankingEngineService as any).prototype.deriveLegs = originalDeriveLegs;
    }
});
