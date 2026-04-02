import { TransactionStatus } from '../../types.js';

export const FINANCIAL_INVARIANTS = {
    sourceOfTruth: 'ledger',
    appendOnlyLedger: true,
    internalWalletMinimumBalance: 0,
    settlementEligibleStatus: 'processing' as TransactionStatus,
    internalTransferSettlementAppendPhase: 'PAYSAFE_SETTLEMENT',
    internalTransferSettlementVersion: 'v2',
    internalTransferSettlementClaimTtlMs: 5 * 60 * 1000,
    reversalBlockedStatuses: new Set<TransactionStatus | string>(['reversed', 'failed', 'refunded', 'cancelled']),
} as const;

export const buildInternalTransferSettlementAppendKey = (txId: string): string =>
    `settlement:${txId}:paysafe_release:${FINANCIAL_INVARIANTS.internalTransferSettlementVersion}`;

export const buildInternalTransferSettlementLifecycleKey = (txId: string): string =>
    `INTERNAL_TRANSFER:${txId}:PAYSAFE_SETTLEMENT`;

export const createBalancePreview = (params: {
    available: number;
    required: number;
    walletName: string;
    walletId?: string | null;
}) => ({
    available: params.available,
    required: params.required,
    sufficient: params.available >= params.required,
    wallet_name: params.walletName,
    wallet_id: params.walletId || null,
    authoritative: false,
    source_of_truth: FINANCIAL_INVARIANTS.sourceOfTruth,
});

export const violatesInternalWalletNonNegativeRule = (nextBalance: number): boolean =>
    nextBalance < FINANCIAL_INVARIANTS.internalWalletMinimumBalance;

export const isIdempotencyViolationError = (error: any): boolean => {
    const rawMessage = String(error?.message || error?.details || error || '').toUpperCase();
    const dbCode = String(error?.code || '');
    return rawMessage.includes('APPEND_ALREADY_APPLIED') || rawMessage.includes('IDEMPOTENCY_VIOLATION') || dbCode === '23505';
};

export const isWalletLockError = (error: any): boolean => {
    const rawMessage = String(error?.message || error?.details || error || '').toUpperCase();
    return rawMessage.includes('WALLET_LOCKED') || rawMessage.includes('GOAL_MISSING');
};

export const isInvalidSettlementStateError = (error: any): boolean => {
    const rawMessage = String(error?.message || error?.details || error || '').toUpperCase();
    return rawMessage.includes('INVALID_SETTLEMENT_STATE') || rawMessage.includes('SETTLEMENT_ABORTED') || rawMessage.includes('SETTLEMENT_ERROR');
};

export const isInsufficientFundsError = (error: any): boolean => {
    const rawMessage = String(error?.message || error?.details || error || '').toUpperCase();
    return rawMessage.includes('INSUFFICIENT_FUNDS');
};

export const isConcurrencyConflictError = (error: any): boolean => {
    const rawMessage = String(error?.message || error?.details || error || '').toUpperCase();
    const dbCode = String(error?.code || '');
    return (
        dbCode === '40001' ||
        dbCode === '40P01' ||
        rawMessage.includes('COULD NOT SERIALIZE ACCESS') ||
        rawMessage.includes('DEADLOCK DETECTED') ||
        rawMessage.includes('CONCURRENT')
    );
};

export const normalizeFinancialAuthorityError = (error: any, context: string = 'FINANCIAL_AUTHORITY'): Error => {
    const rawMessage = String(error?.message || error?.details || error || 'UNKNOWN_ERROR');

    if (isInsufficientFundsError(error)) {
        return new Error(`INSUFFICIENT_FUNDS: ${context} rejected the request because the authoritative SQL balance check found insufficient funds.`);
    }

    if (isIdempotencyViolationError(error)) {
        return new Error(`IDEMPOTENCY_VIOLATION: ${context} rejected a duplicate financial mutation.`);
    }

    if (isWalletLockError(error)) {
        return new Error(`LOCKED_WALLET: ${context} could not proceed because one of the financial containers is locked or unavailable.`);
    }

    if (isInvalidSettlementStateError(error)) {
        return new Error(`INVALID_SETTLEMENT_STATE: ${context} cannot continue because the settlement is no longer in a valid state.`);
    }

    if (isConcurrencyConflictError(error)) {
        return new Error(`CONCURRENCY_CONFLICT: ${context} conflicted with another financial update. Retry with the same idempotency key.`);
    }

    return new Error(`${context}: ${rawMessage}`);
};

export const isSettlementEligibleStatus = (status: string | null | undefined): boolean =>
    String(status || '').toLowerCase() === FINANCIAL_INVARIANTS.settlementEligibleStatus;

export const assertSettlementEligible = (params: {
    txId: string;
    txExists: boolean;
    status?: string | null;
    hasInternalVault?: boolean;
}) => {
    if (!params.txExists) {
        throw new Error(`INVALID_SETTLEMENT_STATE: Transaction ${params.txId} was not found for settlement.`);
    }

    if (String(params.status || '').toLowerCase() === 'completed') {
        return;
    }

    if (!isSettlementEligibleStatus(params.status)) {
        throw new Error(`INVALID_SETTLEMENT_STATE: Transaction ${params.txId} is ${params.status}, expected ${FINANCIAL_INVARIANTS.settlementEligibleStatus}.`);
    }

    if (params.hasInternalVault === false) {
        throw new Error(`INVALID_SETTLEMENT_STATE: Transaction ${params.txId} is missing its internal settlement vault.`);
    }
};

export const isReversalEligibleStatus = (status: string | null | undefined): boolean =>
    !FINANCIAL_INVARIANTS.reversalBlockedStatuses.has(String(status || '').toLowerCase());

export const assertReversalEligible = (status: string | null | undefined) => {
    if (!isReversalEligibleStatus(status)) {
        throw new Error('TRANSACTION_NOT_REVERSIBLE');
    }
};
