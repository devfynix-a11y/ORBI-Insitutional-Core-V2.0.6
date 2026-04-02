
import { TransactionStatus } from '../../types.js';
import { EventBus } from '../infrastructure/EventBus.js';

export interface SagaStep<T = any> {
    name: string;
    execute: (context: T) => Promise<void>;
    compensate: (context: T) => Promise<void>;
}

export class SagaOrchestrator<T = any> {
    private steps: SagaStep<T>[] = [];
    private executedSteps: SagaStep<T>[] = [];

    constructor(private context: T, private sagaId: string) {}

    public addStep(step: SagaStep<T>): this {
        this.steps.push(step);
        return this;
    }

    public async execute(): Promise<boolean> {
        console.info(`[Saga] Starting Saga execution: ${this.sagaId}`);
        for (const step of this.steps) {
            try {
                console.info(`[Saga] Executing step: ${step.name}`);
                await step.execute(this.context);
                this.executedSteps.push(step);
            } catch (error) {
                console.error(`[Saga] Step ${step.name} failed. Initiating compensation. Error:`, error);
                await this.compensate();
                return false; // Saga failed
            }
        }
        console.info(`[Saga] Saga execution completed successfully: ${this.sagaId}`);
        return true; // Saga succeeded
    }

    private async compensate(): Promise<void> {
        console.warn(`[Saga] Compensating Saga: ${this.sagaId}`);
        // Compensate in reverse order
        for (let i = this.executedSteps.length - 1; i >= 0; i--) {
            const step = this.executedSteps[i];
            try {
                console.info(`[Saga] Compensating step: ${step.name}`);
                await step.compensate(this.context);
            } catch (error) {
                console.error(`[Saga] CRITICAL: Compensation failed for step ${step.name}. Manual intervention required!`, error);
                // In a real banking system, this triggers a P0 alert to operations
                EventBus.getInstance().emit('alert:critical' as any, {
                    type: 'SAGA_COMPENSATION_FAILED',
                    sagaId: this.sagaId,
                    step: step.name,
                    error
                });
            }
        }
    }
}

export class TransactionStateMachine {
    private static readonly VALID_TRANSITIONS: Record<TransactionStatus, TransactionStatus[]> = {
        'created': ['created', 'pending', 'failed', 'cancelled', 'held_for_review'],
        'pending': ['authorized', 'failed', 'cancelled', 'held_for_review', 'processing', 'completed'],
        'authorized': ['processing', 'failed', 'reversed', 'completed', 'held_for_review'],
        'processing': ['settled', 'failed', 'reversed', 'completed', 'held_for_review'],
        'settled': ['completed', 'reversed', 'refunded'],
        'completed': ['reversed', 'refunded', 'held_for_review'],
        'failed': [],
        'reversed': ['refunded'],
        'refunded': [],
        'cancelled': [],
        'held_for_review': ['pending', 'authorized', 'failed', 'cancelled', 'completed', 'reversed']
    };

    /**
     * Validates if a transition from currentStatus to nextStatus is allowed.
     */
    public static isValidTransition(currentStatus: TransactionStatus, nextStatus: TransactionStatus): boolean {
        const allowed = this.VALID_TRANSITIONS[currentStatus];
        return allowed ? allowed.includes(nextStatus) : false;
    }

    /**
     * Transitions a transaction to a new state and emits an event.
     */
    public static transition(txId: string, currentStatus: TransactionStatus, nextStatus: TransactionStatus, metadata: any = {}): void {
        if (currentStatus === nextStatus) {
            console.info(`[StateMachine] Skipping no-op transition for TX ${txId}: ${currentStatus}`);
            return;
        }

        if (!this.isValidTransition(currentStatus, nextStatus)) {
            throw new Error(`INVALID_STATE_TRANSITION: Cannot move from ${currentStatus} to ${nextStatus} for TX ${txId}`);
        }

        console.info(`[StateMachine] Transitioning TX ${txId}: ${currentStatus} -> ${nextStatus}`);
        
        const eventBus = EventBus.getInstance();
        eventBus.emit(`transaction:${nextStatus}` as any, {
            txId,
            oldState: currentStatus,
            newState: nextStatus,
            metadata,
            ts: Date.now()
        });
    }

    /**
     * Gets the next logical state based on the current state and success/failure.
     */
    public static getNextState(currentStatus: TransactionStatus, success: boolean): TransactionStatus {
        if (!success) return 'failed';

        switch (currentStatus) {
            case 'created': return 'pending';
            case 'pending': return 'authorized';
            case 'authorized': return 'processing';
            case 'processing': return 'settled';
            case 'settled': return 'completed';
            default: return currentStatus;
        }
    }

    /**
     * Determines if the state is terminal (no further transitions allowed).
     */
    public static isTerminal(status: TransactionStatus): boolean {
        return ['completed', 'failed', 'cancelled', 'refunded'].includes(status);
    }
}
