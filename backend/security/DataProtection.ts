import { decryptEnvelope, encryptEnvelope, CryptoBoundaryError, isEncryptedEnvelope } from './CryptoEnvelope.js';

export class DataProtectionService {
    async encryptValue(value: unknown, context: Record<string, any> = {}): Promise<string> {
        return encryptEnvelope(value, 'DATA_AT_REST', context);
    }

    async decryptValue<T = unknown>(cipher: string): Promise<T> {
        return await decryptEnvelope(cipher) as T;
    }

    async encryptAmount(amount: number, context: Record<string, any> = {}): Promise<string> {
        return encryptEnvelope(amount, 'FINANCIAL_AMOUNT', context);
    }

    async decryptAmount(cipher: unknown, fallback = 0): Promise<number> {
        if (cipher === null || cipher === undefined || cipher === '') return fallback;
        if (typeof cipher === 'number') return cipher;
        const decrypted = isEncryptedEnvelope(cipher) ? await decryptEnvelope(cipher) : cipher;
        const numeric = Number(decrypted);
        if (Number.isNaN(numeric)) {
            throw new CryptoBoundaryError('INVALID_FINANCIAL_AMOUNT', `Amount is not numeric: ${String(decrypted)}`);
        }
        return numeric;
    }

    async encryptDescription(description: string, context: Record<string, any> = {}): Promise<string> {
        return encryptEnvelope(description, 'FINANCIAL_DESCRIPTION', context);
    }

    async decryptDescription(cipher: unknown, fallback = ''): Promise<string> {
        if (cipher === null || cipher === undefined || cipher === '') return fallback;
        if (typeof cipher !== 'string') return String(cipher);
        const decrypted = isEncryptedEnvelope(cipher) ? await decryptEnvelope(cipher) : cipher;
        return String(decrypted ?? fallback);
    }

    async encryptMessageContent(value: string, context: Record<string, any> = {}): Promise<string> {
        return encryptEnvelope(value, 'MESSAGE_CONTENT', context);
    }

    async decryptMessageContent(cipher: unknown, fallback = ''): Promise<string> {
        if (cipher === null || cipher === undefined || cipher === '') return fallback;
        if (typeof cipher !== 'string') return String(cipher);
        const decrypted = isEncryptedEnvelope(cipher) ? await decryptEnvelope(cipher) : cipher;
        return String(decrypted ?? fallback);
    }
}

export const DataProtection = new DataProtectionService();
