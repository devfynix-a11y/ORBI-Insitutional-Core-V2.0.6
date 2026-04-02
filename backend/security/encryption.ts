
import { DataProtection } from './DataProtection.js';
import { CryptoBoundaryError, decryptEnvelope, encryptEnvelope } from './CryptoEnvelope.js';

export enum VaultError {
    INTEGRITY_FAIL = "[Security Integrity Error]",
    HEALING_REQUIRED = "SENTINEL_HEALING_REQUIRED",
    DECRYPTION_FAILED = "DECRYPTION_FAILED",
    KMS_OFFLINE = "KMS_NODE_OFFLINE"
}

/**
 * ORBI INSTITUTIONAL ENCRYPTION ENGINE (V13.0)
 */
export const DataVault = {
    encrypt: async (value: any, context: Record<string, any> = {}): Promise<string> => {
        if (value === null || value === undefined) return '';
        try {
            return await encryptEnvelope(value, 'DATA_AT_REST', context);
        } catch (e: any) {
            console.error("[Vault] Encryption protocol failure:", e);
            throw e; 
        }
    },

    /**
     * DECRYPT WITH SELF-HEALING PROTOCOL
     */
    decrypt: async (cipher: string): Promise<any> => {
        if (!cipher || typeof cipher !== 'string' || !cipher.startsWith('enc_v')) return cipher;

        try {
            return await decryptEnvelope(cipher);
        } catch (e: any) {
            console.error("[Vault] Decryption integrity failure:", e);
            if (e instanceof CryptoBoundaryError && e.code === 'HEALING_REQUIRED') {
                return VaultError.HEALING_REQUIRED;
            }
            return VaultError.INTEGRITY_FAIL;
        }
    },

    /**
     * RE-KEY DATA TO LATEST VERSION
     */
    reKey: async (cipher: string): Promise<string> => {
        if (!cipher || !cipher.startsWith('enc_v')) return cipher;
        
        const decrypted = await DataVault.decrypt(cipher);
        if (decrypted === VaultError.INTEGRITY_FAIL || decrypted === VaultError.HEALING_REQUIRED) {
            return cipher; // Cannot re-key what we can't decrypt
        }
        
        // Re-encrypting will use the latest active key
        return await DataProtection.encryptValue(decrypted);
    },

    /**
     * RECURSIVE TRANSLATION ENGINE
     */
    translate: async (input: any): Promise<any> => {
        if (input === null || input === undefined) return input;
        
        if (typeof input === 'string' && input.startsWith('enc_v')) {
            return await DataVault.decrypt(input);
        }
        
        if (Array.isArray(input)) {
            return await Promise.all(input.map(item => DataVault.translate(item)));
        }
        
        if (typeof input === 'object') {
            const keys = Object.keys(input);
            const values = await Promise.all(keys.map(k => DataVault.translate(input[k])));
            
            const res: any = {};
            for (let i = 0; i < keys.length; i++) {
                const k = keys[i];
                const val = values[i];
                
                // ORBI TRANSLATION MAPPING: Snake to Camel for UI consistency
                let mappedKey = k;
                if (k === 'wallet_id') mappedKey = 'walletId';
                else if (k === 'to_wallet_id') mappedKey = 'toWalletId';
                else if (k === 'category_id') mappedKey = 'categoryId';
                else if (k === 'created_at') mappedKey = 'createdAt';
                else if (k === 'updated_at') mappedKey = 'updatedAt';
                else if (k === 'status_notes') mappedKey = 'statusNotes';

                const isNumeric = /amount|balance|target|current|budget|vat|fee|rate/i.test(k);
                if (val === VaultError.INTEGRITY_FAIL || val === VaultError.HEALING_REQUIRED) {
                    res[mappedKey] = isNumeric ? 0 : "🔒 Protected Node";
                } else {
                    res[mappedKey] = val;
                }
            }
            return res;
        }
        return input;
    }
};
