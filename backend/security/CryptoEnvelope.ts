import { EncryptedData } from '../../types.js';
import { KMS, KeyType } from './kms.js';

export class CryptoBoundaryError extends Error {
    public readonly code: string;

    constructor(code: string, message?: string) {
        super(message || code);
        this.name = 'CryptoBoundaryError';
        this.code = code;
    }
}

export type CryptoDomain =
    | 'DATA_AT_REST'
    | 'FINANCIAL_AMOUNT'
    | 'FINANCIAL_DESCRIPTION'
    | 'PROVIDER_SECRET'
    | 'PROVIDER_TOKEN'
    | 'MESSAGE_CONTENT';

type EnvelopeKeyFamily = 'ENCRYPTION' | 'SECRET_WRAPPING';

export const ENCRYPTED_PREFIX = 'enc_v2_';

const toBase64 = (d: ArrayBuffer | Uint8Array) => Buffer.from(new Uint8Array(d)).toString('base64');
const fromBase64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

export function isEncryptedEnvelope(value: unknown): value is string {
    return typeof value === 'string' && value.startsWith('enc_v');
}

export async function encryptEnvelope(
    value: unknown,
    domain: CryptoDomain,
    context: Record<string, any> = {},
    keyFamily: EnvelopeKeyFamily = 'ENCRYPTION',
): Promise<string> {
    if (value === null || value === undefined) return '';
    if (isEncryptedEnvelope(value)) return value;

    await KMS.waitReady();
    const key = await KMS.getActiveKey(keyFamily as KeyType);
    if (!key) {
        throw new CryptoBoundaryError('KMS_OFFLINE', 'Encryption key unavailable');
    }

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const payloadData = encoder.encode(JSON.stringify({
        v: value,
        ts: Date.now(),
        ctx: {
            domain,
            ...context,
        },
    }));
    const aad = encoder.encode(JSON.stringify({
        v: KMS.getActiveVersion('ENCRYPTION'),
        origin: 'ORBI_V3_CORE',
        domain,
    }));

    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        key,
        payloadData,
    );
    const combined = new Uint8Array(encrypted);
    const ciphertext = combined.slice(0, combined.byteLength - 16);
    const tag = combined.slice(combined.byteLength - 16);
    const envelope: EncryptedData = {
        version: KMS.getActiveVersion('ENCRYPTION'),
        iv: toBase64(iv),
        ciphertext: toBase64(ciphertext),
        tag: toBase64(tag),
        timestamp: Date.now(),
        keyId: 'p-node-active',
        algorithm: 'AES-GCM-256',
        aad: toBase64(aad),
    };

    return `${ENCRYPTED_PREFIX}${Buffer.from(JSON.stringify(envelope)).toString('base64')}`;
}

export async function decryptEnvelope(cipher: string, keyFamily: EnvelopeKeyFamily = 'ENCRYPTION'): Promise<unknown> {
    if (!isEncryptedEnvelope(cipher)) return cipher;

    await KMS.waitReady();
    const rawPayload = cipher.replace('enc_v2_', '').replace('enc_v1_', '');
    let payload: EncryptedData;
    try {
        payload = JSON.parse(Buffer.from(rawPayload, 'base64').toString('utf-8'));
    } catch (error) {
        throw new CryptoBoundaryError('INTEGRITY_FAIL', `Encrypted payload parse failure: ${String(error)}`);
    }

    const key = await KMS.getKeyByVersion(keyFamily as KeyType, payload.version);
    if (!key) {
        throw new CryptoBoundaryError('HEALING_REQUIRED', `Missing encryption key version ${payload.version}`);
    }

    const iv = fromBase64(payload.iv);
    const ciphertext = fromBase64(payload.ciphertext);
    const tag = payload.tag ? fromBase64(payload.tag) : new Uint8Array(0);
    const aad = payload.aad ? fromBase64(payload.aad) : undefined;
    const encrypted = new Uint8Array(ciphertext.length + tag.length);
    encrypted.set(ciphertext);
    encrypted.set(tag, ciphertext.length);

    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
            key,
            encrypted,
        );
        const packet = JSON.parse(new TextDecoder().decode(decrypted));
        return packet.v;
    } catch (error) {
        throw new CryptoBoundaryError('INTEGRITY_FAIL', `Encrypted payload decrypt failure: ${String(error)}`);
    }
}
