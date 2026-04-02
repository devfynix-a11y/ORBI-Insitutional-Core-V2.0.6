import { KMS } from './kms.js';

export class SignatureService {
    async sign(payload: string): Promise<string> {
        await KMS.waitReady();
        const key = await KMS.getActiveKey('SIGNING');
        if (!key) {
            throw new Error('SIGNING_KEY_OFFLINE');
        }

        const algorithm = key.algorithm.name === 'ECDSA'
            ? { name: 'ECDSA', hash: { name: 'SHA-256' } }
            : { name: 'HMAC' };

        const signature = await crypto.subtle.sign(algorithm, key, new TextEncoder().encode(payload));
        return Buffer.from(new Uint8Array(signature)).toString('base64');
    }
}

export const Signatures = new SignatureService();
