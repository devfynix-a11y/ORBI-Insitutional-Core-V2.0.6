import { KMS } from './kms.js';

const toBase64Url = (input: string) =>
    Buffer.from(input, 'utf8').toString('base64url');
const fromBase64Url = (input: string) =>
    Buffer.from(input, 'base64url').toString('utf8');

export class AuthTokenCrypto {
    private async getKey(): Promise<CryptoKey> {
        await KMS.waitReady();
        const key = await KMS.getActiveKey('AUTH');
        if (!key) {
            throw new Error('AUTH_KEY_OFFLINE');
        }
        return key;
    }

    encodeSegment(value: Record<string, any>): string {
        return toBase64Url(JSON.stringify(value));
    }

    decodeSegment<T = any>(value: string): T {
        return JSON.parse(fromBase64Url(value)) as T;
    }

    async signSegments(encodedHeader: string, encodedPayload: string): Promise<string> {
        const key = await this.getKey();
        const data = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);
        const sig = await crypto.subtle.sign({ name: 'HMAC' }, key, data);
        return Buffer.from(new Uint8Array(sig)).toString('base64url');
    }

    async verifySegments(encodedHeader: string, encodedPayload: string, signature: string): Promise<boolean> {
        const key = await this.getKey();
        const data = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);
        const sig = new Uint8Array(Buffer.from(signature, 'base64url'));
        return crypto.subtle.verify({ name: 'HMAC' }, key, sig, data);
    }
}

export const AuthTokens = new AuthTokenCrypto();
