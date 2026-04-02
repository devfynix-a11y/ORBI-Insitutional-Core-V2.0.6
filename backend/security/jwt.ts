
import { AuthTokens } from './AuthTokenCrypto.js';
import { getSupabase } from '../supabaseClient.js';

export class JWTNode {
    // In-memory blocklist for fast lookups. Hydrated from DB.
    private static blocklist: Set<string> = new Set();
    private static blocklistHydrated = false;

    public static async sign(payload: any, expiresInSeconds: number = 900): Promise<string> {
        const header = { alg: 'HS256', typ: 'JWT' };
        const encodedHeader = AuthTokens.encodeSegment(header);
        
        const now = Math.floor(Date.now() / 1000);
        const jwtPayload = {
            ...payload,
            iat: now,
            exp: now + expiresInSeconds,
            jti: crypto.randomUUID() // Unique JWT ID for revocation
        };
        
        const encodedPayload = AuthTokens.encodeSegment(jwtPayload);
        const encodedSig = await AuthTokens.signSegments(encodedHeader, encodedPayload);
        return `${encodedHeader}.${encodedPayload}.${encodedSig}`;
    }

    private static async hydrateBlocklist() {
        const sb = getSupabase();
        if (sb) {
            try {
                const { data } = await sb.from('revoked_tokens').select('jti');
                if (data) {
                    data.forEach(row => this.blocklist.add(row.jti));
                }
                this.blocklistHydrated = true;
            } catch (e) {
                console.error("[JWT] Failed to hydrate blocklist", e);
            }
        }
    }

    public static async verify<T>(token: string): Promise<T | null> {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return null;
            
            const isValid = await AuthTokens.verifySegments(parts[0], parts[1], parts[2]);
            if (!isValid) return null;
            const payload = AuthTokens.decodeSegment(parts[1]);
            
            // 1. Check Expiration
            if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
                return null; // Token expired
            }
            
            // 2. Check Blocklist (Revocation)
            if (payload.jti) {
                if (!this.blocklistHydrated) {
                    await this.hydrateBlocklist();
                }
                if (this.blocklist.has(payload.jti)) {
                    console.warn(`[JWT] Attempted use of revoked token: ${payload.jti}`);
                    return null; // Token revoked
                }
            }
            
            return payload;
        } catch (e) { return null; }
    }

    /**
     * Revokes a token by adding its JTI to the blocklist.
     */
    public static async revoke(jti: string): Promise<void> {
        this.blocklist.add(jti);
        console.info(`[JWT] Token revoked: ${jti}`);
        
        // Persist to DB for distributed revocation
        const sb = getSupabase();
        if (sb) {
            try {
                await sb.from('revoked_tokens').insert({ jti });
            } catch (e) {
                console.error("[JWT] Failed to persist revoked token", e);
            }
        }
    }
}
