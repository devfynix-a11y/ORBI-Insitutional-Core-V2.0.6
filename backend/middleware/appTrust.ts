import { Request, Response, NextFunction } from 'express';
import { normalizeAndroidHash } from '../security/passkeyUtils.js';
import { TRUSTED_APP_IDS, TRUSTED_APP_ORIGINS } from '../config/appIdentity.js';

/**
 * ORBI TRUSTED DOMAINS
 * List of verified web origins allowed to communicate with the Sovereign Node.
 */
const isProd = process.env.NODE_ENV === 'production';
const configuredTrustedDomains = [
    process.env.RP_ID,
    process.env.ORBI_WEB_ORIGIN,
    process.env.BACKEND_URL,
    ...(process.env.ORBI_ALLOWED_ORIGINS || '').split(','),
]
    .map((value) => String(value || '').trim())
    .filter(Boolean)
    .map((value) => {
        try {
            if (/^https?:\/\//i.test(value)) {
                return new URL(value).hostname;
            }
            return value.replace(/^https?:\/\//i, '').split('/')[0];
        } catch {
            return value;
        }
    });

export const ALLOWED_DOMAINS = Array.from(new Set([
    ...configuredTrustedDomains,
    ...(isProd ? [] : ['localhost', '127.0.0.1']),
]));

const ALLOWED_IOS_BUNDLE_IDS = (process.env.ORBI_IOS_BUNDLE_IDS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);

const resolveTrustedAppRequest = (
    appIdHeader: string,
    appOriginHeader: string,
    origin: string,
) => {
    const isTrustedOrigin =
        TRUSTED_APP_ORIGINS.includes(origin) ||
        TRUSTED_APP_ORIGINS.includes(appOriginHeader);
    const isTrustedId = TRUSTED_APP_IDS.includes(appIdHeader);
    return {
        isTrustedOrigin,
        isTrustedId,
        isTrustedApp: isTrustedOrigin && isTrustedId,
    };
};

const isTrustedIosBundleOrigin = (origin: string) => {
    if (!origin.startsWith('ios:bundle-id:')) return false;
    const bundleId = origin.replace('ios:bundle-id:', '').trim();
    return bundleId.length > 0 && ALLOWED_IOS_BUNDLE_IDS.includes(bundleId);
};

/**
 * APP TRUST MIDDLEWARE
 * --------------------
 * Ensures that requests originate from trusted web domains or the official 
 * signed Android/iOS applications.
 */
export const appTrustMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const protectedPrefixes = [
        '/api',
        '/v1',
        '/auth',
        '/user',
        '/wallets',
        '/transactions',
        '/goals',
        '/categories',
        '/tasks',
        '/notifications',
        '/fx',
        '/escrow',
        '/merchants',
        '/receipt',
        '/sys',
        '/sandbox',
    ];
    const isProtectedApiPath = protectedPrefixes.some(
        (prefix) => req.path === prefix || req.path.startsWith(`${prefix}/`),
    );

    // 1. Skip for non-API routes (assets, static files)
    if (!isProtectedApiPath) return next();
    
    // 2. Skip for health checks and public telemetry
    if (req.path === '/health' || req.path === '/api/health' || req.path === '/api/broker/health') {
        return next();
    }

    const rpID = req.hostname;
    const origin = req.get('origin') || req.get('referer') || '';
    const apkHashHeader = req.get('x-orbi-apk-hash'); // Custom header for native app identification
    const appIdHeader = req.get('x-orbi-app-id') || ''; // App ID identification
    const appOriginHeader = req.get('x-orbi-app-origin') || '';

    const isLocal = !isProd && (rpID === 'localhost' || rpID === '127.0.0.1');
    
    // 3. Route-Aware Logic
    
    // 3a. Passkey/WebAuthn endpoints: Skip hash check here, let controller handle it via clientDataJSON
    if (req.path.includes('/auth/passkey/') || req.path.includes('/auth/biometric/')) {
        // Only allow trusted domains or local for passkey operations
        if (ALLOWED_DOMAINS.includes(rpID) || isLocal) {
            return next();
        }
    }

    // 3b. Web Browser & Mobile App Requests: Require exact allowed Origin/Referer host
    // In production, we don't trust all *.run.app hosts.
    const isWebOrigin = ALLOWED_DOMAINS.some(domain => origin.includes(domain));
    const { isTrustedOrigin, isTrustedId, isTrustedApp } = resolveTrustedAppRequest(
        appIdHeader,
        appOriginHeader,
        origin,
    );
    
    if (isWebOrigin || isLocal || isTrustedApp) {
        return next();
    }

    // 4. Android Native REST Requests: Require x-orbi-apk-hash
    const expectedHash = process.env.ORBI_ANDROID_APP_HASH?.replace(/['"]/g, '');
    const normalizedExpected = normalizeAndroidHash(expectedHash || '');
    
    if (expectedHash && normalizeAndroidHash(apkHashHeader || '') === normalizedExpected) {
        return next();
    }

    // 5. Check Android Biometric Origin (Fallback for non-REST biometric calls)
    if (expectedHash && origin.startsWith('android:apk-key-hash:')) {
        const incomingHash = origin.replace('android:apk-key-hash:', '');
        if (normalizeAndroidHash(incomingHash) === normalizedExpected) {
            return next();
        }
    }

    // 6. Check iOS Bundle Trust
    if (isTrustedIosBundleOrigin(origin)) {
        return next(); 
    }

    // 7. Security Rejection
    const rejectionReason = !isWebOrigin && !isLocal && !apkHashHeader ? 'Missing Origin/Hash' : 
                           apkHashHeader && apkHashHeader !== expectedHash ? 'Invalid APK Hash' :
                           !isTrustedOrigin ? 'Untrusted App Origin' :
                           !isTrustedId ? 'Untrusted App ID' :
                           'Untrusted Origin';

    console.warn(`[Security] Untrusted request blocked: 
        Path=${req.path}
        Method=${req.method}
        IP=${req.ip}
        Origin=${origin}
        RP=${rpID}
        App_ID_Header=${appIdHeader || 'Missing'}
        APK_Hash_Header=${apkHashHeader ? 'Present' : 'Missing'}
        Expected_Hash=${expectedHash ? 'Configured' : 'Not Configured'}
        Reason=${rejectionReason}
        User-Agent=${req.get('user-agent')}
    `);
    
    return res.status(403).json({ 
        success: false, 
        error: 'SECURITY_VIOLATION', 
        message: 'Untrusted application origin. Please use the official Orbi app.' 
    });
};
