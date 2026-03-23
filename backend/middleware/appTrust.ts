import { Request, Response, NextFunction } from 'express';
import { normalizeAndroidHash } from '../security/passkeyUtils.js';

/**
 * ORBI TRUSTED DOMAINS
 * List of verified web origins allowed to communicate with the Sovereign Node.
 */
export const ALLOWED_DOMAINS = [
    'orbi-financial-technologies-c0re-v2026.onrender.com',
    'localhost',
    '127.0.0.1'
];

const TRUSTED_MOBILE_APP_ORIGINS = [
    process.env.ORBI_MOBILE_ORIGIN,
    'ORBI_MOBILE_V2026',
].filter((value): value is string => Boolean(value && value.trim()));

/**
 * APP TRUST MIDDLEWARE
 * --------------------
 * Ensures that requests originate from trusted web domains or the official 
 * signed Android/iOS applications.
 */
export const appTrustMiddleware = (req: Request, res: Response, next: NextFunction) => {
    // 1. Skip for non-API routes (assets, static files)
    if (!req.path.startsWith('/api')) return next();
    
    // 2. Skip for health checks and public telemetry
    if (req.path === '/health' || req.path === '/api/health' || req.path === '/api/broker/health') {
        return next();
    }

    const rpID = req.hostname;
    const origin = req.get('origin') || req.get('referer') || '';
    const apkHashHeader = req.get('x-orbi-apk-hash'); // Custom header for native app identification
    const appIdHeader = req.get('x-orbi-app-id'); // App ID identification
    const appOriginHeader = req.get('x-orbi-app-origin') || '';

    const isLocal = rpID === 'localhost' || rpID === '127.0.0.1';
    
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
    const isMobileApp =
        TRUSTED_MOBILE_APP_ORIGINS.includes(origin) ||
        TRUSTED_MOBILE_APP_ORIGINS.includes(appOriginHeader);
    const isTrustedMobileId = appIdHeader === 'mobile-android' && isMobileApp;
    
    if (isWebOrigin || isLocal || isMobileApp || isTrustedMobileId) {
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

    // 6. Check iOS Bundle Trust (Placeholder)
    if (origin.startsWith('ios:bundle-id:')) {
        return next(); 
    }

    // 7. Security Rejection
    const rejectionReason = !isWebOrigin && !isLocal && !apkHashHeader ? 'Missing Origin/Hash' : 
                           apkHashHeader && apkHashHeader !== expectedHash ? 'Invalid APK Hash' :
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
