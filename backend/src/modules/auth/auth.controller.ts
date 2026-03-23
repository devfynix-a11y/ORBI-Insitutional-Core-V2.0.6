import { Request, Response } from "express";
import { Passkeys } from "../passkey/passkey.service.js";
import { Fingerprint } from "../../services/fingerprint.service.js";
import { Behavior } from "../../services/behavior.service.js";
import { Risk } from "../../services/risk.service.js";
import { Fraud } from "../../services/fraud.service.js";
import { Sessions } from "../session/session.service.js";
import { Attestation } from "../device/attestation.service.js";
import { AIFraud } from "../fraud/ai-fraud.service.js";
import { HSM } from "../security/hsm.service.js";
import { getAdminSupabase } from "../../../supabaseClient.js";
import { OTPService } from "../../../security/otpService.js";
import { Messaging } from "../../../features/MessagingService.js";
import { Audit } from "../../../security/audit.js";
import { normalizeAndroidOrigin, sameTrustedOrigin } from "../../../security/passkeyUtils.js";
import { ALLOWED_DOMAINS } from "../../../middleware/appTrust.js";

const cleanAndroidHash = process.env.ORBI_ANDROID_APP_HASH?.replace(/['"]/g, '');
const EXPECTED_ANDROID_ORIGIN = cleanAndroidHash ? `android:apk-key-hash:${cleanAndroidHash}` : '';
const ALLOWED_APK_HASHES = EXPECTED_ANDROID_ORIGIN ? [normalizeAndroidOrigin(EXPECTED_ANDROID_ORIGIN)] : [];
const TRUSTED_MOBILE_APP_ORIGINS = [
    process.env.ORBI_MOBILE_ORIGIN,
    'ORBI_MOBILE_V2026',
].filter((value): value is string => Boolean(value && value.trim()));

const isTrustedMobileAppIdentity = (appIdentity: string) =>
    TRUSTED_MOBILE_APP_ORIGINS.includes(appIdentity);

const validateBiometricContext = (req: any) => {
    // Strictly use the specified domain for both prod and dev
    const finalRpId = process.env.RP_ID || 'orbi-financial-technologies-c0re-v2026.onrender.com';
    
    let origin = '';

    // 1. Always prefer clientDataJSON for the true WebAuthn origin
    if (req.body.response?.response?.clientDataJSON) {
        try {
            const base64 = req.body.response.response.clientDataJSON;
            const normalizedBase64 = base64.replace(/-/g, '+').replace(/_/g, '/');
            const clientData = JSON.parse(Buffer.from(normalizedBase64, 'base64').toString('utf8'));
            if (clientData.origin) {
                origin = clientData.origin;
            }
        } catch (e) {
            console.warn("Failed to parse clientDataJSON for origin", e);
        }
    }

    // 2. Fallback to explicit body origin if provided (e.g. during startPasskeyRegistration)
    if (!origin && req.body.origin && (req.body.origin.startsWith('http') || req.body.origin.startsWith('android:') || req.body.origin.startsWith('ios:'))) {
        origin = req.body.origin;
    }

    // 3. Fallback to header origin if it's a valid WebAuthn origin format
    if (!origin) {
        const headerOrigin = req.get('origin');
        if (headerOrigin && (headerOrigin.startsWith('http') || headerOrigin.startsWith('android:') || headerOrigin.startsWith('ios:'))) {
            origin = headerOrigin;
        }
    }

    // App Identity Metadata (Separate from WebAuthn Origin)
    const appIdentity = req.get('x-orbi-app-origin') || req.get('origin') || req.body.origin;
    const isMobileApp = isTrustedMobileAppIdentity(appIdentity);
    const appIdHeader = req.get('x-orbi-app-id');
    const isTrustedMobileId = appIdHeader === 'mobile-android' && isMobileApp;

    // 4. Final fallback
    if (!origin) {
        if (isTrustedMobileId && cleanAndroidHash) {
            origin = `android:apk-key-hash:${cleanAndroidHash}`;
        } else {
            origin = process.env.ORBI_WEB_ORIGIN || `https://${req.get('host')}`;
        }
    }

    const isLocal = finalRpId === 'localhost' || finalRpId === '127.0.0.1';
    
    if (!ALLOWED_DOMAINS.includes(finalRpId) && !isLocal) {
        console.error(`[Security] Untrusted Domain Rejection:
            RP_ID=${finalRpId}
            IP=${req.ip}
            Path=${req.path}
            Origin=${origin}
        `);
        const err: any = new Error(`SECURITY_VIOLATION: Untrusted Domain [${finalRpId}]`);
        err.status = 403;
        throw err;
    }

    const isAndroidHash = origin.startsWith('android:apk-key-hash:');
    
    const isIosBundle = origin.startsWith('ios:bundle-id:');
    
    const isWebOrigin = origin.includes(finalRpId);

    if (isAndroidHash) {
        if (!ALLOWED_APK_HASHES.includes(normalizeAndroidOrigin(origin))) {
            console.error(`[Security] Untrusted APK Hash Rejection:
                Origin=${origin}
                AppIdentity=${appIdentity}
                IP=${req.ip}
                Path=${req.path}
            `);
            const err: any = new Error(`SECURITY_VIOLATION: Untrusted APK Hash [${origin}]`);
            err.status = 403;
            throw err;
        }
    } else if (!isWebOrigin && !isIosBundle && !isTrustedMobileId) {
         console.error(`[Security] Untrusted Origin Rejection:
            Origin=${origin}
            RP_ID=${finalRpId}
            AppIdentity=${appIdentity}
            App_ID_Header=${appIdHeader || 'Missing'}
            IP=${req.ip}
            Path=${req.path}
         `);
         const err: any = new Error(`SECURITY_VIOLATION: Untrusted Origin [${origin}]`);
         err.status = 403;
         throw err;
    }

    return { rpID: finalRpId, origin };
};

export class AuthController {
    async startPasskeyLogin(req: Request, res: Response) {
        try {
            const { userId } = req.body;
            if (!userId) return res.status(400).json({ error: "User ID required" });

            const { rpID } = validateBiometricContext(req);
            const options = await Passkeys.generateLoginOptions(userId, rpID);
            res.json({ success: true, data: options });
        } catch (e: any) {
            console.error(`[Auth] Error in startPasskeyLogin:
                Error=${e.message}
                Stack=${e.stack}
                User_ID=${req.body.userId}
                IP=${req.ip}
            `);
            res.status(e.status || 500).json({ error: e.message });
        }
    }

    async completePasskeyLogin(req: Request, res: Response) {
        try {
            const { userId, response, challenge, device, behaviorMetrics, attestationToken, platform } = req.body;
            
            // 1. Hardware-Backed Key Attestation
            if (attestationToken && platform) {
                const isAttested = await Attestation.verifyDevice(platform, attestationToken);
                if (!isAttested) {
                    console.error(`[Security] Device attestation failed:
                        User_ID=${userId}
                        Platform=${platform}
                        IP=${req.ip}
                    `);
                    return res.status(403).json({ error: "Device attestation failed. Device may be compromised." });
                }
            }

            // 2. Verify Passkey
            const { rpID, origin } = validateBiometricContext(req);
            const appIdentity = req.get('x-orbi-app-origin') || req.get('origin') || req.body.origin;
            const isMobileApp = isTrustedMobileAppIdentity(appIdentity);
            const appIdHeader = req.get('x-orbi-app-id');
            const isTrustedMobile = isMobileApp && appIdHeader === 'mobile-android';
            
            // Fail closed if Android origin is missing on Android biometric completion
            if (platform === 'android' && !origin.startsWith('android:apk-key-hash:') && !isTrustedMobile) {
                console.error(`[Security] Missing Android Origin on Android platform:
                    User_ID=${userId}
                    Origin=${origin}
                    IP=${req.ip}
                `);
                return res.status(403).json({ error: "SECURITY_VIOLATION: Missing Android Origin on Android platform" });
            }

            const verified = await Passkeys.verifyLogin(userId, response, challenge, origin, rpID);
            if (!verified) {
                console.warn(`[Auth] Passkey verification failed for user ${userId}`);
                return res.status(401).json({ error: "Passkey verification failed" });
            }

            // 3. Device Fingerprint Check
            const fingerprint = Fingerprint.generateFingerprint(device);
            const isNewDevice = await Fingerprint.validateDevice(userId, fingerprint);
            
            // If biometric login is successful, we can trust this device
            const sb = getAdminSupabase();
            if (sb) {
                await sb.from('user_devices')
                    .update({ is_trusted: true, last_active_at: new Date().toISOString() })
                    .eq('user_id', userId)
                    .eq('device_fingerprint', fingerprint);
            }

            if (isNewDevice) {
                Messaging.sendNewDeviceAlert(userId, device.model || 'Unknown Device').catch(console.error);
            }

            // 4. Risk Scoring & AI Fraud Detection
            const { data: profile } = await sb!.from('behavior_profiles').select('*').eq('user_id', userId).single();
            
            const behaviorMismatch = profile ? Behavior.behaviorMismatch(profile, behaviorMetrics) : false;

            const riskData = {
                newDevice: isNewDevice,
                newLocation: false, // Would come from IP/Geo logic
                vpnDetected: false, // Would come from IP logic
                behaviorMismatch
            };

            const ruleRiskScore = Risk.calculateRisk(riskData);
            
            // AI Fraud Engine Inference
            const aiRiskScore = await AIFraud.evaluateTransaction({
                loginTime: new Date().toISOString(),
                deviceAgeDays: isNewDevice ? 0 : 30,
                behaviorPatterns: behaviorMetrics,
                transactionAmount: 0, // Login event
                locationHistory: []
            });

            const totalRiskScore = ruleRiskScore + aiRiskScore;
            let decision = Risk.getDecision(totalRiskScore);

            console.log(`[Risk] Decision for user ${userId}:
                Total_Score=${totalRiskScore}
                Rule_Score=${ruleRiskScore}
                AI_Score=${aiRiskScore}
                Decision=${decision}
                New_Device=${isNewDevice}
                Behavior_Mismatch=${behaviorMismatch}
            `);

            if (decision === 'BLOCK') {
                console.warn(`[Security] Login blocked due to high risk: User_ID=${userId}, Score=${totalRiskScore}`);
                return res.status(403).json({ error: "Login blocked due to high risk" });
            }

            // 5. Fraud Detection (Takeover)
            const takeover = Fraud.detectTakeover({ ...riskData, newCountry: false });
            if (takeover) {
                console.error(`[Security] Account takeover detected: User_ID=${userId}`);
                return res.status(403).json({ error: "Account takeover detected" });
            }

            // 6. Session Management (Secure Token Architecture via HSM)
            const sessionToken = await HSM.generateSecureToken(userId, fingerprint);
            const refreshToken = Sessions.createRefreshToken(userId, fingerprint);

            // 7. Require Step-up if needed
            decision = Risk.getDecision(totalRiskScore);
            if (decision === 'REQUIRE_OTP') {
                if (!isNewDevice) {
                    // Skip OTP challenge for trusted device
                    decision = 'ALLOW';
                } else {
                    const { data } = await sb!.auth.admin.getUserById(userId);
                    const contact = data?.user?.phone || data?.user?.email;
                    
                    if (!contact) {
                        return res.status(403).json({ error: "High risk detected, but no contact method available for verification." });
                    }

                    const type = contact.includes('@') ? 'email' : 'sms';
                    const otpResult = await OTPService.generateAndSend(userId, contact, 'LOGIN_STEP_UP', type as any, device.model || 'Unknown Device');

                    if (otpResult.requestId === 'THROTTLED') {
                        return res.status(429).json({ 
                            error: "Too many requests. Please wait 60 seconds before requesting a new OTP." 
                        });
                    }

                    return res.json({ 
                        status: 'STEP_UP_REQUIRED', 
                        tempToken: sessionToken,
                        requestId: otpResult.requestId,
                        message: `High risk detected. Please verify with OTP sent via ${otpResult.deliveryType || type}.` 
                    });
                }
            }

            if (decision === 'ALLOW') {
                await Audit.log('IDENTITY', userId, 'LOGIN_SUCCESS', { device: device.model, platform });
                res.json({
                    success: true,
                    data: {
                        status: 'SUCCESS',
                        access_token: sessionToken,
                        refresh_token: refreshToken
                    }
                });
            } else if (decision === 'BLOCK') {
                // This case should be handled by the initial check, but just in case
                return res.status(403).json({ error: "Login blocked due to high risk" });
            }
        } catch (e: any) {
            console.error(`[Auth] Error in completePasskeyLogin:
                Error=${e.message}
                Stack=${e.stack}
                User_ID=${req.body.userId}
                IP=${req.ip}
            `);
            res.status(e.status || 500).json({ error: e.message });
        }
    }

    async startPasskeyRegistration(req: Request, res: Response) {
        try {
            const { userId, email } = req.body;
            if (!userId) return res.status(400).json({ error: "User ID required" });

            const { rpID } = validateBiometricContext(req);
            const options = await Passkeys.generateRegistration({ id: userId, email }, rpID);
            res.json({ success: true, data: options });
        } catch (e: any) {
            console.error(`[Auth] Error in startPasskeyRegistration:
                Error=${e.message}
                Stack=${e.stack}
                User_ID=${req.body.userId}
                IP=${req.ip}
            `);
            res.status(e.status || 500).json({ error: e.message });
        }
    }

    async completePasskeyRegistration(req: Request, res: Response) {
        try {
            const { userId, response, challenge, platform } = req.body;
            const { rpID, origin } = validateBiometricContext(req);
            const appIdentity = req.get('x-orbi-app-origin') || req.get('origin') || req.body.origin;
            const isMobileApp = isTrustedMobileAppIdentity(appIdentity);
            const appIdHeader = req.get('x-orbi-app-id');
            const isTrustedMobile = isMobileApp && appIdHeader === 'mobile-android';

            // Fail closed if Android origin is missing on Android biometric registration
            if (platform === 'android' && !origin.startsWith('android:apk-key-hash:') && !isTrustedMobile) {
                console.error(`[Security] Missing Android Origin on Android registration:
                    User_ID=${userId}
                    Origin=${origin}
                    IP=${req.ip}
                `);
                return res.status(403).json({ error: "SECURITY_VIOLATION: Missing Android Origin on Android platform" });
            }

            const verified = await Passkeys.verifyRegistration(userId, response, challenge, origin, rpID);
            if (verified) {
                console.log(`[Auth] Passkey registration successful for user ${userId}`);
                res.json({ success: true });
            } else {
                console.warn(`[Auth] Passkey registration verification failed for user ${userId}`);
                res.status(400).json({ error: "Registration verification failed" });
            }
        } catch (e: any) {
            console.error(`[Auth] Error in completePasskeyRegistration:
                Error=${e.message}
                Stack=${e.stack}
                User_ID=${req.body.userId}
                IP=${req.ip}
            `);
            res.status(e.status || 500).json({ error: e.message });
        }
    }

    async recordBehavior(req: Request, res: Response) {
        try {
            const { userId, behaviorMetrics } = req.body;
            const sb = getAdminSupabase();
            if (!sb) throw new Error("Database offline");

            const { error } = await sb.from('behavior_profiles').upsert({
                user_id: userId,
                ...behaviorMetrics,
                updated_at: new Date().toISOString()
            });

            if (error) throw error;
            res.json({ success: true });
        } catch (e: any) {
            console.error(`[Auth] Error in recordBehavior:
                Error=${e.message}
                Stack=${e.stack}
                User_ID=${req.body.userId}
                IP=${req.ip}
            `);
            res.status(500).json({ error: e.message });
        }
    }
}

export const Auth = new AuthController();
