
import { Session, User, UserRole, Permission, UserSession } from '../types.js';
import { getSupabase, getAdminSupabase, createAuthenticatedClient } from '../services/supabaseClient.js';
import { Storage, STORAGE_KEYS } from '../backend/storage.js';
import { UUID, IdentityGenerator } from '../services/utils.js';
import { OTPService } from '../backend/security/otpService.js';
import { Audit } from '../backend/security/audit.js';
import { createHash } from 'crypto';
import { SecurityService } from './securityService.js';
import { Messaging } from '../backend/features/MessagingService.js';
import { ProvisioningService } from '../backend/features/ProvisioningService.js';
import { WalletService } from '../wealth/walletService.js';
import { parsePhoneNumber } from 'libphonenumber-js';
import { JWTNode } from '../backend/security/jwt.js';
import { DEFAULT_INSTITUTIONAL_APP_ORIGIN, TRUSTED_INSTITUTIONAL_APP_ORIGINS, TRUSTED_MOBILE_APP_ORIGINS } from '../backend/config/appIdentity.js';
import { buildPostgrestOrFilter } from '../backend/security/postgrest.js';

/**
 * ORBI AUTHENTICATION PROTOCOL (V24.5 Titanium Hardened)
 * ---------------------------------------------
 * Hardened for Zero-Trust Identity Quarantine.
 * Implements Full Banking Model Security:
 * - Refresh Token Rotation
 * - Reuse Detection
 * - Device Fingerprinting
 * - Login Anomaly Detection
 */
import { BruteForceService } from '../backend/src/services/bruteForce.service.js';

export class AuthService {
    private security = new SecurityService();
    private bruteForce = new BruteForceService();
    private readonly allowLocalSessionFallback =
        process.env.NODE_ENV !== 'production' &&
        process.env.ORBI_ALLOW_LOCAL_SESSION_FALLBACK === 'true';

    private hashToken(token: string): string {
        return createHash('sha256').update(token).digest('hex');
    }

    private async detectLoginAnomaly(userId: string, fingerprint: string, ip: string): Promise<boolean> {
        const sb = getSupabase();
        if (!sb) return false;

        // Check for new device/IP
        const { data: sessions } = await sb.from('user_sessions')
            .select('device_fingerprint, ip_address')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(5);

        if (!sessions || sessions.length === 0) return false; // First login is not anomalous

        const knownDevice = sessions.some(s => s.device_fingerprint === fingerprint);
        const knownIP = sessions.some(s => s.ip_address === ip);

        if (!knownDevice && !knownIP) {
            // High risk: New device AND new IP
            return true;
        }
        return false;
    }

    private async revokeSessionChain(userId: string, tokenHash: string) {
        const sb = getSupabase();
        if (!sb) return;

        // Recursive revocation or just revoke all for user if reuse detected
        // For banking security, revoking all sessions for the user is safer upon reuse detection
        await sb.from('user_sessions')
            .update({ is_revoked: true })
            .eq('user_id', userId);
            
        // Also sign out from Supabase to invalidate JWTs
        const adminSb = getAdminSupabase();
        if (adminSb) {
            await adminSb.auth.admin.signOut(userId);
        }
    }

    private getPermissionsForRole(role: UserRole = 'USER', status: string = 'pending'): Permission[] {
        // Enforce total scope lockdown for non-active nodes
        if (status !== 'active') return [];

        const common: Permission[] = ['auth.login', 'auth.logout', 'user.read', 'user.update'];

        const adminOps: Permission[] = [
            'staff.read',
            'staff.write',
            'provider.read',
            'provider.write',
            'institutional_account.read',
            'institutional_account.write',
            'provider_routing.read',
            'provider_routing.write',
            'config.ledger.read',
            'config.ledger.write',
            'config.fx.read',
            'config.fx.write',
            'config.commissions.read',
            'config.commissions.write',
            'reconciliation.read',
            'reconciliation.run',
            'device.read',
            'device.trust.manage',
            'kyc.review',
            'document.review',
            'service_access.review',
        ];

        if (role === 'SUPER_ADMIN') {
            return [
                ...common,
                'user.freeze',
                'wallet.read', 'wallet.create', 'wallet.update', 'wallet.delete', 'wallet.credit', 'wallet.debit', 'wallet.freeze',
                'transaction.create', 'transaction.view', 'transaction.verify', 'transaction.reverse', 'transaction.delete',
                'ledger.read', 'ledger.write',
                'admin.approve', 'admin.freeze', 'admin.audit.read', 'admin.user.manage',
                'system.wallet.credit', 'system.wallet.debit',
                'auth.pwd_reset',
                ...adminOps,
            ];
        }

        switch (role) {
            case 'ADMIN':
                return [
                    ...common,
                    'wallet.read', 'wallet.update',
                    'transaction.view', 'transaction.verify',
                    'ledger.read',
                    'admin.approve', 'admin.audit.read', 'admin.user.manage',
                    'staff.read', 'staff.write',
                    'provider.read', 'provider.write',
                    'institutional_account.read', 'institutional_account.write',
                    'provider_routing.read', 'provider_routing.write',
                    'config.ledger.read', 'config.ledger.write',
                    'config.fx.read', 'config.fx.write',
                    'config.commissions.read', 'config.commissions.write',
                    'reconciliation.read', 'reconciliation.run',
                    'device.read', 'device.trust.manage',
                    'kyc.review', 'document.review', 'service_access.review',
                ];
            case 'HUMAN_RESOURCE':
                return [
                    ...common,
                    'user.freeze',
                    'admin.user.manage',
                    'admin.approve',
                    'staff.read', 'staff.write',
                ];
            case 'AUDIT':
                return [
                    ...common,
                    'wallet.read',
                    'transaction.view',
                    'ledger.read',
                    'admin.audit.read',
                    'reconciliation.read',
                    'staff.read',
                ];
            case 'ACCOUNTANT':
                return [
                    ...common,
                    'wallet.read',
                    'transaction.view',
                    'ledger.read',
                    'ledger.write',
                    'reconciliation.read',
                    'config.commissions.read',
                    'config.fx.read',
                ];
            case 'IT':
                return [
                    ...common,
                    'admin.audit.read',
                    'system.wallet.credit', 'system.wallet.debit',
                    'provider.read', 'provider.write',
                    'institutional_account.read', 'institutional_account.write',
                    'provider_routing.read', 'provider_routing.write',
                    'device.read', 'device.trust.manage',
                    'config.ledger.read',
                    'config.fx.read',
                ];
            case 'CUSTOMER_CARE':
                return [
                    ...common,
                    'transaction.view',
                    'kyc.review',
                    'document.review',
                    'service_access.review',
                ];
            case 'MERCHANT':
                return [
                    ...common,
                    'wallet.read',
                    'transaction.create',
                    'transaction.view',
                    'merchant.read',
                    'merchant.create',
                    'merchant.update',
                    'merchant.settlement',
                ];
            case 'AGENT':
                return [
                    ...common,
                    'wallet.read',
                    'transaction.create',
                    'transaction.view',
                    'agent.cash.deposit',
                    'agent.cash.withdraw',
                    'agent.float.manage',
                ];
            case 'CONSUMER':
            case 'USER':
                return [...common, 'wallet.read', 'wallet.create', 'wallet.update', 'wallet.delete', 'transaction.create', 'transaction.view', 'goal.read', 'goal.create', 'goal.update', 'goal.delete', 'category.read', 'category.create', 'category.update', 'category.delete', 'task.read', 'task.create', 'task.update', 'task.delete'];
            default: return [...common];
        }
    }

    public describePermissionsForRole(role: UserRole = 'USER', status: string = 'pending'): Permission[] {
        return this.getPermissionsForRole(role, status);
    }

    private async resolveNodeStatus(
        userId: string,
        registryType: 'STAFF' | 'CONSUMER' | 'MERCHANT' | 'AGENT' = 'STAFF',
    ): Promise<{ status: string, kyc_level: number, kyc_status: string, id_type?: string, id_number?: string }> {
        const sb = getAdminSupabase();
        
        // 1. Supabase Check
        if (sb) {
            try {
                const table = registryType === 'STAFF' ? 'staff' : 'users';
                const { data, error } = await sb.from(table)
                    .select('account_status, kyc_level, kyc_status, id_type, id_number')
                    .eq('id', userId)
                    .maybeSingle();
                
                if (error || !data) return { status: 'pending', kyc_level: 0, kyc_status: 'unverified' };
                
                return {
                    status: data.account_status || 'pending',
                    kyc_level: data.kyc_level || 0,
                    kyc_status: data.kyc_status || 'unverified',
                    id_type: data.id_type,
                    id_number: data.id_number
                };
            } catch (e) {
                return { status: 'pending', kyc_level: 0, kyc_status: 'error' };
            }
        }

        // 2. Local Fallback
        const users = Storage.getFromDB<any>(STORAGE_KEYS.CUSTOM_USERS);
        const user = users.find(u => u.id === userId);
        if (user) {
            return {
                status: user.account_status || 'active',
                kyc_level: user.kyc_level || 0,
                kyc_status: user.kyc_status || 'unverified',
                id_type: user.id_type,
                id_number: user.id_number
            };
        }

        return { status: 'active', kyc_level: 1, kyc_status: 'pending' };
    }

    public async mapSession(sbSession: any): Promise<Session> {
        // Handle both full session object (from login) and user-only object (from getUser)
        const user = sbSession.user || sbSession;
        const meta = user.user_metadata || {};
        const AUTHORIZED_ORIGIN =
            process.env.ORBI_WEB_ORIGIN ||
            process.env.ORBI_INSTITUTIONAL_APP_ORIGIN ||
            process.env.ORBI_CORE_APP_ORIGIN ||
            DEFAULT_INSTITUTIONAL_APP_ORIGIN;
        
        // HARDENING: Cluster Origin Enforcement
        const origin = meta.app_origin;
        const ALLOWED_ORIGINS = Array.from(new Set([AUTHORIZED_ORIGIN, ...TRUSTED_INSTITUTIONAL_APP_ORIGINS, ...TRUSTED_MOBILE_APP_ORIGINS]));
        
        if (origin && !ALLOWED_ORIGINS.includes(origin)) {
            throw new Error(`ACCESS_DENIED: Identity node originates from unauthorized cluster [${origin}].`);
        }

        const registryType = meta.registry_type || 'STAFF';
        const nodeState = await this.resolveNodeStatus(user.id, registryType);
        const liveStatus = nodeState.status;

        // HARDENING: Immediate Quarantine Check
        if (liveStatus === 'frozen' || liveStatus === 'blocked') {
            Storage.removeItem(STORAGE_KEYS.USER_SESSION);
            throw new Error(`IDENTITY_LOCKED: Your Account has been temporary ${liveStatus.toUpperCase()} by the System security, please contact us if the issue persist more than 24HRS`);
        }

        const session: Session = {
            user: {
                id: user.id,
                email: user.email,
                full_name: meta.full_name || 'Customer',
                phone: meta.phone,
                customer_id: meta.customer_id,
                role: (meta.role as UserRole) || 'USER',
                account_status: liveStatus,
                kyc_level: nodeState.kyc_level,
                kyc_status: nodeState.kyc_status,
                id_type: nodeState.id_type,
                id_number: nodeState.id_number,
                registry_type: registryType,
                app_origin: origin
            },
            access_token: sbSession.access_token || '',
            refresh_token: sbSession.refresh_token || '',
            expires_at: sbSession.expires_at || 0,
            token_type: 'Bearer',
            sub: user.id,
            iss: 'orbi-auth-v25',
            exp: sbSession.expires_at || Math.floor(Date.now() / 1000) + 3600,
            role: (meta.role as UserRole) || 'USER',
            permissions: [] // Default to empty, will be resolved by RBAC if needed
        };

        Storage.setItem(STORAGE_KEYS.USER_SESSION, JSON.stringify(session));
        
        return session;
    }
    
    async getSession(token?: string): Promise<Session | null> {
        const sb = getSupabase();
        const adminSb = getAdminSupabase();
        
        // 1. Validate provided token against Supabase Auth
        if (sb && token) {
            const { data: { user }, error } = await sb.auth.getUser(token);
            
            if (user && !error) {
                try {
                    // Construct a session object since getUser only returns the user
                    const sessionData = {
                        access_token: token,
                        token_type: 'Bearer',
                        user: user,
                        expires_at: Math.floor(Date.now() / 1000) + 3600 // Assume valid for 1h if getUser succeeds
                    };
                    return await this.mapSession(sessionData);
                } catch (e: any) {
                    console.error("[AuthService] Session mapping failed:", e);
                    return null;
                }
            }
        }

        // 1b. Validate internally signed access tokens
        if (token) {
            type InternalAccessPayload = {
                sub: string;
                device?: string;
                exp?: number;
                jti?: string;
                type?: string;
            };

            const payload = await JWTNode.verify<InternalAccessPayload>(token);
            if (payload?.sub && (!payload.type || payload.type === 'access') && adminSb) {
                try {
                    const { data: userData } = await adminSb.auth.admin.getUserById(payload.sub);
                    const authUser = userData?.user;
                    if (authUser) {
                        const sessionData = {
                            access_token: token,
                            token_type: 'Bearer',
                            user: authUser,
                            expires_at: payload.exp || Math.floor(Date.now() / 1000) + 900,
                        };
                        return await this.mapSession(sessionData);
                    }
                } catch (e: any) {
                    console.error("[AuthService] Internal JWT session resolution failed:", e);
                    return null;
                }
            }
        }

        // 2. Fallback to local storage (Legacy/Testing only)
        if (this.allowLocalSessionFallback) {
            const local = Storage.getItem(STORAGE_KEYS.USER_SESSION);
            if (local) {
                try {
                    const s = JSON.parse(local) as Session;
                    if (s.exp > Date.now() / 1000) return s;
                } catch (e) { Storage.removeItem(STORAGE_KEYS.USER_SESSION); }
            }
        }
        return null;
    }

    private async registerOrValidateDevice(userId: string, fingerprint: string, userAgent?: string): Promise<'trusted' | 'untrusted' | 'blocked' | 'new'> {
        const sb = getSupabase();
        if (!sb) return 'new';

        // 1. Enforce Device Limit (Max 2 Accounts per Device)
        const { count, error } = await sb.from('user_devices')
            .select('user_id', { count: 'exact', head: true })
            .eq('device_fingerprint', fingerprint)
            .neq('user_id', userId); // Count OTHER users on this device

        if (count !== null && count >= 2) {
            throw new Error('DEVICE_LIMIT_EXCEEDED: This device is already linked to the maximum number of accounts (2).');
        }

        const { data: device } = await sb.from('user_devices')
            .select('*')
            .eq('user_id', userId)
            .eq('device_fingerprint', fingerprint)
            .maybeSingle();

        if (device) {
            if (device.status === 'blocked') return 'blocked';
            
            // Update last active
            await sb.from('user_devices').update({ 
                last_active_at: new Date().toISOString(),
                user_agent: userAgent || device.user_agent 
            }).eq('id', device.id);

            return device.is_trusted ? 'trusted' : 'untrusted';
        } else {
            // Register new device
            await sb.from('user_devices').insert({
                user_id: userId,
                device_fingerprint: fingerprint,
                user_agent: userAgent,
                device_type: 'unknown', // Could parse UA
                is_trusted: false,
                status: 'active'
            });
            return 'new';
        }
    }

    async login(e: string, p: string, metadata?: { fingerprint?: string, ip?: string, userAgent?: string }) { 
        const sb = getSupabase();
        if (!sb) return { error: { message: "ORBI Cluster Offline" } };
        
        // Lookup user ID for brute force protection
        let userId = null;
        const { data: user } = await sb
            .from('users')
            .select('id')
            .or(buildPostgrestOrFilter([
                { column: 'email', operator: 'eq', value: e },
                { column: 'phone', operator: 'eq', value: e },
            ]))
            .maybeSingle();
        if (user) userId = user.id;

        if (userId) {
            const { locked, reason, retryAfter } = await this.bruteForce.isLocked(userId);
            if (locked) {
                return { error: { message: `ACCOUNT_LOCKED: ${reason}. Please try again in ${Math.ceil(retryAfter! / 1000)} seconds.` } };
            }
        }
        
        let res;
        if (e && typeof e === 'string' && e.includes('@')) {
            res = await sb.auth.signInWithPassword({ email: e, password: p });
        } else {
            // Assume phone
            let formattedPhone = e;
            if (!formattedPhone.startsWith('+')) {
                formattedPhone = '+' + formattedPhone;
            }
            res = await sb.auth.signInWithPassword({ phone: formattedPhone, password: p });
        }
        if (res.data?.session) {
            try {
                // Clear brute force attempts on success
                if (userId) {
                    await this.bruteForce.clearAttempts(userId);
                }

                const mapped = await this.mapSession(res.data.session);
                
                // Banking Security: Anomaly Detection & Session Tracking
                if (metadata?.fingerprint && metadata?.ip) {
                    // 1. Device Binding Check
                    const deviceStatus = await this.registerOrValidateDevice(mapped.user.id, metadata.fingerprint, metadata.userAgent);
                    
                    if (deviceStatus === 'blocked') {
                        throw new Error('DEVICE_BLOCKED: This device is explicitly blocked from accessing your account.');
                    }

                    // 2. Single Active Device Policy (Logout previous sessions)
                    if (deviceStatus === 'new' || deviceStatus === 'untrusted') {
                        // Revoke all other sessions for this user to enforce single active device
                        await sb.from('user_sessions')
                            .update({ is_revoked: true })
                            .eq('user_id', mapped.user.id)
                            .neq('device_fingerprint', metadata.fingerprint); // Keep current device if it had a session (though unlikely for 'new')
                        
                        console.log(`[Auth] Enforced Single Device Policy for user ${mapped.user.id}`);
                    }

                    const isAnomalous = await this.detectLoginAnomaly(mapped.user.id, metadata.fingerprint, metadata.ip);
                    
                    if (isAnomalous || deviceStatus === 'new') {
                        console.warn(`[Auth] Login anomaly detected for user ${mapped.user.id}`);
                        
                        const language = mapped.user.user_metadata?.language || 'en';
                        const subject = language === 'sw' ? 'Kifaa Kipya Kimegunduliwa' : 'New Device Detected';
                        const body = language === 'sw' 
                            ? `Kuingia kutoka kifaa kipya (IP: ${metadata.ip}). Kama huyu hakuwa wewe, funga akaunti yako mara moja.` 
                            : `Login from new device (IP: ${metadata.ip}). If this wasn't you, freeze your account immediately.`;

                        // NOTIFICATION: Security Alert via Push
                        await Messaging.dispatch(
                            mapped.user.id,
                            'security',
                            subject,
                            body,
                            { sms: true }
                        );

                        await this.security.logActivity(mapped.user.id, 'login', 'warning', `New device detected: ${metadata.fingerprint}`, undefined, metadata.fingerprint);
                    } else {
                        // STANDARD LOGIN: No user notification (to reduce noise), just audit log
                        console.log(`[Auth] Standard login processed for user ${mapped.user.id} (No Notification Sent)`);
                        // Parse User Agent for cleaner log
                        let deviceName = 'Unknown Device';
                        if (metadata.userAgent) {
                            if (metadata.userAgent.includes('Android')) deviceName = 'Android Device';
                            else if (metadata.userAgent.includes('iPhone')) deviceName = 'iPhone';
                            else if (metadata.userAgent.includes('iPad')) deviceName = 'iPad';
                            else if (metadata.userAgent.includes('Windows')) deviceName = 'Windows PC';
                            else if (metadata.userAgent.includes('Macintosh')) deviceName = 'Mac';
                            else if (metadata.userAgent.includes('Linux')) deviceName = 'Linux Device';
                            else deviceName = 'Web Browser';
                        }
                        
                        await this.security.logActivity(mapped.user.id, 'login', 'success', `Login via ${deviceName}`, undefined, metadata.fingerprint);
                    }

                    // Update User Last Active Timestamp (Critical for "Last Seen")
                    await sb.from('users').update({ 
                        last_active: new Date().toISOString() 
                    }).eq('id', mapped.user.id);

                    // PROVISIONING: Ensure user has default infrastructure
                    await ProvisioningService.provisionUser(mapped.user.id, mapped.user.user_metadata?.full_name || 'Customer');

                    // Store Session
                    const tokenHash = this.hashToken(res.data.session.refresh_token);
                    await sb.from('user_sessions').insert({
                        user_id: mapped.user.id,
                        refresh_token_hash: tokenHash,
                        device_fingerprint: metadata.fingerprint,
                        ip_address: metadata.ip,
                        user_agent: metadata.userAgent,
                        expires_at: new Date((res.data.session.expires_at || Date.now() / 1000 + 3600) * 1000).toISOString()
                    });
                } else {
                    // Log generic login if no metadata
                    await this.security.logActivity(mapped.user.id, 'login', 'success', 'Login without device metadata');
                }

                // Check if 2FA is required
                if (mapped.user.user_metadata?.two_factor_enabled) {
                    return { 
                        two_factor_required: true, 
                        userId: mapped.user.id, 
                        phone: mapped.user.user_metadata?.phone,
                        temp_session: mapped 
                    };
                }

                // MANDATORY BIOMETRIC CHECK
                // If user has no authenticators, force setup
                const authenticators = mapped.user.user_metadata?.authenticators || [];
                const biometricRequired = authenticators.length === 0;

                return { 
                    user: mapped.user, 
                    session: mapped,
                    access_token: mapped.access_token,
                    biometric_setup_required: biometricRequired // Flag for frontend to trigger registration
                };
            } catch (err: any) {
                if (userId) {
                    await this.bruteForce.recordFailedAttempt(userId);
                }
                return { error: { message: err.message } };
            }
        }
        return { error: res.error };
    }

    async refreshSession(refreshToken: string, metadata?: { fingerprint?: string, ip?: string }) {
        const sb = getSupabase();
        if (!sb) return { error: { message: "DB_OFFLINE" } };

        const tokenHash = this.hashToken(refreshToken);

        // 1. Verify Token in DB
        const { data: sessionRecord } = await sb.from('user_sessions')
            .select('*')
            .eq('refresh_token_hash', tokenHash)
            .maybeSingle();

        if (!sessionRecord) {
            // Token not found - could be forged or very old
            return { error: { message: "INVALID_REFRESH_TOKEN" } };
        }

        // 2. Reuse Detection
        if (sessionRecord.replaced_by) {
            // CRITICAL: Token reuse detected! Revoke everything.
            await this.revokeSessionChain(sessionRecord.user_id, tokenHash);
            
            const { data: user } = await sb.from('users').select('language').eq('id', sessionRecord.user_id).maybeSingle();
            const language = user?.language || 'en';
            const subject = language === 'sw' ? 'MUHIMU: Udukuzi wa Kipindi Umezuiwa' : 'CRITICAL: Session Hijack Blocked';
            const body = language === 'sw' 
                ? 'Matumizi ya kipindi maradufu yamegunduliwa. Vifaa vyote vimetolewa kwa usalama wako.' 
                : 'Duplicate session usage detected. All devices have been logged out for your safety.';

            // NOTIFICATION: Critical Security Alert via Push
            await Messaging.dispatch(
                sessionRecord.user_id,
                'security',
                subject,
                body,
                { sms: true }
            );
            await this.security.logActivity(sessionRecord.user_id, 'security_update', 'blocked', 'Token reuse detected - Session Chain Revoked', undefined, metadata?.fingerprint);

            return { error: { message: "SECURITY_ALERT: Token reuse detected. All sessions revoked." } };
        }

        // 3. Revocation Check
        if (sessionRecord.is_revoked) {
            return { error: { message: "SESSION_REVOKED" } };
        }

        // 4. Device Verification
        if (metadata?.fingerprint && sessionRecord.device_fingerprint !== metadata.fingerprint) {
            // Fingerprint mismatch - potential theft
            await this.revokeSessionChain(sessionRecord.user_id, tokenHash);
            
            const { data: user } = await sb.from('users').select('language').eq('id', sessionRecord.user_id).maybeSingle();
            const language = user?.language || 'en';
            const subject = language === 'sw' ? 'Kipindi Kimekatishwa' : 'Session Terminated';
            const body = language === 'sw' 
                ? 'Tofauti ya alama ya kidole ya kifaa imegunduliwa. Tafadhali ingia tena.' 
                : 'Device fingerprint mismatch detected. Please login again.';

            await Messaging.dispatch(
                sessionRecord.user_id,
                'security',
                subject,
                body,
                { sms: true }
            );
            await this.security.logActivity(sessionRecord.user_id, 'security_update', 'failed', 'Device fingerprint mismatch', undefined, metadata?.fingerprint);

            return { error: { message: "DEVICE_MISMATCH: Session terminated." } };
        }

        // 5. Perform Refresh via Supabase
        const { data, error } = await sb.auth.refreshSession({ refresh_token: refreshToken });
        
        if (error || !data.session) {
            return { error: error || { message: "Refresh failed" } };
        }

        // 6. Rotation: Invalidate old, store new
        const newTokenHash = this.hashToken(data.session.refresh_token);
        
        // Mark old as replaced
        await sb.from('user_sessions')
            .update({ replaced_by: newTokenHash })
            .eq('id', sessionRecord.id);

        // Create new session record
        await sb.from('user_sessions').insert({
            user_id: sessionRecord.user_id,
            refresh_token_hash: newTokenHash,
            device_fingerprint: sessionRecord.device_fingerprint,
            ip_address: metadata?.ip || sessionRecord.ip_address,
            user_agent: sessionRecord.user_agent,
            expires_at: new Date((data.session.expires_at || Date.now() / 1000 + 3600) * 1000).toISOString()
        });

        const mapped = await this.mapSession(data.session);

        // Update User Last Active Timestamp
        await sb.from('users').update({ 
            last_active: new Date().toISOString() 
        }).eq('id', mapped.user.id);

        return { session: mapped };
    }

    async logout(token?: string, refreshToken?: string) {
        const sb = getSupabase();
        const adminSb = getAdminSupabase();

        if (refreshToken && sb) {
            const tokenHash = this.hashToken(refreshToken);
            await sb.from('user_sessions')
                .update({ is_revoked: true })
                .eq('refresh_token_hash', tokenHash);
        }

        let resolvedUserId: string | null = null;
        let resolvedEmail: string | null = null;

        if (token && sb) {
            const { data: { user } } = await sb.auth.getUser(token);
            if (user) {
                resolvedUserId = user.id;
                resolvedEmail = user.email || null;
            }
        }

        if (!resolvedUserId && token) {
            const payload = await JWTNode.verify<{ sub?: string; jti?: string; type?: string }>(token);
            if (payload?.jti) {
                await JWTNode.revoke(payload.jti);
            }
            if (payload?.sub) {
                resolvedUserId = payload.sub;
                if (adminSb) {
                    const { data } = await adminSb.auth.admin.getUserById(payload.sub);
                    resolvedEmail = data?.user?.email || null;
                }
            }
        }

        if (resolvedUserId && sb) {
            await sb.from('user_sessions')
                .update({ is_revoked: true })
                .eq('user_id', resolvedUserId);
        }

        if (resolvedUserId) {
            await Audit.log('IDENTITY', resolvedUserId, 'LOGOUT', { email: resolvedEmail });
            if (adminSb) {
                await adminSb.auth.admin.signOut(resolvedUserId).catch(() => {});
            }
        }

        Storage.removeItem(STORAGE_KEYS.USER_SESSION);
    }

    async registerBiometric(userId: string, credential: any) {
        const sb = getSupabase();
        if (sb) {
            const { data, error } = await sb.auth.updateUser({
                data: { 
                    biometric_credential: credential,
                    security_biometric_enabled: true 
                }
            });
            return { data, error };
        }
        
        // Local fallback
        let users = Storage.getFromDB<any>(STORAGE_KEYS.CUSTOM_USERS);
        const idx = users.findIndex(u => u.id === userId);
        if (idx >= 0) {
            users[idx].biometric_credential = credential;
            users[idx].security_biometric_enabled = true;
            Storage.saveToDB(STORAGE_KEYS.CUSTOM_USERS, users);
            return { success: true };
        }
        return { error: "User not found" };
    }

    async signUp(e: string, p: string, m?: any) {
        const sb = getSupabase();
        if (sb) {
            try {
                const normalizedCurrency = typeof m?.currency === 'string'
                    ? m.currency.trim().toUpperCase()
                    : '';
                if (!normalizedCurrency) {
                    return { data: null, error: { message: "CURRENCY_REQUIRED: Account currency is mandatory at signup." } };
                }

                // Generate customer_id if not provided
                const customerId = m?.customer_id || IdentityGenerator.generateCustomerID();
                
                // HARDENING: Role & Registry Enforcement based on Origin
                let role: UserRole = 'USER';
                let registryType: 'STAFF' | 'CONSUMER' | 'MERCHANT' | 'AGENT' = 'CONSUMER';
                const origin = m?.app_origin;
                const requestedRole = (m?.role as UserRole) || 'USER';
                const staffRoles: UserRole[] = [
                    'SUPER_ADMIN',
                    'ADMIN',
                    'IT',
                    'AUDIT',
                    'ACCOUNTANT',
                    'CUSTOMER_CARE',
                    'HUMAN_RESOURCE',
                ];

                if (TRUSTED_MOBILE_APP_ORIGINS.includes(origin)) {
                    // Mobile app signups start as ordinary public users.
                    // Merchant/agent access is granted later through ORBI review.
                    role = 'USER';
                    registryType = 'CONSUMER';
                } else if (TRUSTED_INSTITUTIONAL_APP_ORIGINS.includes(origin)) {
                    role = requestedRole;
                    if (staffRoles.includes(requestedRole)) {
                        registryType = 'STAFF';
                    } else if (requestedRole === 'MERCHANT') {
                        registryType = 'MERCHANT';
                    } else if (requestedRole === 'AGENT') {
                        registryType = 'AGENT';
                    } else {
                        registryType = 'CONSUMER';
                    }
                } else {
                    // Default fallback for unknown origins
                    role = 'USER';
                    registryType = 'CONSUMER';
                }

                // Format phone number
                let formattedPhone = m?.phone;
                if (formattedPhone) {
                    try {
                        const phoneNumber = parsePhoneNumber(formattedPhone, 'TZ');
                        if (phoneNumber.isValid()) {
                            formattedPhone = phoneNumber.format('E.164');
                        } else {
                            throw new Error('Invalid phone number format');
                        }
                    } catch (err) {
                        return { data: null, error: { message: "Invalid phone number provided." } };
                    }
                }

                // Enforce single phone number across all identities
                if (formattedPhone) {
                    const adminSb = getAdminSupabase();
                    const checkClient = adminSb || sb;
                    if (checkClient) {
                        const { data: userMatch, error: userMatchError } = await checkClient
                            .from('users')
                            .select('id')
                            .eq('phone', formattedPhone)
                            .maybeSingle();
                        if (userMatchError) {
                            console.warn('[AuthService] Phone uniqueness check failed (users):', userMatchError.message);
                        }
                        if (userMatch) {
                            return { data: null, error: { message: "PHONE_ALREADY_IN_USE: This phone number is already linked to another account." } };
                        }

                        const { data: staffMatch, error: staffMatchError } = await checkClient
                            .from('staff')
                            .select('id')
                            .eq('phone', formattedPhone)
                            .maybeSingle();
                        if (staffMatchError) {
                            console.warn('[AuthService] Phone uniqueness check failed (staff):', staffMatchError.message);
                        }
                        if (staffMatch) {
                            return { data: null, error: { message: "PHONE_ALREADY_IN_USE: This phone number is already linked to another account." } };
                        }
                    }
                }

                const nationality = m?.nationality || 'Tanzania';
                const language = m?.language || (nationality === 'Tanzania' ? 'sw' : 'en');

                const metadata = { 
                    ...m, 
                    phone: formattedPhone, 
                    customer_id: customerId, 
                    currency: normalizedCurrency,
                    language: language,
                    account_status: 'pending',
                    role,
                    registry_type: registryType
                };

                const signUpPayload: any = { password: p, options: { data: metadata } };
                if (e && typeof e === 'string' && e.includes('@')) {
                    signUpPayload.email = e;
                } else if (formattedPhone) {
                    signUpPayload.phone = formattedPhone;
                } else {
                    return { data: null, error: { message: "Either email or phone is required for registration." } };
                }

                console.info(`[AuthService] Attempting signUp for ${e || formattedPhone}...`);
                const res = await sb.auth.signUp(signUpPayload);

                if (res.error) {
                    console.error("[AuthService] Supabase signUp error:", res.error);
                    return { data: null, error: res.error };
                }

                if (res.data?.user) {
                    console.info(`[AuthService] User created: ${res.data.user.id}. Populating profile...`);
                    const adminSb = getAdminSupabase();
                    let targetClient = adminSb;

                    if (!adminSb) {
                        console.warn("[AuthService] Admin client not available. Falling back to authenticated client.");
                        if (res.data.session) {
                            targetClient = createAuthenticatedClient(res.data.session.access_token);
                        }
                        if (!targetClient) {
                            targetClient = sb;
                        }
                    }
                    
                    const targetTable = registryType === 'STAFF' ? 'staff' : 'users';
                    
                    const profileData: any = {
                        id: res.data.user.id,
                        full_name: m?.full_name || 'New User',
                        email: (e && typeof e === 'string' && e.includes('@')) ? e : null,
                        customer_id: customerId,
                        phone: formattedPhone,
                        nationality: nationality,
                        currency: normalizedCurrency,
                        language: language,
                        account_status: 'active',
                        registry_type: registryType,
                        app_origin: origin
                    };

                    if (registryType === 'STAFF' || targetTable === 'users') {
                        profileData.role = role;
                    }
                    
                    if (targetTable === 'users') {
                        profileData.address = m?.address;
                    }

                    const { error: profileError } = await targetClient!.from(targetTable).upsert(profileData, { onConflict: 'id' });

                    if (profileError) {
                        console.error("[AuthService] Profile creation failed:", profileError);
                        if (adminSb) {
                            console.info(`[AuthService] Rolling back auth user ${res.data.user.id}...`);
                            await adminSb.auth.admin.deleteUser(res.data.user.id);
                        }
                        return { data: null, error: profileError };
                    }

                    console.info(`[AuthService] Profile created. Triggering provisioning...`);
                    const provisionResult = await ProvisioningService.provisionUser(res.data.user.id, m?.full_name || 'Customer', customerId);
                    if (provisionResult.status === 'failed') {
                        console.error(`[AuthService] Provisioning failed for user ${res.data.user.id}:`, provisionResult.error);
                    } else {
                        console.info(`[AuthService] Provisioning successful for user ${res.data.user.id}`);
                    }
                    
                    const walletService = new WalletService();
                    const wallets = await walletService.fetchForUser(res.data.user.id);
                    (res.data.user as any).wallets = wallets;

                    console.info(`[AuthService] Sending welcome message...`);
                    await Messaging.sendWelcomeMessage(res.data.user, wallets);
                }

                if (res.data?.session) {
                    return { data: { user: res.data.user, session: await this.mapSession(res.data.session) }, error: null };
                }
                return { data: { user: res.data?.user, session: null }, error: res.error };
            } catch (err: any) {
                console.error("[AuthService] Registration protocol interrupted:", err);
                const errorMessage = err instanceof Error ? err.message : (typeof err === 'string' ? err : (err?.message || JSON.stringify(err) || "Registration protocol interrupted."));
                return { data: null, error: { message: errorMessage } };
            }
        }
        return { error: { message: "Cloud Node Offline" } };
    }

    async generateSessionForUser(userId: string): Promise<Session | null> {
        const sb = getSupabase();
        let user: any;

        if (sb) {
            const { data, error } = await sb.auth.admin.getUserById(userId);
            if (error || !data.user) return null;
            user = data.user;
        } else {
            const users = Storage.getFromDB<any>(STORAGE_KEYS.CUSTOM_USERS);
            user = users.find(u => u.id === userId);
        }

        if (!user) return null;

        // Generate Session
        const session: Session = {
            access_token: 'local-jwt-' + UUID.generate(),
            token_type: 'Bearer',
            user: {
                id: user.id,
                email: user.email,
                user_metadata: { 
                    ...user.user_metadata, 
                    app_origin: user.user_metadata?.app_origin || DEFAULT_INSTITUTIONAL_APP_ORIGIN 
                },
                role: (user.user_metadata?.role || 'USER') as UserRole
            },
            sub: user.id,
            iss: 'orbi.auth',
            exp: Date.now() / 1000 + (24 * 60 * 60), // 24h
            expires_at: Date.now() / 1000 + (24 * 60 * 60),
            role: (user.user_metadata?.role || 'USER') as UserRole,
            permissions: this.getPermissionsForRole((user.user_metadata?.role || 'USER') as UserRole, 'active')
        };

        // Store locally (Single session mode for this architecture)
        Storage.setItem(STORAGE_KEYS.USER_SESSION, JSON.stringify(session));
        
        return session;
    }

    async initiatePhoneLogin(phone: string) { 
        let formattedPhone = phone;
        try {
            const phoneNumber = parsePhoneNumber(phone, 'TZ');
            if (phoneNumber && phoneNumber.isValid()) {
                formattedPhone = phoneNumber.format('E.164');
            } else {
                formattedPhone = phone.startsWith('+') ? phone : '+' + phone.replace(/\s/g, '');
            }
        } catch (e) {
            formattedPhone = phone.startsWith('+') ? phone : '+' + phone.replace(/\s/g, '');
        }

        // Production: Trigger Push/Log challenge
        const { requestId, deliveryType, deliveryContact } = await OTPService.generateAndSend('system', formattedPhone, 'PHONE_LOGIN');
        return { success: true, requestId, deliveryType, deliveryContact }; 
    }

    async verifyPhoneLogin(phone: string, token: string, requestId?: string) { 
        let formattedPhone = phone;
        try {
            const phoneNumber = parsePhoneNumber(phone, 'TZ');
            if (phoneNumber && phoneNumber.isValid()) {
                formattedPhone = phoneNumber.format('E.164');
            } else {
                formattedPhone = phone.startsWith('+') ? phone : '+' + phone.replace(/\s/g, '');
            }
        } catch (e) {
            formattedPhone = phone.startsWith('+') ? phone : '+' + phone.replace(/\s/g, '');
        }

        const isProduction = process.env.NODE_ENV === 'production';
        
        if (isProduction && !requestId) {
             return { success: false, error: 'SECURITY_VIOLATION: Direct OTP injection not permitted in production.' };
        }

        if (requestId) {
            const isValid = await OTPService.verify(requestId, token, 'system');
            if (!isValid) return { success: false, error: 'IDENTITY_CHALLENGE_FAILED: Incorrect verification code.' };
        } else if (token !== '123456') {
             return { success: false, error: 'IDENTITY_CHALLENGE_FAILED: Incorrect verification code.' };
        }

        let users = Storage.getFromDB<any>(STORAGE_KEYS.CUSTOM_USERS);
        let user = users.find(u => u.phone === formattedPhone);
        
        if (user?.account_status === 'blocked' || user?.account_status === 'frozen') {
            return { success: false, error: 'IDENTITY_LOCKED' };
        }

        let isNewUser = false;
        if (!user) {
            isNewUser = true;
            user = {
                id: UUID.generate(), phone: formattedPhone, 
                role: 'USER' as UserRole, created_at: new Date().toISOString(),
                customer_id: IdentityGenerator.generateCustomerID(users.length + 1),
                account_status: 'active',
                language: 'sw' // Default to sw for phone login (Tanzania)
            };
            users.push(user);
            Storage.saveToDB(STORAGE_KEYS.CUSTOM_USERS, users);
        }

        const session: Session = {
            access_token: 'local-jwt-' + UUID.generate(),
            token_type: 'Bearer',
            user: {
                id: user.id,
                email: user.email,
                user_metadata: { 
                    ...user, 
                    app_origin: user.app_origin || DEFAULT_INSTITUTIONAL_APP_ORIGIN 
                },
                role: user.role || 'USER'
            },
            sub: user.id,
            iss: 'orbi.auth',
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
            expires_at: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
            role: user.role || 'USER',
            permissions: this.getPermissionsForRole((user.role || 'USER') as UserRole, 'active')
        };
        Storage.setItem(STORAGE_KEYS.USER_SESSION, JSON.stringify(session));
        return { success: true, user: session.user, session, isNewUser };
    }

    async getUserProfile(userId: string) {
        const sb = getAdminSupabase();
        if (sb) {
            const { data, error } = await sb.from('users').select('*, metadata').eq('id', userId).single();
            if (error) return { error };
            
            // Flatten metadata for UI convenience if needed, but keeping it explicit as requested
            return { data };
        }
        // Fallback for local storage if needed, but primary is supabase
        let users = Storage.getFromDB<any>(STORAGE_KEYS.CUSTOM_USERS);
        const user = users.find(u => u.id === userId);
        return { data: user || null };
    }

    async updatePassword(password: string) {
        const sb = getSupabase();
        if (sb) return await sb.auth.updateUser({ password });
        return { data: null, error: new Error("Cloud synchronization required.") };
    }

    async completePasswordReset(password: string) {
        // Wrapper for updatePassword to provide explicit semantics for password reset flow
        const result = await this.updatePassword(password);
        if (!result.error) {
            await this.security.logActivity('system', 'PASSWORD_RESET_COMPLETED', 'success', 'User completed password reset');
        }
        return result;
    }

    async initiatePasswordReset(identifier: string) {
        const sb = getSupabase();
        if (sb) return await sb.auth.resetPasswordForEmail(identifier);
        return { data: null, error: new Error("Cloud synchronization required.") };
    }

    async deleteAccount() { 
        const session = await this.getSession();
        if (session?.sub) { return { success: true }; }
        return { success: false, error: "Context Required" }; 
    }

    async completeProfile(phone: string, updates: any) { 
        if (Object.prototype.hasOwnProperty.call(updates || {}, 'currency')) {
            const normalizedCurrency = typeof updates?.currency === 'string'
                ? updates.currency.trim().toUpperCase()
                : '';
            if (!normalizedCurrency) {
                return { success: false, error: "CURRENCY_REQUIRED: Account currency cannot be empty." };
            }
            updates = { ...updates, currency: normalizedCurrency };
        }
        let users = Storage.getFromDB<any>(STORAGE_KEYS.CUSTOM_USERS);
        const idx = users.findIndex(u => u.phone === phone);
        if (idx >= 0) {
            users[idx] = { ...users[idx], ...updates };
            Storage.saveToDB(STORAGE_KEYS.CUSTOM_USERS, users);
            return { success: true };
        }
        return { success: false, error: "Identification failed." }; 
    }
}
