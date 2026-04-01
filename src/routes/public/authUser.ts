import crypto from 'crypto';
import express, { type Request, type RequestHandler, type Router } from 'express';
import { Sessions } from '../../../backend/src/modules/session/session.service.js';
import { Audit } from '../../../backend/security/audit.js';
import { getAdminSupabase, getSupabase } from '../../../backend/supabaseClient.js';
import { isInstitutionalAppIdentity } from '../../../backend/config/appIdentity.js';

function getDeviceNameFromUA(userAgent?: string): string {
  if (!userAgent) return 'Unknown Device';
  if (userAgent.includes('Android')) return 'Android Device';
  if (userAgent.includes('iPhone')) return 'iPhone';
  if (userAgent.includes('iPad')) return 'iPad';
  if (userAgent.includes('Windows')) return 'Windows PC';
  if (userAgent.includes('Macintosh')) return 'Mac';
  if (userAgent.includes('Linux')) return 'Linux Device';
  return 'Web Browser';
}

function isInstitutionalNodeRequest(req: Request) {
  const appId = String(req.headers['x-orbi-app-id'] || '');
  const appOrigin = String(req.headers['x-orbi-app-origin'] || '');
  return isInstitutionalAppIdentity(appId, appOrigin);
}

async function ensurePublicUserRow(userId: string, sessionUser: any, fallbackMetadata?: Record<string, any>) {
  const sb = getAdminSupabase() || getSupabase();
  if (!sb) throw new Error('DB_OFFLINE');

  const { data: existing, error: existingError } = await sb.from('users').select('id').eq('id', userId).maybeSingle();
  if (existingError) throw new Error(existingError.message);
  if (existing) return;

  const adminSb = getAdminSupabase();
  const authUserResult = adminSb ? await adminSb.auth.admin.getUserById(userId) : null;
  const authUser = authUserResult?.data?.user;
  const metadata = {
    ...(authUser?.user_metadata || {}),
    ...(sessionUser?.user_metadata || {}),
    ...(fallbackMetadata || {}),
  };

  const profilePayload = {
    id: userId,
    full_name: metadata.full_name || sessionUser?.full_name || 'User',
    email: authUser?.email || sessionUser?.email || null,
    phone: authUser?.phone || sessionUser?.phone || metadata.phone || null,
    nationality: metadata.nationality || null,
    address: metadata.address || null,
    avatar_url: metadata.avatar_url || null,
    customer_id: metadata.customer_id || null,
    currency: metadata.currency || 'TZS',
    language: metadata.language || 'en',
    account_status: metadata.account_status || 'active',
    role: String(metadata.role || 'USER').toUpperCase(),
    registry_type: String(metadata.registry_type || 'CONSUMER').toUpperCase(),
    app_origin: metadata.app_origin || null,
  };

  const { error: upsertError } = await sb.from('users').upsert(profilePayload, { onConflict: 'id' });
  if (upsertError) throw new Error(upsertError.message);
}

type Deps = {
  authenticate: RequestHandler;
  validate: (schema: any) => RequestHandler;
  upload: any;
  NewAuth: any;
  LogicCore: any;
  LoginSchema: any;
  BootstrapAdminSchema: any;
  SignUpSchema: any;
  KYCSubmitSchema: any;
  ServiceAccessRequestCreateSchema: any;
  resolveSessionRole: (session: any) => string;
  resolveSessionRegistryType: (session: any) => string;
  mapServiceRoleToRegistryType: (role: string) => string;
  legacyBiometricAliasesEnabled: boolean;
};

export const registerAuthUserRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    validate,
    upload,
    NewAuth,
    LogicCore,
    LoginSchema,
    BootstrapAdminSchema,
    SignUpSchema,
    KYCSubmitSchema,
    ServiceAccessRequestCreateSchema,
    resolveSessionRole,
    resolveSessionRegistryType,
    mapServiceRoleToRegistryType,
    legacyBiometricAliasesEnabled,
  } = deps;

  v1.post('/auth/passkey/register/start', authenticate, (req, res) => NewAuth.startPasskeyRegistration(req, res));
  v1.post('/auth/passkey/register/finish', authenticate, (req, res) => NewAuth.completePasskeyRegistration(req, res));
  v1.post('/auth/passkey/login/start', (req, res) => NewAuth.startPasskeyLogin(req, res));
  v1.post('/auth/passkey/login/finish', (req, res) => NewAuth.completePasskeyLogin(req, res));
  v1.post('/auth/pin/enroll', authenticate, (req, res) => NewAuth.enrollPin(req, res));
  v1.post('/auth/pin/update', authenticate, (req, res) => NewAuth.updatePin(req, res));
  v1.post('/auth/pin-login', (req, res) => NewAuth.pinLogin(req, res));

  if (legacyBiometricAliasesEnabled) {
    v1.post('/auth/biometric/register/start', authenticate, (req, res) => NewAuth.startPasskeyRegistration(req, res));
    v1.post('/auth/biometric/register/finish', authenticate, (req, res) => NewAuth.completePasskeyRegistration(req, res));
    v1.post('/auth/biometric/login/start', (req, res) => NewAuth.startPasskeyLogin(req, res));
    v1.post('/auth/biometric/login/finish', (req, res) => NewAuth.completePasskeyLogin(req, res));

    v1.post('/auth/biometric/cleanup', authenticate, async (req, res) => {
      const session = (req as any).session;
      const sb = getAdminSupabase();
      if (!sb) return res.status(500).json({ error: 'DB_OFFLINE' });

      const { data: user } = await sb.auth.admin.getUserById(session.sub);
      const metadata = user?.user?.user_metadata || {};
      delete metadata.authenticators;
      delete metadata.currentChallenge;

      await sb.auth.admin.updateUserById(session.sub, { user_metadata: metadata });
      res.json({ success: true, message: 'Legacy biometric registrations cleaned.' });
    });
  }

  v1.post('/auth/behavior/record', authenticate, (req, res) => NewAuth.recordBehavior(req, res));

  v1.get('/user/lookup/:customerId', authenticate, async (req, res) => {
    try {
      const profile = await LogicCore.lookupUser(req.params.customerId);
      if (!profile) {
        return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
      }
      res.json({ success: true, data: profile });
    } catch (e: any) {
      console.error(`[User Lookup] Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.get('/user/lookup', authenticate, async (req, res) => {
    try {
      const query = req.query.q as string;
      if (!query || query.length < 3) {
        return res.status(400).json({ success: false, error: 'QUERY_TOO_SHORT' });
      }

      const profile = await LogicCore.lookupUser(query);
      if (!profile) {
        return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
      }

      res.json({ success: true, data: profile });
    } catch (e: any) {
      console.error(`[User Lookup] Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.post('/auth/verify', authenticate, async (req, res) => {
    const session = (req as any).session;
    const { requestId, code, refreshSession, device } = req.body;
    try {
      const result = await LogicCore.verifySensitiveAction(requestId, code, session.sub);
      if (result?.success === true) {
        const accessToken = req.headers.authorization?.startsWith('Bearer ')
          ? req.headers.authorization.substring(7)
          : null;
        let effectiveAccessToken = accessToken;
        let effectiveRefreshToken: string | null = null;
        let effectiveUser = {
          id: session.sub,
          email: session.user?.email,
          phone: session.user?.phone,
          ...session.user?.user_metadata,
        };

        if (refreshSession === true) {
          const adminSb = getAdminSupabase();
          const publicSb = getSupabase();
          if (!adminSb || !publicSb) throw new Error('SUPABASE_SESSION_FAILED');

          const authUserResult = await adminSb.auth.admin.getUserById(session.sub);
          const authUser = authUserResult.data?.user;
          const loginEmail = authUser?.email || authUser?.user_metadata?.email;
          if (!authUser || !loginEmail) throw new Error('IDENTITY_NOT_FOUND');

          const linkResult = await adminSb.auth.admin.generateLink({ type: 'magiclink', email: loginEmail });
          if (linkResult.error || !linkResult.data?.properties?.hashed_token) {
            throw new Error(linkResult.error?.message || 'SUPABASE_SESSION_FAILED');
          }

          const supaSessionResult = await publicSb.auth.verifyOtp({
            type: 'magiclink',
            token_hash: linkResult.data.properties.hashed_token,
          });
          const supaSession = supaSessionResult.data?.session;
          if (supaSessionResult.error || !supaSession) {
            throw new Error(supaSessionResult.error?.message || 'SUPABASE_SESSION_FAILED');
          }

          effectiveAccessToken = supaSession.access_token;
          effectiveRefreshToken = supaSession.refresh_token || null;
          effectiveUser = {
            id: authUser.id,
            email: authUser.email,
            phone: authUser.phone,
            ...authUser.user_metadata,
          };

          const fingerprintSource = {
            platform: device?.platform,
            manufacturer: device?.manufacturer,
            brand: device?.brand,
            model: device?.deviceModel || device?.model,
            deviceName: device?.deviceName,
            deviceCodeName: device?.deviceCodeName,
            screenResolution: device?.screenResolution,
          };
          const deviceFingerprint = crypto.createHash('sha256').update(JSON.stringify(fingerprintSource)).digest('hex');
          const userAgent = [
            `orbi/${String(device?.platform || 'mobile').toLowerCase()}`,
            device?.deviceName || device?.model || 'Unknown Device',
            device?.osRelease || device?.systemVersion || device?.os || '',
            device?.appVersion ? `app=${device.appVersion}` : '',
          ].filter(Boolean).join(' | ');

          await adminSb.from('user_devices').upsert({
            user_id: session.sub,
            device_fingerprint: deviceFingerprint,
            device_name: device?.deviceName || device?.model || 'Unknown Device',
            device_type: String(device?.platform || 'mobile').toLowerCase(),
            user_agent: userAgent,
            last_active_at: new Date().toISOString(),
            is_trusted: true,
            status: 'active',
          }, { onConflict: 'user_id,device_fingerprint' });

          if (effectiveRefreshToken) {
            const refreshTokenHash = crypto.createHash('sha256').update(effectiveRefreshToken).digest('hex');
            await adminSb.from('user_sessions').insert({
              user_id: session.sub,
              refresh_token_hash: refreshTokenHash,
              device_fingerprint: deviceFingerprint,
              ip_address: req.ip,
              user_agent: userAgent,
              expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
              last_active_at: new Date().toISOString(),
              is_trusted_device: true,
            });
          }
        }

        if (!effectiveAccessToken) {
          const deviceId = session?.deviceId || session?.user?.user_metadata?.fingerprint || session?.user?.user_metadata?.device_id;
          effectiveRefreshToken = effectiveRefreshToken || Sessions.createRefreshToken(session.sub, deviceId);
        }

        return res.json({
          success: true,
          data: {
            success: true,
            verified: true,
            access_token: effectiveAccessToken,
            refresh_token: effectiveRefreshToken,
            user: effectiveUser,
          },
        });
      }
      return res.status(403).json({ success: false, error: result?.error || 'INVALID_OTP' });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/auth/login', validate(LoginSchema), async (req, res) => {
    console.log(`[Auth] Login attempt for: ${req.body.email || req.body.e}`);
    try {
      const email = req.body.email || req.body.e;
      const password = req.body.password || req.body.p;
      const fingerprint = req.headers['x-orbi-fingerprint'] as string;
      const ip = req.ip;
      const userAgent = req.headers['user-agent'];

      const result = await LogicCore.login(email, password, { fingerprint, ip, userAgent });
      if (result.error) {
        console.warn(`[Auth] Login failed for ${email}: ${result.error.message}`);
        return res.status(401).json({ success: false, error: result.error.message || 'Authentication failed' });
      }

      if (result.two_factor_required) {
        return res.json({ success: true, data: result });
      }

      res.json({ success: true, data: result });
    } catch (e: any) {
      console.error(`[Auth] Login exception for ${req.body.email}:`, e);
      res.status(500).json({ success: false, error: 'LOGIN_ERROR', message: e.message });
    }
  });

  v1.post('/auth/otp/initiate', async (req, res) => {
    let { userId, contact, action, type } = req.body;
    if (!userId || !action) return res.status(400).json({ success: false, error: 'MISSING_FIELDS' });

    try {
      if (!contact) {
        const sb = getAdminSupabase();
        if (sb) {
          const { data } = await sb.auth.admin.getUserById(userId);
          if (data?.user?.email) contact = data.user.email;
          else if (data?.user?.phone) contact = data.user.phone;
        }
      }

      if (!contact) return res.status(400).json({ success: false, error: 'NO_CONTACT_AVAILABLE' });

      const deviceName = getDeviceNameFromUA(req.get('user-agent') || undefined);
      const result = await LogicCore.initiateSensitiveAction(userId, contact, action, type, deviceName);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/auth/password/reset/initiate', async (req, res) => {
    try {
      const { identifier } = req.body;
      if (!identifier) return res.status(400).json({ success: false, error: 'MISSING_IDENTIFIER' });

      const result = await LogicCore.initiatePasswordReset(identifier);
      if (result.error) return res.status(400).json({ success: false, error: result.error.message });

      res.json({ success: true, message: 'Password reset email sent.' });
    } catch (e: any) {
      console.error(`[Auth] Password Reset Initiate Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.post('/auth/password/reset/complete', authenticate, async (req, res) => {
    try {
      const { password } = req.body;
      if (!password) return res.status(400).json({ success: false, error: 'MISSING_PASSWORD' });

      const result = await LogicCore.completePasswordReset(password);
      if (result.error) return res.status(400).json({ success: false, error: result.error.message });

      res.json({ success: true, message: 'Password updated successfully.' });
    } catch (e: any) {
      console.error(`[Auth] Password Reset Complete Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.post('/auth/refresh', async (req, res) => {
    try {
      const { refresh_token } = req.body;
      if (!refresh_token) return res.status(400).json({ success: false, error: 'MISSING_REFRESH_TOKEN' });

      const fingerprint = req.headers['x-orbi-fingerprint'] as string;
      const ip = req.ip;
      const result = await LogicCore.refreshSession(refresh_token, { fingerprint, ip });

      if (result.error) {
        return res.status(401).json({ success: false, error: result.error.message });
      }

      res.json({ success: true, data: result });
    } catch (e: any) {
      console.error(`[Auth] Refresh Session Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.post('/auth/logout', authenticate, async (req, res) => {
    try {
      const accessToken = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : undefined;
      const refreshToken = typeof req.body?.refresh_token === 'string' ? req.body.refresh_token : undefined;

      await LogicCore.logout(accessToken, refreshToken);
      res.json({ success: true, data: { logged_out: true } });
    } catch (e: any) {
      console.error('[Auth] Logout Error:', e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.get('/auth/bootstrap-state', async (req, res) => {
    if (!isInstitutionalNodeRequest(req)) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const state = await LogicCore.getBootstrapState();
      res.json({ success: true, data: state });
    } catch (e: any) {
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.post('/auth/bootstrap-admin', validate(BootstrapAdminSchema), async (req, res) => {
    if (!isInstitutionalNodeRequest(req)) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.bootstrapAdmin(req.body);
      if (result.error) {
        return res.status(400).json({ success: false, error: result.error });
      }
      res.json({ success: true, data: result.data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.post('/auth/signup', validate(SignUpSchema), async (req, res) => {
    try {
      const appId = String(req.headers['x-orbi-app-id'] || 'anonymous');
      const email = req.body.email || req.body.e;
      const password = req.body.password || req.body.p;
      const { metadata, ...profileFields } = req.body;

      delete (profileFields as any).e;
      delete (profileFields as any).p;
      delete (profileFields as any).email;
      delete (profileFields as any).password;

      const fullMetadata = { ...metadata, ...profileFields };
      const result = await LogicCore.signUp(email, password, fullMetadata, appId);

      if (result.error) {
        return res.status(400).json({ success: false, error: result.error.message || 'Registration failed' });
      }

      res.json({ success: true, data: result.data });
    } catch (e: any) {
      console.error(`[Auth] Signup Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.get('/auth/session', authenticate, async (req, res) => {
    try {
      res.json({ success: true, data: (req as any).session });
    } catch (e: any) {
      console.error(`[Auth] Session Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.get('/user/profile', authenticate, async (req, res) => {
    try {
      const session = (req as any).session;
      const result = await LogicCore.getUserProfile(session.sub);
      if (result.error) {
        return res.json({ success: true, data: session.user.user_metadata });
      }
      res.json({ success: true, data: result.data });
    } catch (e: any) {
      console.error(`[User] Profile Get Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.get('/service-access/requests/my', authenticate, async (req, res) => {
    try {
      const session = (req as any).session;
      await ensurePublicUserRow(session.sub, session.user);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const { data, error } = await sb
        .from('service_access_requests')
        .select('*')
        .eq('user_id', session.sub)
        .order('created_at', { ascending: false });

      if (error) {
        return res.status(500).json({ success: false, error: error.message });
      }

      res.json({ success: true, data: data || [] });
    } catch (e: any) {
      console.error('[ServiceAccess] List My Requests Error:', e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.post('/service-access/requests', authenticate, validate(ServiceAccessRequestCreateSchema), async (req, res) => {
    try {
      const session = (req as any).session;
      await ensurePublicUserRow(session.sub, session.user);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const currentRole = resolveSessionRole(session);
      const currentRegistryType = resolveSessionRegistryType(session);
      if (currentRegistryType === 'STAFF') {
        return res.status(403).json({
          success: false,
          error: 'STAFF_INELIGIBLE',
          message: 'Staff identities cannot request merchant or agent access through the consumer app.',
        });
      }

      const requestedRole = String(req.body.requested_role || '').trim().toUpperCase();
      const requestedRegistryType = mapServiceRoleToRegistryType(requestedRole);
      if (currentRole === requestedRole && currentRegistryType === requestedRegistryType) {
        return res.status(409).json({
          success: false,
          error: 'ROLE_ALREADY_ACTIVE',
          message: `Your account already has ${requestedRole} access.`,
        });
      }

      const { data: existingPending } = await sb
        .from('service_access_requests')
        .select('id')
        .eq('user_id', session.sub)
        .eq('requested_role', requestedRole)
        .in('status', ['pending', 'under_review'])
        .limit(1);

      if (existingPending && existingPending.length > 0) {
        return res.status(409).json({
          success: false,
          error: 'REQUEST_ALREADY_PENDING',
          message: `A ${requestedRole.toLowerCase()} access request is already pending review.`,
        });
      }

      const payload = {
        user_id: session.sub,
        requested_role: requestedRole,
        requested_registry_type: requestedRegistryType,
        current_user_role: currentRole,
        current_user_registry_type: currentRegistryType,
        business_name: req.body.business_name,
        phone: req.body.phone || session.user?.phone || session.user?.user_metadata?.phone || null,
        note: req.body.note,
        submitted_via: 'mobile_app',
        status: 'pending',
        metadata: {
          app_origin: session.user?.app_origin || session.user?.user_metadata?.app_origin,
          ...(req.body.metadata || {}),
        },
      };

      const { data, error } = await sb.from('service_access_requests').insert(payload).select('*').single();
      if (error) {
        return res.status(500).json({ success: false, error: error.message });
      }

      await Audit.log('ADMIN', session.sub, 'SERVICE_ACCESS_REQUEST_SUBMITTED', {
        requestId: data.id,
        requestedRole,
        requestedRegistryType,
      });

      res.status(201).json({ success: true, data });
    } catch (e: any) {
      console.error('[ServiceAccess] Create Request Error:', e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.patch('/user/profile', authenticate, async (req, res) => {
    try {
      const session = (req as any).session;
      const result = await LogicCore.updateUserProfile(session.sub, req.body, session.user.user_metadata);
      if (result.error) return res.status(403).json({ success: false, error: result.error });
      res.json({ success: true, data: result });
    } catch (e: any) {
      console.error(`[User] Profile Update Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.patch('/user/login-info', authenticate, async (req, res) => {
    try {
      const session = (req as any).session;
      const { email, password } = req.body;

      if (!email && !password) {
        return res.status(400).json({ success: false, error: 'MISSING_FIELDS: Provide email or password.' });
      }

      const result = await LogicCore.updateLoginInfo(session.sub, email, password);
      if (result.error) return res.status(400).json({ success: false, error: result.error });

      res.json({ success: true, message: 'Login information updated successfully.' });
    } catch (e: any) {
      console.error(`[User] Login Info Update Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.post('/user/avatar', authenticate, upload.single('file'), express.raw({ type: ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/heic', 'image/heif', 'application/octet-stream'], limit: '20mb' }), async (req, res) => {
    const session = (req as any).session;
    let file: Buffer | undefined;
    let contentType = req.headers['content-type'] || 'image/png';

    if (req.file) {
      file = req.file.buffer;
      contentType = req.file.mimetype;
    } else if (req.body instanceof Buffer) {
      file = req.body;
    } else if (typeof req.body === 'object' && ((req.body as any).image || (req.body as any).file)) {
      const rawData = (req.body as any).image || (req.body as any).file;
      if (typeof rawData === 'string' && rawData.includes('base64,')) {
        const base64Data = rawData.split('base64,')[1];
        file = Buffer.from(base64Data, 'base64');
      }
    }

    if (!file || !(file instanceof Buffer)) {
      return res.status(400).json({ success: false, error: 'INVALID_FILE_FORMAT', message: 'Please upload a valid image file (PNG, JPEG, WEBP, HEIC) as raw binary, multipart/form-data, or base64.' });
    }

    try {
      const oldUrl = session.user.user_metadata?.avatar_url;
      const newUrl = await LogicCore.uploadAvatar(session.sub, file, contentType, oldUrl);

      if (!newUrl) {
        return res.status(500).json({ success: false, error: 'UPLOAD_FAILED' });
      }

      res.json({ success: true, data: { avatar_url: newUrl } });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/user/kyc', authenticate, validate(KYCSubmitSchema), async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.submitKYC(session.sub, req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/user/kyc/status', authenticate, async (req, res) => {
    try {
      const session = (req as any).session;
      const result = await LogicCore.getKYCStatus(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      console.error(`[User] KYC Status Error:`, e);
      res.status(500).json({ success: false, error: 'INTERNAL_SERVER_ERROR', message: e.message });
    }
  });

  v1.post('/user/kyc/scan', authenticate, upload.single('file'), express.raw({ type: ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/heic', 'image/heif', 'application/octet-stream'], limit: '20mb' }), async (req, res) => {
    let file: Buffer | undefined;
    let contentType = req.headers['content-type'] || 'image/png';

    if (req.file) {
      file = req.file.buffer;
      contentType = req.file.mimetype;
    } else if (req.body instanceof Buffer) {
      file = req.body;
    } else if (typeof req.body === 'object' && ((req.body as any).image || (req.body as any).file)) {
      const rawData = (req.body as any).image || (req.body as any).file;
      if (typeof rawData === 'string' && rawData.includes('base64,')) {
        const base64Data = rawData.split('base64,')[1];
        file = Buffer.from(base64Data, 'base64');
      }
    }

    if (!file || !(file instanceof Buffer)) {
      return res.status(400).json({ success: false, error: 'INVALID_FILE_FORMAT', message: 'Please upload a valid document image as raw binary, multipart/form-data, or base64.' });
    }

    try {
      const result = await LogicCore.scanKYC(file, contentType);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/user/kyc/upload', authenticate, upload.single('file'), express.raw({ type: ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/heic', 'image/heif', 'application/pdf', 'application/octet-stream'], limit: '20mb' }), async (req, res) => {
    const session = (req as any).session;
    let file: Buffer | undefined;
    let contentType = req.headers['content-type'] || 'image/png';
    const fileName = req.headers['x-file-name'] as string || 'kyc_document';

    if (req.file) {
      file = req.file.buffer;
      contentType = req.file.mimetype;
    } else if (req.body instanceof Buffer) {
      file = req.body;
    } else if (typeof req.body === 'object' && ((req.body as any).image || (req.body as any).file)) {
      const rawData = (req.body as any).image || (req.body as any).file;
      if (typeof rawData === 'string' && rawData.includes('base64,')) {
        const base64Data = rawData.split('base64,')[1];
        file = Buffer.from(base64Data, 'base64');
      }
    }

    if (!file || !(file instanceof Buffer)) {
      return res.status(400).json({ success: false, error: 'INVALID_FILE_FORMAT', message: 'Please upload a valid document as raw binary, multipart/form-data, or base64.' });
    }

    try {
      const url = await LogicCore.uploadKYCDocument(session.sub, file, fileName, contentType);
      res.json({ success: true, data: { url } });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
};
