import { NextFunction, Request, Response } from 'express';
import { Server as LogicCore } from '../../../backend/server.js';
import { WAF } from '../../../backend/security/waf.js';
import { getAdminSupabase } from '../../../backend/supabaseClient.js';
import {
  TRUSTED_INSTITUTIONAL_APP_ORIGINS,
  TRUSTED_MOBILE_APP_IDS,
  TRUSTED_MOBILE_APP_ORIGINS,
  isInstitutionalAppIdentity,
} from '../../../backend/config/appIdentity.js';

export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.startsWith('Bearer ')
    ? req.headers.authorization.substring(7)
    : null;
  try {
    const session = await LogicCore.getSession(token || undefined);
    if (!session) throw new Error('IDENTITY_REQUIRED');

    const appIdHeader = String(req.get('x-orbi-app-id') || '');
    const appOriginHeader = String(req.get('x-orbi-app-origin') || '');
    const roleHeader = String(req.get('x-orbi-user-role') || '').trim().toUpperCase();
    const registryTypeHeader = String(req.get('x-orbi-registry-type') || '').trim().toUpperCase();
    const sessionRole = String(
      session.role ||
      session.user?.role ||
      session.user?.user_metadata?.role ||
      'USER',
    ).trim().toUpperCase();
    const sessionOrigin = String(
      session.user?.app_origin ||
      session.user?.user_metadata?.app_origin ||
      '',
    ).trim();
    const registryType = String(
      session.user?.registry_type ||
      session.user?.user_metadata?.registry_type ||
      'CONSUMER',
    ).trim().toUpperCase();

    const isInstitutionalNode = isInstitutionalAppIdentity(appIdHeader, appOriginHeader);
    const isMobileNode =
      TRUSTED_MOBILE_APP_IDS.includes(appIdHeader) ||
      TRUSTED_MOBILE_APP_ORIGINS.includes(appOriginHeader);

    if (roleHeader && roleHeader !== sessionRole) {
      return res.status(403).json({
        success: false,
        error: 'ROLE_HEADER_MISMATCH',
        message: 'The declared user role header does not match the authenticated session role.',
      });
    }

    if (registryTypeHeader && registryTypeHeader !== registryType) {
      return res.status(403).json({
        success: false,
        error: 'REGISTRY_HEADER_MISMATCH',
        message: 'The declared registry type header does not match the authenticated session registry type.',
      });
    }

    if (isInstitutionalNode) {
      if (!roleHeader) {
        return res.status(403).json({
          success: false,
          error: 'ROLE_HEADER_REQUIRED',
          message: 'Institutional requests must include x-orbi-user-role.',
        });
      }

      if (!TRUSTED_INSTITUTIONAL_APP_ORIGINS.includes(sessionOrigin)) {
        return res.status(403).json({
          success: false,
          error: 'NODE_ORIGIN_MISMATCH',
          message: 'Institutional node access is limited to institutional identities.',
        });
      }

      if (registryType !== 'STAFF') {
        return res.status(403).json({
          success: false,
          error: 'STAFF_IDENTITY_REQUIRED',
          message: 'Institutional node access is reserved for staff identities.',
        });
      }
    }

    if (isMobileNode && registryType === 'STAFF') {
      return res.status(403).json({
        success: false,
        error: 'CONSUMER_NODE_REQUIRED',
        message: 'Staff identities cannot use the consumer mobile node.',
      });
    }

    const status = session.user.user_metadata?.account_status || 'active';
    if (status === 'blocked' || status === 'frozen') {
      return res.status(403).json({
        success: false,
        error: 'IDENTITY_LOCKED',
        message: `Your account has been ${status.toUpperCase()} by Cluster Governance.`,
      });
    }

    const operation = req.path.replace(/\//g, '_').substring(1);
    await WAF.throttle(session.user.id, operation);

    (req as any).session = session;
    (req as any).authToken = token || session.access_token || null;
    (req as any).resolvedRole = sessionRole;
    next();
  } catch (err: any) {
    if (String(err.message || '').startsWith('RATE_LIMIT_EXCEEDED')) {
      return res.status(429).json({
        success: false,
        error: 'RATE_LIMIT_EXCEEDED',
        message: err.message,
      });
    }
    res.status(401).json({ success: false, error: 'AUTH_REQUIRED', message: err.message });
  }
};

export const resolveSessionRole = (session: any): string =>
  String(
    session?.role ||
    session?.user?.role ||
    session?.user?.user_metadata?.role ||
    'USER',
  ).trim().toUpperCase();

export const requireRole = (session: any, roles: string[]): boolean =>
  roles.includes(resolveSessionRole(session));

export const resolveSessionRegistryType = (session: any): string =>
  String(
    session?.user?.registry_type ||
    session?.user?.user_metadata?.registry_type ||
    'CONSUMER',
  ).trim().toUpperCase();

export const mapServiceRoleToRegistryType = (role: string): 'MERCHANT' | 'AGENT' => {
  if (String(role).trim().toUpperCase() === 'AGENT') return 'AGENT';
  return 'MERCHANT';
};

export const adminOnly = async (req: Request, res: Response, next: NextFunction) => {
  const session = (req as any).session;
  if (!session) return res.status(401).json({ success: false, error: 'AUTH_REQUIRED' });

  const role = session.user.user_metadata?.role;
  const orgRole = session.user.user_metadata?.org_role;

  if (role === 'ADMIN' || role === 'STAFF' || orgRole === 'ADMIN') {
    return next();
  }
  res.status(403).json({ success: false, error: 'ADMIN_ACCESS_REQUIRED' });
};

const hasSessionPermission = (session: any, permission: string) => {
  const permissions = Array.isArray(session?.permissions) ? session.permissions : [];
  return permissions.includes(permission);
};

export const requireSessionPermission =
  (permissions: string[], allowedRoles: string[] = []) =>
  (req: Request, res: Response, next: NextFunction) => {
    const session = (req as any).session;
    if (!session) {
      return res.status(401).json({ success: false, error: 'AUTH_REQUIRED' });
    }
    const role = String(session.role || session.user?.role || '').toUpperCase();
    if (
      allowedRoles.includes(role) ||
      permissions.some((permission) => hasSessionPermission(session, permission))
    ) {
      return next();
    }
    return res
      .status(403)
      .json({ success: false, error: 'ACCESS_DENIED', message: 'Missing required permission.' });
  };

export const syncAgentIdentityClassification = async (
  userId: string,
  metadata?: Record<string, any>,
) => {
  const adminSb = getAdminSupabase();
  if (!adminSb) throw new Error('DB_OFFLINE');

  const { data: userRow } = await adminSb
    .from('users')
    .select('full_name')
    .eq('id', userId)
    .maybeSingle();

  await adminSb.from('agents').upsert(
    {
      user_id: userId,
      display_name: userRow?.full_name || 'Agent',
      status: 'active',
      commission_enabled: true,
      metadata: metadata || {},
    },
    { onConflict: 'user_id' },
  );
};
