import type { RequestHandler, Router } from 'express';
import { z } from 'zod';
import { Audit } from '../../../backend/security/audit.js';
import { getAdminSupabase, getSupabase } from '../../../backend/supabaseClient.js';
import { ServiceActorOps } from '../../../backend/features/ServiceActorOps.js';
import { Messaging } from '../../../backend/features/MessagingService.js';
import { staffMessagingAdminService } from '../../../backend/features/StaffMessagingAdminService.js';
import { AuthService } from '../../../iam/authService.js';
import { sessionHasAnyRole } from '../../middleware/auth/authorization.js';

const MessageAudienceFiltersSchema = z.object({
  search: z.string().trim().optional(),
  country: z.string().trim().optional(),
  registryType: z.string().trim().optional(),
  kycStatus: z.string().trim().optional(),
  accountStatus: z.string().trim().optional(),
  appOrigin: z.string().trim().optional(),
  hasPhone: z.boolean().optional(),
  hasEmail: z.boolean().optional(),
  createdAfter: z.string().trim().optional(),
  createdBefore: z.string().trim().optional(),
  newCustomersWithinDays: z.coerce.number().int().positive().optional(),
  minTransactionCount: z.coerce.number().int().min(0).optional(),
  minTransactionAmount: z.coerce.number().min(0).optional(),
  maxTransactionAmount: z.coerce.number().min(0).optional(),
  minTotalTransactionAmount: z.coerce.number().min(0).optional(),
  currency: z.string().trim().optional(),
  limit: z.coerce.number().int().min(1).max(5000).optional(),
});

const TemplateCatalogQuerySchema = z.object({
  search: z.string().trim().optional(),
  channel: z.enum(['sms', 'email', 'push', 'whatsapp']).optional(),
  language: z.enum(['en', 'sw']).optional(),
  messageType: z.enum(['transactional', 'promotional']).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

const TemplatePreviewSchema = z.object({
  templateName: z.string().min(1),
  variables: z.record(z.string(), z.unknown()).optional(),
  channel: z.enum(['sms', 'email', 'push', 'whatsapp']).optional(),
  language: z.enum(['en', 'sw']).optional(),
  messageType: z.enum(['transactional', 'promotional']).optional(),
});

const StaffTemplatedSendSchema = z.object({
  templateName: z.string().min(1),
  variables: z.record(z.string(), z.unknown()).optional(),
  userIds: z.array(z.string().uuid()).optional(),
  filters: MessageAudienceFiltersSchema.optional(),
  channel: z.enum(['sms', 'email', 'push', 'whatsapp']).optional(),
  language: z.enum(['en', 'sw']).optional(),
  messageType: z.enum(['transactional', 'promotional']).optional(),
  category: z.enum(['security', 'update', 'promo', 'info']).optional(),
  maxRecipients: z.coerce.number().int().min(1).max(500).optional(),
});

const StaffSystemSmsSchema = z.object({
  body: z.string().min(1).max(2000),
  userIds: z.array(z.string().uuid()).optional(),
  filters: MessageAudienceFiltersSchema.optional(),
  category: z.enum(['security', 'update', 'promo', 'info']).optional(),
  maxRecipients: z.coerce.number().int().min(1).max(500).optional(),
});

type Deps = {
  authenticate: RequestHandler;
  adminOnly: RequestHandler;
  validate: (schema: any) => RequestHandler;
  requireSessionPermission: (permissions: string[], roles?: string[]) => RequestHandler;
  LogicCore: any;
  queryStringValue: (value: unknown) => string | undefined;
  syncUserIdentityClassification: (userId: string, updates: { role: string; registryType: string; metadata?: Record<string, any> }) => Promise<void>;
  mapServiceRoleToRegistryType: (role: string) => string;
  TransactionIssueSchema: any;
  TransactionAuditDecisionSchema: any;
  DocumentVerifySchema: any;
  StaffCreateSchema: any;
  StaffAdminUpdateSchema: any;
  StaffPasswordResetSchema: any;
  ManagedIdentityCreateSchema: any;
  ServiceAccessRequestReviewSchema: any;
  AccountStatusUpdateSchema: any;
  UserProfileUpdateSchema: any;
  messagingTestRoutesEnabled: boolean;
};

export const registerAdminOpsRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    adminOnly,
    validate,
    requireSessionPermission,
    LogicCore,
    queryStringValue,
    syncUserIdentityClassification,
    mapServiceRoleToRegistryType,
    TransactionIssueSchema,
    TransactionAuditDecisionSchema,
    DocumentVerifySchema,
    StaffCreateSchema,
    StaffAdminUpdateSchema,
    StaffPasswordResetSchema,
    ManagedIdentityCreateSchema,
    ServiceAccessRequestReviewSchema,
    AccountStatusUpdateSchema,
    UserProfileUpdateSchema,
    messagingTestRoutesEnabled,
  } = deps;

  v1.get('/admin/transactions', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'AUDIT', 'CUSTOMER_CARE', 'ACCOUNTANT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.getAllTransactions({
        limit: Number(queryStringValue(req.query.limit) || 100),
        offset: Number(queryStringValue(req.query.offset) || 0),
        status: queryStringValue(req.query.status),
        type: queryStringValue(req.query.type),
        currency: queryStringValue(req.query.currency),
        query: queryStringValue(req.query.query),
        dateFrom: queryStringValue(req.query.dateFrom),
        dateTo: queryStringValue(req.query.dateTo),
      });
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/transactions/summary', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'AUDIT', 'CUSTOMER_CARE', 'ACCOUNTANT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.getTransactionVolumeSummary({
        status: queryStringValue(req.query.status),
        type: queryStringValue(req.query.type),
        currency: queryStringValue(req.query.currency),
        query: queryStringValue(req.query.query),
        dateFrom: queryStringValue(req.query.dateFrom),
        dateTo: queryStringValue(req.query.dateTo),
      });
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/transactions/:id/ledger', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'AUDIT', 'CUSTOMER_CARE'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.getLedgerEntries(req.params.id);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/transactions/:id/lock', authenticate, validate(TransactionIssueSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'AUDIT', 'CUSTOMER_CARE'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const transactionId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const result = await LogicCore.lockTransactionForAdmin(session.sub, transactionId, req.body.reason);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/transactions/:id/audit', authenticate, validate(TransactionAuditDecisionSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const transactionId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const result = await LogicCore.recordTransactionAuditDecision(session.sub, transactionId, req.body.passed, req.body.notes);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/transactions/:id/approve', authenticate, validate(TransactionIssueSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const transactionId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const result = await LogicCore.approveReviewedTransaction(session.sub, transactionId, req.body.reason);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/transactions/approve-audited', authenticate, validate(TransactionIssueSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.approveAllAuditPassedTransactions(session.sub, req.body.reason);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/transactions/:id/reverse', authenticate, validate(TransactionIssueSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const transactionId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      await LogicCore.reverseTransactionForAdmin(session.sub, transactionId, req.body.reason);
      res.json({ success: true });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/documents/:id/verify', authenticate, validate(DocumentVerifySchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'CUSTOMER_CARE'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.verifyDocument(req.params.id as string, session.sub, req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/staff', authenticate, requireSessionPermission(['staff.write'], ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE']), validate(StaffCreateSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.createStaff(req.body, session.sub);
      if (result.error) return res.status(400).json({ success: false, error: result.error });
      res.json({ success: true, data: result.data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/staff', authenticate, requireSessionPermission(['staff.read', 'staff.write'], ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE', 'AUDIT']), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await LogicCore.getAllStaff();
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/staff/:id', authenticate, requireSessionPermission(['staff.write'], ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE']), validate(StaffAdminUpdateSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.adminUpdateStaffProfile(req.params.id as string, req.body, session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/staff/:id/activity', authenticate, requireSessionPermission(['staff.read', 'admin.audit.read'], ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE', 'AUDIT']), async (req, res) => {
    try {
      const staffId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const data = await LogicCore.getDetailedUserActivity(staffId);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/staff/:id/reset-password', authenticate, requireSessionPermission(['staff.write'], ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE']), validate(StaffPasswordResetSchema), async (req, res) => {
    const session = (req as any).session;

    try {
      const result = await LogicCore.adminResetStaffPassword(req.params.id as string, req.body.password, session.sub);
      if (result?.error) return res.status(400).json({ success: false, error: result.error });
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/permissions/preview', authenticate, requireSessionPermission(['staff.read', 'staff.write'], ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE', 'AUDIT']), async (req, res) => {
    try {
      const role = String(queryStringValue(req.query.role) || 'USER').trim().toUpperCase();
      const status = String(queryStringValue(req.query.status) || 'active').trim().toLowerCase();
      const permissions = new AuthService().describePermissionsForRole(role as any, status);
      res.json({ success: true, data: { role, status, permissions } });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/users/register', authenticate, validate(ManagedIdentityCreateSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.createManagedIdentity(req.body, session.sub);
      if (result.error) return res.status(400).json({ success: false, error: result.error });
      res.json({ success: true, data: result.data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/service-access/requests', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'CUSTOMER_CARE', 'AUDIT', 'HUMAN_RESOURCE'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) {
        return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      }

      let query = sb.from('service_access_requests').select('*').order('created_at', { ascending: false });
      const status = String(req.query.status || '').trim();
      const requestedRole = String(req.query.requestedRole || req.query.requested_role || '').trim().toUpperCase();
      if (status) query = query.eq('status', status);
      if (requestedRole) query = query.eq('requested_role', requestedRole);

      const { data, error } = await query;
      if (error) return res.status(500).json({ success: false, error: error.message });
      res.json({ success: true, data: data || [] });
    } catch (e: any) {
      console.error('[Admin] Service Access Requests Error:', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/service-access/requests/:id/review', authenticate, validate(ServiceAccessRequestReviewSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'CUSTOMER_CARE', 'HUMAN_RESOURCE'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) {
        return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      }

      const { data: existing, error: fetchError } = await sb.from('service_access_requests').select('*').eq('id', req.params.id).maybeSingle();
      if (fetchError) return res.status(500).json({ success: false, error: fetchError.message });
      if (!existing) return res.status(404).json({ success: false, error: 'REQUEST_NOT_FOUND' });

      const currentStatus = String(existing.status || '').toLowerCase();
      if (currentStatus !== 'pending' && currentStatus !== 'under_review') {
        return res.status(409).json({ success: false, error: 'REQUEST_ALREADY_RESOLVED' });
      }

      const decision = String(req.body.decision || '').trim().toUpperCase();
      const reviewNote = req.body.review_note;
      const now = new Date().toISOString();
      const updatePayload: any = {
        status: decision === 'APPROVED' ? 'approved' : 'rejected',
        review_note: reviewNote || null,
        reviewed_by: session.sub,
        reviewed_at: now,
        updated_at: now,
      };

      let provisioning: any = null;
      if (decision === 'APPROVED') {
        updatePayload.approved_at = now;
        await syncUserIdentityClassification(existing.user_id, {
          role: existing.requested_role,
          registryType: existing.requested_registry_type || mapServiceRoleToRegistryType(existing.requested_role),
          metadata: {
            service_access_approved_at: now,
            service_access_approved_role: existing.requested_role,
          },
        });
        provisioning = await ServiceActorOps.provisionApprovedActorAccess(existing.user_id, existing.requested_role);

        await Messaging.dispatchServiceActivity(existing.user_id, 'SERVICE_ACCESS_APPROVED', {
          actorLabel: existing.requested_role === 'AGENT' ? 'Agent desk' : 'Merchant desk',
        }, 'info');
      }

      const { data, error } = await sb.from('service_access_requests').update(updatePayload).eq('id', req.params.id).select('*').single();
      if (error) return res.status(500).json({ success: false, error: error.message });

      await Audit.log('ADMIN', session.sub, 'SERVICE_ACCESS_REQUEST_REVIEWED', {
        requestId: req.params.id,
        decision,
        targetUserId: existing.user_id,
        requestedRole: existing.requested_role,
      });

      res.json({ success: true, data, provisioning });
    } catch (e: any) {
      console.error('[Admin] Service Access Review Error:', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/service-links', authenticate, adminOnly, async (req, res) => {
    try {
      const actorRole = typeof req.query.actorRole === 'string' ? req.query.actorRole.toUpperCase() : undefined;
      const actorUserId = typeof req.query.actorUserId === 'string' ? req.query.actorUserId : undefined;
      const result = await LogicCore.getServiceLinkedCustomers(actorUserId, actorRole);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/service-commissions', authenticate, adminOnly, async (req, res) => {
    try {
      const actorRole = typeof req.query.actorRole === 'string' ? req.query.actorRole.toUpperCase() : undefined;
      const actorUserId = typeof req.query.actorUserId === 'string' ? req.query.actorUserId : undefined;
      const result = await LogicCore.getServiceCommissions(actorUserId, actorRole);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/users/:id/status', authenticate, validate(AccountStatusUpdateSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      await LogicCore.updateAccountStatus(req.params.id as string, req.body.status, session.sub);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/users/:id/profile', authenticate, validate(UserProfileUpdateSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'HUMAN_RESOURCE'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.adminUpdateUserProfile(req.params.id as string, req.body, session.sub);
      if (result.error) return res.status(400).json({ success: false, error: result.error });
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/messaging/templates', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'CUSTOMER_CARE', 'MARKETING', 'IT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const query = TemplateCatalogQuerySchema.parse(req.query);
      const data = await staffMessagingAdminService.searchTemplates(query);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/messaging/templates/preview', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'CUSTOMER_CARE', 'MARKETING', 'IT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const payload = TemplatePreviewSchema.parse(req.body);
      const data = await staffMessagingAdminService.previewTemplate(payload);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/messaging/audience/preview', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'CUSTOMER_CARE', 'MARKETING', 'IT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const filters = MessageAudienceFiltersSchema.parse(req.body || {});
      const data = await staffMessagingAdminService.previewAudience(filters);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/messaging/send-template', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'CUSTOMER_CARE', 'MARKETING', 'IT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const payload = StaffTemplatedSendSchema.parse(req.body);
      const data = await staffMessagingAdminService.sendTemplated({
        actorId: session.sub,
        ...payload,
      });

      await Audit.log('ADMIN', session.sub, 'STAFF_TEMPLATE_MESSAGE_SENT', {
        templateName: payload.templateName,
        userIdCount: payload.userIds?.length || 0,
        hasFilters: !!payload.filters,
        category: payload.category || null,
      });

      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/messaging/send-system-sms', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'CUSTOMER_CARE', 'IT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const payload = StaffSystemSmsSchema.parse(req.body);
      const data = await staffMessagingAdminService.sendSystemCustomSms({
        actorId: session.sub,
        ...payload,
      });

      await Audit.log('ADMIN', session.sub, 'STAFF_SYSTEM_SMS_SENT', {
        userIdCount: payload.userIds?.length || 0,
        hasFilters: !!payload.filters,
        category: payload.category || null,
      });

      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  if (messagingTestRoutesEnabled) {
    v1.post('/messaging/email', authenticate, async (_req, res) => {
      res.status(403).json({ success: false, error: 'EMAIL_SERVICE_DISABLED' });
    });
  }
};
