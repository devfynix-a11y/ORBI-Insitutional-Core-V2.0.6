import { type RequestHandler, type Router } from 'express';
import { Messaging } from '../../../backend/features/MessagingService.js';

type Deps = {
  authenticate: RequestHandler;
  LogicCore: any;
  getSupabase: () => any;
  getAdminSupabase: () => any;
  SharedBudgetCreateSchema: any;
  SharedBudgetUpdateSchema: any;
  SharedBudgetMemberAddSchema: any;
  SharedBudgetInviteResponseSchema: any;
  SharedBudgetApprovalResponseSchema: any;
  SharedBudgetSpendSchema: any;
  wealthNumber: (value: any) => number;
  resolveSharedBudgetMembership: (sb: any, budgetId: string, userId: string) => Promise<any>;
  canManageSharedBudget: (role: string) => boolean;
  canSpendFromSharedBudget: (role: string) => boolean;
  canReviewSharedBudgetSpend: (role: string) => boolean;
  resolveUserBySharedBudgetIdentifier: (sb: any, identifier: string) => Promise<any>;
  expireSharedBudgetInvitationIfNeeded: (sb: any, invite: any) => Promise<any>;
  executeSharedBudgetSpend: (sb: any, input: any) => Promise<any>;
};

export const registerSharedBudgetRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    LogicCore,
    getSupabase,
    getAdminSupabase,
    SharedBudgetCreateSchema,
    SharedBudgetUpdateSchema,
    SharedBudgetMemberAddSchema,
    SharedBudgetInviteResponseSchema,
    SharedBudgetApprovalResponseSchema,
    SharedBudgetSpendSchema,
    wealthNumber,
    resolveSharedBudgetMembership,
    canManageSharedBudget,
    canSpendFromSharedBudget,
    canReviewSharedBudgetSpend,
    resolveUserBySharedBudgetIdentifier,
    expireSharedBudgetInvitationIfNeeded,
    executeSharedBudgetSpend,
  } = deps;

  v1.get('/wealth/shared-budgets', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data: memberships, error: memberError } = await sb
        .from('shared_budget_members')
        .select('budget_id, role')
        .eq('user_id', session.sub);
      if (memberError) return res.status(400).json({ success: false, error: memberError.message });

      const memberBudgetIds = Array.from(new Set((memberships || []).map((item: any) => String(item.budget_id || '')).filter(Boolean)));
      let query = sb
        .from('shared_budgets')
        .select('*')
        .eq('owner_user_id', session.sub);
      if (memberBudgetIds.length > 0) {
        query = sb
          .from('shared_budgets')
          .select('*')
          .or([
            `owner_user_id.eq.${session.sub}`,
            `id.in.(${memberBudgetIds.join(',')})`,
          ].join(','));
      }
      const { data, error } = await query.order('created_at', { ascending: false });
      if (error) return res.status(400).json({ success: false, error: error.message });
      const membershipByBudget = new Map(
        (memberships || []).map((item: any) => [String(item.budget_id), String(item.role || 'SPENDER').toUpperCase()]),
      );
      const items = (data || []).map((budget: any) => ({
        ...budget,
        my_role: budget.owner_user_id === session.sub
          ? 'OWNER'
          : (membershipByBudget.get(String(budget.id)) || 'SPENDER'),
        is_owner: budget.owner_user_id === session.sub,
        remaining_amount: Math.max(0, wealthNumber(budget.budget_limit) - wealthNumber(budget.spent_amount)),
      }));
      res.json({ success: true, data: { budgets: items } });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budgets', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetCreateSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb
        .from('shared_budgets')
        .insert({
          owner_user_id: session.sub,
          name: payload.name,
          purpose: payload.purpose,
          currency: payload.currency?.toUpperCase() || 'TZS',
          budget_limit: payload.budget_limit,
          spent_amount: 0,
          period_type: payload.period_type || 'MONTHLY',
          approval_mode: payload.approval_mode || 'AUTO',
          status: 'ACTIVE',
          metadata: { created_from: 'mobile_app' },
        })
        .select('*')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });
      await sb.from('shared_budget_members').insert({
        budget_id: data.id,
        user_id: session.sub,
        role: 'OWNER',
        spent_amount: 0,
      });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.patch('/wealth/shared-budgets/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetUpdateSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canManageSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }
      const updatePayload: any = { updated_at: new Date().toISOString() };
      if (payload.name !== undefined) updatePayload.name = payload.name;
      if (payload.purpose !== undefined) updatePayload.purpose = payload.purpose;
      if (payload.currency !== undefined) updatePayload.currency = payload.currency.toUpperCase();
      if (payload.budget_limit !== undefined) updatePayload.budget_limit = payload.budget_limit;
      if (payload.period_type !== undefined) updatePayload.period_type = payload.period_type;
      if (payload.approval_mode !== undefined) updatePayload.approval_mode = payload.approval_mode;
      if (payload.status !== undefined) updatePayload.status = payload.status;
      const { data, error } = await sb
        .from('shared_budgets')
        .update(updatePayload)
        .eq('id', req.params.id)
        .select('*')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/wealth/shared-budgets/:id/members', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      const { data, error } = await sb
        .from('shared_budget_members')
        .select('id,budget_id,user_id,role,status,member_limit,spent_amount,metadata,created_at, users!shared_budget_members_user_id_fkey(id, full_name, email, phone)')
        .eq('budget_id', budget.id)
        .order('created_at', { ascending: true });
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data: { members: data || [] } });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/wealth/shared-budgets/:id/transactions', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      const { data, error } = await sb
        .from('shared_budget_transactions')
        .select('*, users!shared_budget_transactions_member_user_id_fkey(id, full_name, email, phone)')
        .eq('shared_budget_id', budget.id)
        .order('created_at', { ascending: false });
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data: { transactions: data || [] } });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/wealth/shared-budgets/:id/invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canManageSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }
      const { data, error } = await sb
        .from('shared_budget_invitations')
        .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at, users!shared_budget_invitations_invitee_user_id_fkey(id, full_name, email, phone)')
        .eq('budget_id', budget.id)
        .order('created_at', { ascending: false });
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data: { invitations: data || [] } });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/wealth/shared-budget-invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb
        .from('shared_budget_invitations')
        .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at, shared_budgets!shared_budget_invitations_budget_id_fkey(id, name, purpose, currency, budget_limit, spent_amount, period_type, approval_mode, status), users!shared_budget_invitations_inviter_user_id_fkey(id, full_name, email, phone)')
        .eq('invitee_user_id', session.sub)
        .order('created_at', { ascending: false });
      if (error) return res.status(400).json({ success: false, error: error.message });
      const invitations = [];
      for (const invite of data || []) {
        invitations.push(await expireSharedBudgetInvitationIfNeeded(sb, invite));
      }
      res.json({ success: true, data: { invitations } });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budgets/:id/invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetMemberAddSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canManageSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }
      const memberUser = await resolveUserBySharedBudgetIdentifier(sb, payload.identifier);
      if (!memberUser?.id) {
        return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
      }
      if (String(memberUser.id) === String(budget.owner_user_id)) {
        return res.status(400).json({ success: false, error: 'OWNER_ALREADY_MEMBER' });
      }
      const { data: existingMember, error: existingMemberError } = await sb
        .from('shared_budget_members')
        .select('id')
        .eq('budget_id', budget.id)
        .eq('user_id', memberUser.id)
        .maybeSingle();
      if (existingMemberError) return res.status(400).json({ success: false, error: existingMemberError.message });
      if (existingMember) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_ALREADY_EXISTS' });
      }
      const { data: pendingInvite, error: pendingInviteError } = await sb
        .from('shared_budget_invitations')
        .select('*')
        .eq('budget_id', budget.id)
        .eq('invitee_user_id', memberUser.id)
        .eq('status', 'PENDING')
        .order('created_at', { ascending: false })
        .limit(1)
        .single();
      if (pendingInviteError && pendingInviteError.code !== 'PGRST116') {
        return res.status(400).json({ success: false, error: pendingInviteError.message });
      }
      if (pendingInvite) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_INVITE_ALREADY_PENDING' });
      }

      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      const { data, error } = await sb
        .from('shared_budget_invitations')
        .insert({
          budget_id: budget.id,
          inviter_user_id: session.sub,
          invitee_user_id: memberUser.id,
          invitee_identifier: payload.identifier,
          role: payload.role || 'SPENDER',
          member_limit: payload.member_limit || null,
          message: payload.message || null,
          expires_at: expiresAt,
          metadata: {
            invited_by: session.sub,
            invite_source: 'shared_budget_member_sheet',
            identifier: payload.identifier,
          },
        })
        .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });

      await Messaging.dispatch(
        String(memberUser.id),
        'info',
        'Shared budget invitation',
        `${session.user?.user_metadata?.full_name || 'A member'} invited you to join "${budget.name}" as ${String(payload.role || 'SPENDER').toLowerCase()}.`,
        {
          push: true,
          sms: false,
          email: true,
          eventCode: 'SHARED_BUDGET_INVITATION',
          variables: {
            budget_name: budget.name,
            role: payload.role || 'SPENDER',
            invite_id: data.id,
          },
        },
      );

      res.json({ success: true, data: { invitation: data } });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budget-invitations/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetInviteResponseSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const { data: inviteRaw, error: inviteError } = await sb
        .from('shared_budget_invitations')
        .select('*')
        .eq('id', req.params.id)
        .maybeSingle();
      if (inviteError) return res.status(400).json({ success: false, error: inviteError.message });
      if (!inviteRaw) return res.status(404).json({ success: false, error: 'SHARED_BUDGET_INVITE_NOT_FOUND' });
      const invite = await expireSharedBudgetInvitationIfNeeded(sb, inviteRaw);

      if (String(invite.invitee_user_id || '') !== String(session.sub)) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_INVITE_ACCESS_DENIED' });
      }
      if (String(invite.status || '').toUpperCase() !== 'PENDING') {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_INVITE_NOT_PENDING' });
      }

      if (payload.action === 'REJECT') {
        const { data, error } = await sb
          .from('shared_budget_invitations')
          .update({
            status: 'REJECTED',
            responded_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          })
          .eq('id', invite.id)
          .select('*')
          .single();
        if (error) return res.status(400).json({ success: false, error: error.message });
        return res.json({ success: true, data: { invitation: data } });
      }

      const { data: existingMember, error: existingMemberError } = await sb
        .from('shared_budget_members')
        .select('id')
        .eq('budget_id', invite.budget_id)
        .eq('user_id', session.sub)
        .maybeSingle();
      if (existingMemberError) return res.status(400).json({ success: false, error: existingMemberError.message });
      if (existingMember) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_ALREADY_EXISTS' });
      }

      const { data: member, error: memberError } = await sb
        .from('shared_budget_members')
        .insert({
          budget_id: invite.budget_id,
          user_id: session.sub,
          role: invite.role || 'SPENDER',
          status: 'ACTIVE',
          member_limit: invite.member_limit || null,
          spent_amount: 0,
          metadata: {
            joined_via_invitation: invite.id,
            invited_by: invite.inviter_user_id,
          },
        })
        .select('*')
        .single();
      if (memberError) return res.status(400).json({ success: false, error: memberError.message });

      const { data: updatedInvite, error: updateInviteError } = await sb
        .from('shared_budget_invitations')
        .update({
          status: 'ACCEPTED',
          responded_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .eq('id', invite.id)
        .select('*')
        .single();
      if (updateInviteError) return res.status(400).json({ success: false, error: updateInviteError.message });

      res.json({ success: true, data: { invitation: updatedInvite, member } });
    } catch (e: any) {
      const status = e.message === 'SHARED_BUDGET_INVITE_ACCESS_DENIED' ? 403 : 400;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.get('/wealth/shared-budgets/:id/approvals', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canReviewSharedBudgetSpend(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }
      const { data, error } = await sb
        .from('shared_budget_approvals')
        .select('*, users!shared_budget_approvals_requester_user_id_fkey(id, full_name, email, phone), reviewer:users!shared_budget_approvals_reviewer_user_id_fkey(id, full_name, email, phone)')
        .eq('shared_budget_id', budget.id)
        .order('created_at', { ascending: false });
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data: { approvals: data || [] } });
    } catch (e: any) {
      const status = e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budget-approvals/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetApprovalResponseSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const { data: approval, error: approvalError } = await sb
        .from('shared_budget_approvals')
        .select('*')
        .eq('id', req.params.id)
        .maybeSingle();
      if (approvalError) return res.status(400).json({ success: false, error: approvalError.message });
      if (!approval) return res.status(404).json({ success: false, error: 'SHARED_BUDGET_APPROVAL_NOT_FOUND' });
      if (String(approval.status || '').toUpperCase() !== 'PENDING') {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_APPROVAL_NOT_PENDING' });
      }

      const { budget, membership } = await resolveSharedBudgetMembership(sb, approval.shared_budget_id, session.sub);
      if (!canReviewSharedBudgetSpend(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }

      if (payload.action === 'REJECT') {
        const { data, error } = await sb
          .from('shared_budget_approvals')
          .update({
            status: 'REJECTED',
            reviewer_user_id: session.sub,
            responded_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            note: payload.note ?? approval.note ?? null,
          })
          .eq('id', approval.id)
          .select('*')
          .single();
        if (error) return res.status(400).json({ success: false, error: error.message });
        return res.json({ success: true, data: { approval: data } });
      }

      const requesterMembershipResult = await resolveSharedBudgetMembership(
        sb,
        approval.shared_budget_id,
        String(approval.requester_user_id),
      );

      const approvalMetadata = approval.metadata && typeof approval.metadata === 'object'
        ? approval.metadata
        : {};

      const spendPayload = {
        source_wallet_id: approvalMetadata.source_wallet_id || null,
        amount: wealthNumber(approval.amount),
        currency: approval.currency || budget.currency || 'TZS',
        provider: approval.provider || null,
        bill_category: approval.bill_category || null,
        reference: approval.reference || null,
        description: approval.note || null,
        type: approvalMetadata.type || 'EXTERNAL_PAYMENT',
        metadata: {
          ...approvalMetadata,
          approval_reviewer_user_id: session.sub,
          approval_reviewer_role: membership.role || 'MANAGER',
          approval_response_note: payload.note || null,
        },
      };

      const spendData = await executeSharedBudgetSpend(sb, {
        budget,
        membership: requesterMembershipResult.membership,
        actorUserId: String(approval.requester_user_id),
        actorUser: {
          ...(session.user || {}),
          id: String(approval.requester_user_id),
        },
        payload: spendPayload,
        approvalId: approval.id,
      });

      const transactionId = (spendData as any)?.transaction?.internalId || (spendData as any)?.transaction?.id || null;
      const { data: updatedApproval, error: approvalUpdateError } = await sb
        .from('shared_budget_approvals')
        .update({
          status: 'APPROVED',
          reviewer_user_id: session.sub,
          responded_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          metadata: {
            ...approvalMetadata,
            approved_transaction_id: transactionId,
            approval_response_note: payload.note || null,
          },
        })
        .eq('id', approval.id)
        .select('*')
        .single();
      if (approvalUpdateError) return res.status(400).json({ success: false, error: approvalUpdateError.message });

      res.json({ success: true, data: { approval: updatedApproval, ...spendData } });
    } catch (e: any) {
      const status = e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budgets/:id/spend/preview', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetSpendSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canSpendFromSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_SPEND_DENIED' });
      }
      const currentSpent = wealthNumber(budget.spent_amount);
      const budgetLimit = wealthNumber(budget.budget_limit);
      if (currentSpent + payload.amount > budgetLimit) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_LIMIT_EXCEEDED' });
      }
      const memberSpent = wealthNumber(membership.spent_amount || 0);
      const memberLimit = payload.amount + memberSpent;
      if (membership.member_limit && memberLimit > wealthNumber(membership.member_limit)) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_LIMIT_EXCEEDED' });
      }

      const result = await LogicCore.getTransactionPreview(session.sub, {
        sourceWalletId: payload.source_wallet_id,
        recipientId: payload.provider,
        amount: payload.amount,
        currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
        description: payload.description || `${budget.name} spend`,
        type: payload.type || 'EXTERNAL_PAYMENT',
        metadata: {
          ...(payload.metadata || {}),
          shared_budget_id: budget.id,
          shared_budget_name: budget.name,
          shared_budget_role: membership.role || 'SPENDER',
          bill_provider: payload.provider || null,
          bill_category: payload.bill_category || null,
          bill_reference: payload.reference || null,
          shared_budget_preview: true,
          spend_origin: 'SHARED_BUDGET',
          spend_type: payload.type || 'EXTERNAL_PAYMENT',
        },
        dryRun: true,
      });
      if (!result.success) return res.status(400).json(result);
      res.json({
        success: true,
        data: {
          preview: result,
          budget: {
            ...budget,
            remaining_amount: Math.max(0, budgetLimit - currentSpent - payload.amount),
          },
          member: {
            ...membership,
            remaining_member_limit: membership.member_limit
              ? Math.max(0, wealthNumber(membership.member_limit) - memberSpent - payload.amount)
              : null,
          },
        },
      });
    } catch (e: any) {
      const status = e.message === 'SHARED_BUDGET_SPEND_DENIED' ? 403 : 400;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budgets/:id/spend/settle', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetSpendSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canSpendFromSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_SPEND_DENIED' });
      }
      const currentSpent = wealthNumber(budget.spent_amount);
      const budgetLimit = wealthNumber(budget.budget_limit);
      if (currentSpent + payload.amount > budgetLimit) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_LIMIT_EXCEEDED' });
      }
      const memberSpent = wealthNumber(membership.spent_amount || 0);
      if (membership.member_limit && memberSpent + payload.amount > wealthNumber(membership.member_limit)) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_LIMIT_EXCEEDED' });
      }
      if (String(budget.approval_mode || 'AUTO').toUpperCase() === 'REVIEW') {
        const { data, error } = await sb
          .from('shared_budget_approvals')
          .insert({
            shared_budget_id: budget.id,
            requester_user_id: session.sub,
            amount: payload.amount,
            currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
            provider: payload.provider || null,
            bill_category: payload.bill_category || null,
            reference: payload.reference || null,
            note: payload.description || null,
            status: 'PENDING',
            metadata: {
              ...(payload.metadata || {}),
              source_wallet_id: payload.source_wallet_id || null,
              type: payload.type || 'EXTERNAL_PAYMENT',
              shared_budget_name: budget.name,
              requester_role: membership.role || 'SPENDER',
              spend_origin: 'SHARED_BUDGET',
              bill_provider: payload.provider || null,
              bill_category: payload.bill_category || null,
              bill_reference: payload.reference || null,
              preview_required: true,
            },
          })
          .select('*')
          .single();
        if (error) return res.status(400).json({ success: false, error: error.message });
        return res.json({ success: true, data: { approval: data, requires_approval: true } });
      }

      const data = await executeSharedBudgetSpend(sb, {
        budget,
        membership,
        actorUserId: session.sub,
        actorUser: session.user,
        payload,
      });
      res.json({ success: true, data });
    } catch (e: any) {
      const status = e.message === 'SHARED_BUDGET_SPEND_DENIED' ? 403 : 400;
      res.status(status).json({ success: false, error: e.message });
    }
  });
};
