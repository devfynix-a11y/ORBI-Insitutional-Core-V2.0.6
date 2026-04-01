import { type RequestHandler, type Router } from 'express';

type Deps = {
  authenticate: RequestHandler;
  getSupabase: () => any;
  getAdminSupabase: () => any;
  AllocationRuleCreateSchema: any;
  AllocationRuleUpdateSchema: any;
};

export const registerAllocationRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    getSupabase,
    getAdminSupabase,
    AllocationRuleCreateSchema,
    AllocationRuleUpdateSchema,
  } = deps;

  v1.get('/wealth/allocation-rules', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb
        .from('allocation_rules')
        .select('*')
        .eq('user_id', session.sub)
        .order('priority', { ascending: true })
        .order('created_at', { ascending: false });
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data: { rules: data || [] } });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/allocation-rules', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = AllocationRuleCreateSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb
        .from('allocation_rules')
        .insert({
          user_id: session.sub,
          name: payload.name,
          trigger_type: payload.trigger_type,
          source_wallet_id: payload.source_wallet_id,
          target_type: payload.target_type,
          target_id: payload.target_id,
          mode: payload.mode,
          fixed_amount: payload.fixed_amount,
          percentage: payload.percentage,
          priority: payload.priority || 1,
          is_active: true,
          metadata: { created_from: 'mobile_app' },
        })
        .select('*')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.patch('/wealth/allocation-rules/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = AllocationRuleUpdateSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const updatePayload: any = {
        updated_at: new Date().toISOString(),
      };
      if (payload.name !== undefined) updatePayload.name = payload.name;
      if (payload.trigger_type !== undefined) updatePayload.trigger_type = payload.trigger_type;
      if (payload.source_wallet_id !== undefined) updatePayload.source_wallet_id = payload.source_wallet_id;
      if (payload.target_type !== undefined) updatePayload.target_type = payload.target_type;
      if (payload.target_id !== undefined) updatePayload.target_id = payload.target_id;
      if (payload.mode !== undefined) updatePayload.mode = payload.mode;
      if (payload.fixed_amount !== undefined) updatePayload.fixed_amount = payload.fixed_amount;
      if (payload.percentage !== undefined) updatePayload.percentage = payload.percentage;
      if (payload.priority !== undefined) updatePayload.priority = payload.priority;
      if (payload.is_active !== undefined) updatePayload.is_active = payload.is_active;
      const { data, error } = await sb
        .from('allocation_rules')
        .update(updatePayload)
        .eq('id', req.params.id)
        .eq('user_id', session.sub)
        .select('*')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });
};
