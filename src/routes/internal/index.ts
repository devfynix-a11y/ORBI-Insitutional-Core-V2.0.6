import type { Express, NextFunction, Request, Response, Router } from 'express';
import { getAdminSupabase, getSupabase } from '../../../backend/supabaseClient.js';
import { BankingEngineService } from '../../../backend/ledger/transactionEngine.js';
import { Audit } from '../../../backend/security/audit.js';
import { Server as LogicCore } from '../../../backend/server.js';

export const registerInternalRoutes = (internal: Router) => {
  const workerAuth = (req: Request, res: Response, next: NextFunction) => {
    const secret = req.headers['x-worker-secret'];
    const expected = process.env.WORKER_SECRET;

    if (secret && expected && secret === expected) {
      next();
    } else {
      console.warn(`[Internal] Unauthorized worker access attempt from ${req.ip}`);
      res.status(401).json({ success: false, error: 'UNAUTHORIZED_WORKER' });
    }
  };

  internal.use(workerAuth);

  internal.post('/transactions/claim', async (req, res) => {
    const limit = req.body.limit || 100;
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) return res.status(500).json({ success: false, error: 'DB_OFFLINE' });

    try {
      const { data, error } = await sb
        .from('transactions')
        .update({ status: 'processing', updated_at: new Date().toISOString() })
        .eq('status', 'pending')
        .order('created_at', { ascending: true })
        .limit(limit)
        .select();

      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.put('/transactions/:id/resolve', async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    try {
      const engine = new BankingEngineService();
      if (status === 'completed') {
        const success = await engine.completeSettlement(id);
        res.json({ success });
      } else {
        const sb = getAdminSupabase() || getSupabase();
        const { error } = await sb!.from('transactions').update({ status: 'failed' }).eq('id', id);
        res.json({ success: !error });
      }
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.get('/transactions/reversible', async (_req, res) => {
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) return res.status(500).json({ success: false, error: 'DB_OFFLINE' });

    const fifteenMinsAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();

    try {
      const { data, error } = await sb
        .from('transactions')
        .select('*')
        .or(`status.eq.failed,and(status.eq.processing,updated_at.lt.${fifteenMinsAgo})`);

      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.post('/transactions/:id/reverse', async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;

    try {
      const sb = getAdminSupabase() || getSupabase();
      const { data: tx } = await sb!.from('transactions').select('*').eq('id', id).single();
      if (!tx) return res.status(404).json({ success: false, error: 'NOT_FOUND' });

      const { error } = await sb!
        .from('transactions')
        .update({
          status: 'reversed',
          metadata: { ...tx.metadata, reversal_reason: reason, reversed_at: new Date().toISOString() },
        })
        .eq('id', id);

      if (error) throw error;

      await Audit.log('FINANCIAL', tx.user_id, 'TRANSACTION_REVERSED', { txId: id, reason });
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.get('/transactions/recent', async (req, res) => {
    const minutes = parseInt(req.query.minutes as string) || 5;
    const sb = getAdminSupabase() || getSupabase();
    const startTime = new Date(Date.now() - minutes * 60 * 1000).toISOString();

    try {
      const { data, error } = await sb!.from('transactions').select('*').gte('created_at', startTime);
      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.post('/security/anomalies', async (req, res) => {
    const { transactionId, severity, description } = req.body;
    try {
      const sb = getAdminSupabase() || getSupabase();
      const { data: tx } = await sb!.from('transactions').select('*').eq('id', transactionId).single();

      await Audit.log('FRAUD', tx?.user_id || 'SYSTEM', 'WORKER_ANOMALY_REPORTED', {
        transactionId,
        severity,
        description,
      });

      if (sb) {
        await sb.from('provider_anomalies').insert({
          transaction_id: transactionId,
          risk_score: severity === 'high' ? 90 : 50,
          detection_flags: ['WORKER_REPORTED'],
          status: 'OPEN',
          metadata: { description },
        });
      }
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.get('/tasks/pending', async (_req, res) => {
    const sb = getAdminSupabase() || getSupabase();
    try {
      const { data, error } = await sb!.from('tasks').select('*').eq('status', 'pending');
      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.put('/tasks/:id/status', async (req, res) => {
    const { id } = req.params;
    const { status, result } = req.body;
    try {
      const sb = getAdminSupabase() || getSupabase();
      const { error } = await sb!
        .from('tasks')
        .update({
          status,
          metadata: result ? { result } : undefined,
          updated_at: new Date().toISOString(),
        })
        .eq('id', id);
      if (error) throw error;
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.get('/messages/queued', async (_req, res) => {
    const sb = getAdminSupabase() || getSupabase();
    try {
      const { data, error } = await sb!.from('user_messages').select('*').eq('status', 'queued');
      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.post('/offline/requests', async (req, res) => {
    try {
      const result = await LogicCore.processOfflineGatewayRequest(req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  internal.post('/offline/confirmations', async (req, res) => {
    try {
      const result = await LogicCore.processOfflineGatewayConfirmation(req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  internal.put('/messages/:id/status', async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    try {
      const sb = getAdminSupabase() || getSupabase();
      const { error } = await sb!
        .from('user_messages')
        .update({
          status,
          sent_at: status === 'sent' ? new Date().toISOString() : undefined,
        })
        .eq('id', id);
      if (error) throw error;
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.post('/email/test', async (_req, res) => {
    res.status(403).json({ success: false, error: 'EMAIL_SERVICE_DISABLED' });
  });

  internal.get('/email/verify', async (_req, res) => {
    res.status(403).json({ success: false, error: 'EMAIL_SERVICE_DISABLED' });
  });
};

export const mountInternalRoutes = (app: Express, internal: Router) => {
  app.use('/api/internal', internal);
};
