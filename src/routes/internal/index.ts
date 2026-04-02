import type { Express, NextFunction, Request, Response, Router } from 'express';
import { getAdminSupabase, getSupabase } from '../../../backend/supabaseClient.js';
import { BankingEngineService } from '../../../backend/ledger/transactionEngine.js';
import { Audit } from '../../../backend/security/audit.js';
import { Server as LogicCore } from '../../../backend/server.js';
import {
  createInternalWorkerMiddleware,
  getInternalAuditMetadata,
  workerHasRequiredScopes,
} from '../../middleware/auth/authorization.js';

const requireWorkerScope = (requiredScopes: string[]) =>
  (req: Request, res: Response, next: NextFunction) => {
    const worker = (req as any).internalWorker || null;
    if (!workerHasRequiredScopes(worker, requiredScopes)) {
      return res.status(403).json({
        success: false,
        error: 'WORKER_SCOPE_REQUIRED',
        message: `Missing required worker scope: ${requiredScopes.join(', ')}`,
      });
    }
    return next();
  };

export const registerInternalRoutes = (internal: Router) => {
  internal.use(createInternalWorkerMiddleware());

  internal.post('/transactions/claim', requireWorkerScope(['transactions:claim']), async (req, res) => {
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

  internal.put('/transactions/:id/resolve', requireWorkerScope(['transactions:resolve']), async (req, res) => {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const { status } = req.body;
    const workerId = String((req as any).internalWorker?.id || req.get('x-worker-id') || `internal-route:${id}`);

    try {
      const engine = new BankingEngineService();
      if (status === 'completed') {
        const success = await engine.completeSettlement(id, undefined, workerId);
        res.json({ success });
      } else {
        const sb = getAdminSupabase() || getSupabase();
        const { error } = await sb!.from('transactions').update({ status: 'failed' }).eq('id', id);
        res.json({ success: !error });
      }
    } catch (e: any) {
      const message = String(e?.message || e || '');
      const statusCode = message.includes('CONCURRENCY_CONFLICT')
        ? 409
        : message.includes('INVALID_SETTLEMENT_STATE')
          ? 409
          : 500;
      res.status(statusCode).json({ success: false, error: message });
    }
  });

  internal.get('/transactions/reversible', requireWorkerScope(['transactions:read']), async (_req, res) => {
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

  internal.post('/transactions/:id/reverse', requireWorkerScope(['transactions:reverse']), async (req, res) => {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
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

      await Audit.log('FINANCIAL', tx.user_id, 'TRANSACTION_REVERSED', {
        txId: id,
        reason,
        ...getInternalAuditMetadata(req),
      });
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.get('/transactions/recent', requireWorkerScope(['transactions:read']), async (req, res) => {
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

  internal.post('/security/anomalies', requireWorkerScope(['security:anomalies:write']), async (req, res) => {
    const { transactionId, severity, description } = req.body;
    try {
      const sb = getAdminSupabase() || getSupabase();
      const { data: tx } = await sb!.from('transactions').select('*').eq('id', transactionId).single();

      await Audit.log('FRAUD', tx?.user_id || 'SYSTEM', 'WORKER_ANOMALY_REPORTED', {
        transactionId,
        severity,
        description,
        ...getInternalAuditMetadata(req),
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

  internal.get('/tasks/pending', requireWorkerScope(['tasks:read']), async (_req, res) => {
    const sb = getAdminSupabase() || getSupabase();
    try {
      const { data, error } = await sb!.from('tasks').select('*').eq('status', 'pending');
      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.put('/tasks/:id/status', requireWorkerScope(['tasks:write']), async (req, res) => {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
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

  internal.get('/messages/queued', requireWorkerScope(['messages:read']), async (_req, res) => {
    const sb = getAdminSupabase() || getSupabase();
    try {
      const { data, error } = await sb!.from('user_messages').select('*').eq('status', 'queued');
      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.post('/offline/requests', requireWorkerScope(['offline:requests:write']), async (req, res) => {
    try {
      const result = await LogicCore.processOfflineGatewayRequest(req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  internal.post('/offline/confirmations', requireWorkerScope(['offline:confirmations:write']), async (req, res) => {
    try {
      const result = await LogicCore.processOfflineGatewayConfirmation(req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  internal.put('/messages/:id/status', requireWorkerScope(['messages:write']), async (req, res) => {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
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

  internal.post('/email/test', requireWorkerScope(['email:test']), async (_req, res) => {
    res.status(403).json({ success: false, error: 'EMAIL_SERVICE_DISABLED' });
  });

  internal.get('/email/verify', requireWorkerScope(['email:verify']), async (_req, res) => {
    res.status(403).json({ success: false, error: 'EMAIL_SERVICE_DISABLED' });
  });
};

export const mountInternalRoutes = (app: Express, internal: Router) => {
  app.use('/api/internal', internal);
};
