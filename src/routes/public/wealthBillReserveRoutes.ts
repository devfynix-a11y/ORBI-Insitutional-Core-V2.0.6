import { type RequestHandler, type Router } from 'express';

type Deps = {
  authenticate: RequestHandler;
  getSupabase: () => any;
  getAdminSupabase: () => any;
  BillReserveCreateSchema: any;
  BillReserveUpdateSchema: any;
  wealthNumber: (value: any) => number;
  resolveWealthSourceWallet: (sb: any, userId: string, sourceWalletId?: string) => Promise<any>;
  assertBillPaymentSourceAllowed: (sourceRecord: any) => void;
  createWealthTransaction: (...args: any[]) => Promise<any>;
  updateWealthSourceBalance: (...args: any[]) => Promise<any>;
  insertBillReserveLedger: (...args: any[]) => Promise<any>;
};

export const registerBillReserveRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    getSupabase,
    getAdminSupabase,
    BillReserveCreateSchema,
    BillReserveUpdateSchema,
    wealthNumber,
    resolveWealthSourceWallet,
    assertBillPaymentSourceAllowed,
    createWealthTransaction,
    updateWealthSourceBalance,
    insertBillReserveLedger,
  } = deps;

  v1.get('/wealth/bill-reserves', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb
        .from('bill_reserves')
        .select('*')
        .eq('user_id', session.sub)
        .order('created_at', { ascending: false });
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data: { reserves: data || [] } });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/bill-reserves', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = BillReserveCreateSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const currency = payload.currency?.toUpperCase() || 'TZS';
      const isFixedReserve = (payload.reserve_mode || 'FIXED') === 'FIXED';
      const lockedBalance = isFixedReserve ? payload.reserve_amount : 0;

      let sourceRecord: any = null;
      let sourceTable: 'platform_vaults' | 'wallets' = 'platform_vaults';
      let sourceBalanceAfter: number | null = null;

      if (lockedBalance > 0) {
        const resolved = await resolveWealthSourceWallet(
          sb,
          session.sub,
          payload.source_wallet_id,
        );
        sourceRecord = resolved.sourceRecord;
        sourceTable = resolved.sourceTable;
        assertBillPaymentSourceAllowed(sourceRecord);
        const currentBalance = wealthNumber(sourceRecord.balance);
        if (currentBalance < lockedBalance) {
          return res.status(400).json({ success: false, error: 'INSUFFICIENT_FUNDS' });
        }
        sourceBalanceAfter = currentBalance - lockedBalance;
      }

      const insertPayload = {
        user_id: session.sub,
        provider_name: payload.provider_name,
        bill_type: payload.bill_type,
        source_wallet_id: sourceRecord?.id || payload.source_wallet_id,
        currency,
        due_pattern: payload.due_pattern || 'MONTHLY',
        due_day: payload.due_day,
        reserve_mode: payload.reserve_mode || 'FIXED',
        reserve_amount: payload.reserve_amount,
        locked_balance: lockedBalance,
        is_active: true,
        metadata: {
          created_from: 'mobile_app',
          source_table: sourceRecord ? sourceTable : null,
        },
      };
      const { data, error } = await sb
        .from('bill_reserves')
        .insert(insertPayload)
        .select('*')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });

      let transaction: any = null;
      if (lockedBalance > 0 && sourceRecord && sourceBalanceAfter != null) {
        transaction = await createWealthTransaction(
          sb,
          session.sub,
          sourceRecord,
          lockedBalance,
          currency,
          `Bill reserve funding: ${payload.provider_name}`,
          'PLANNED',
          {
            bill_reserve_id: data.id,
            source_table: sourceTable,
            source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
            allocation_source: 'BILL_RESERVE_CREATE',
          },
        );
        await updateWealthSourceBalance(
          sb,
          sourceTable,
          sourceRecord,
          session.sub,
          sourceBalanceAfter,
        );
        await insertBillReserveLedger(sb, {
          transactionId: transaction.id,
          userId: session.sub,
          sourceRecord,
          reserveId: data.id,
          amount: lockedBalance,
          sourceBalanceAfter,
          reserveBalanceAfter: lockedBalance,
          action: 'LOCK',
        });
      }
      res.json({
        success: true,
        data: {
          ...data,
          source_balance: sourceBalanceAfter,
          transaction,
        },
      });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.patch('/wealth/bill-reserves/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = BillReserveUpdateSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data: existingReserve, error: reserveError } = await sb
        .from('bill_reserves')
        .select('*')
        .eq('id', req.params.id)
        .eq('user_id', session.sub)
        .single();
      if (reserveError || !existingReserve) {
        return res.status(404).json({ success: false, error: 'BILL_RESERVE_NOT_FOUND' });
      }

      const nextReserveMode = payload.reserve_mode ?? existingReserve.reserve_mode ?? 'FIXED';
      const nextReserveAmount = payload.reserve_amount ?? wealthNumber(existingReserve.reserve_amount);
      const nextStatus = payload.status ?? String(existingReserve.status || 'ACTIVE').toUpperCase();
      const nextIsActive = payload.is_active ?? (existingReserve.is_active !== false);
      const shouldLockFunds =
        nextIsActive &&
        String(nextStatus).toUpperCase() === 'ACTIVE' &&
        String(nextReserveMode).toUpperCase() === 'FIXED';

      const currentLockedBalance = wealthNumber(existingReserve.locked_balance || 0);
      const desiredLockedBalance = shouldLockFunds ? wealthNumber(nextReserveAmount) : 0;
      const delta = desiredLockedBalance - currentLockedBalance;

      const updatePayload: any = {
        updated_at: new Date().toISOString(),
      };
      if (payload.provider_name !== undefined) updatePayload.provider_name = payload.provider_name;
      if (payload.bill_type !== undefined) updatePayload.bill_type = payload.bill_type;
      if (payload.source_wallet_id !== undefined) updatePayload.source_wallet_id = payload.source_wallet_id;
      if (payload.currency !== undefined) updatePayload.currency = payload.currency.toUpperCase();
      if (payload.due_pattern !== undefined) updatePayload.due_pattern = payload.due_pattern;
      if (payload.due_day !== undefined) updatePayload.due_day = payload.due_day;
      if (payload.reserve_mode !== undefined) updatePayload.reserve_mode = payload.reserve_mode;
      if (payload.reserve_amount !== undefined) updatePayload.reserve_amount = payload.reserve_amount;
      if (payload.is_active !== undefined) updatePayload.is_active = payload.is_active;
      if (payload.status !== undefined) updatePayload.status = payload.status;
      updatePayload.locked_balance = desiredLockedBalance;

      let sourceRecord: any = null;
      let sourceTable: 'platform_vaults' | 'wallets' = 'platform_vaults';
      let sourceBalanceAfter: number | null = null;
      let adjustmentAction: 'LOCK' | 'RELEASE' | null = null;

      if (delta !== 0) {
        const resolved = await resolveWealthSourceWallet(
          sb,
          session.sub,
          (payload.source_wallet_id ?? existingReserve.source_wallet_id ?? '').toString() || undefined,
        );
        sourceRecord = resolved.sourceRecord;
        sourceTable = resolved.sourceTable;
        assertBillPaymentSourceAllowed(sourceRecord);
        const currentBalance = wealthNumber(sourceRecord.balance);
        if (delta > 0) {
          if (currentBalance < delta) {
            return res.status(400).json({ success: false, error: 'INSUFFICIENT_FUNDS' });
          }
          sourceBalanceAfter = currentBalance - delta;
          adjustmentAction = 'LOCK';
        } else {
          sourceBalanceAfter = currentBalance + Math.abs(delta);
          adjustmentAction = 'RELEASE';
        }
        updatePayload.source_wallet_id = sourceRecord.id;
      }

      const { data, error } = await sb
        .from('bill_reserves')
        .update(updatePayload)
        .eq('id', req.params.id)
        .eq('user_id', session.sub)
        .select('*')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });

      let transaction: any = null;
      if (delta !== 0 && sourceRecord && sourceBalanceAfter != null && adjustmentAction) {
        const adjustmentAmount = Math.abs(delta);
        transaction = await createWealthTransaction(
          sb,
          session.sub,
          sourceRecord,
          adjustmentAmount,
          String(data.currency || sourceRecord.currency || 'TZS').toUpperCase(),
          adjustmentAction === 'LOCK'
            ? `Bill reserve top-up: ${data.provider_name}`
            : `Bill reserve release: ${data.provider_name}`,
          'PLANNED',
          {
            bill_reserve_id: data.id,
            source_table: sourceTable,
            source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
            allocation_source: adjustmentAction === 'LOCK'
              ? 'BILL_RESERVE_TOP_UP'
              : 'BILL_RESERVE_RELEASE',
          },
        );
        await updateWealthSourceBalance(
          sb,
          sourceTable,
          sourceRecord,
          session.sub,
          sourceBalanceAfter,
        );
        await insertBillReserveLedger(sb, {
          transactionId: transaction.id,
          userId: session.sub,
          sourceRecord,
          reserveId: data.id,
          amount: adjustmentAmount,
          sourceBalanceAfter,
          reserveBalanceAfter: desiredLockedBalance,
          action: adjustmentAction,
        });
      }
      res.json({
        success: true,
        data: {
          ...data,
          source_balance: sourceBalanceAfter,
          transaction,
        },
      });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.delete('/wealth/bill-reserves/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const { data: reserve, error: reserveError } = await sb
        .from('bill_reserves')
        .select('*')
        .eq('id', req.params.id)
        .eq('user_id', session.sub)
        .single();
      if (reserveError || !reserve) {
        return res.status(404).json({ success: false, error: 'BILL_RESERVE_NOT_FOUND' });
      }

      const lockedBalance = wealthNumber(reserve.locked_balance || 0);
      let sourceBalanceAfter: number | null = null;
      let transaction: any = null;

      if (lockedBalance > 0) {
        const resolved = await resolveWealthSourceWallet(
          sb,
          session.sub,
          String(reserve.source_wallet_id || '').trim() || undefined,
        );
        const sourceRecord = resolved.sourceRecord;
        const sourceTable = resolved.sourceTable;
        const currentBalance = wealthNumber(sourceRecord.balance);
        sourceBalanceAfter = currentBalance + lockedBalance;

        transaction = await createWealthTransaction(
          sb,
          session.sub,
          sourceRecord,
          lockedBalance,
          String(reserve.currency || sourceRecord.currency || 'TZS').toUpperCase(),
          `Bill reserve delete release: ${reserve.provider_name || reserve.bill_type || 'Reserve'}`,
          'PLANNED',
          {
            bill_reserve_id: reserve.id,
            source_table: sourceTable,
            source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
            allocation_source: 'BILL_RESERVE_DELETE_RELEASE',
          },
        );

        await updateWealthSourceBalance(
          sb,
          sourceTable,
          sourceRecord,
          session.sub,
          sourceBalanceAfter,
        );

        await insertBillReserveLedger(sb, {
          transactionId: transaction.id,
          userId: session.sub,
          sourceRecord,
          reserveId: reserve.id,
          amount: lockedBalance,
          sourceBalanceAfter,
          reserveBalanceAfter: 0,
          action: 'RELEASE',
        });
      }

      const { error: deleteError } = await sb
        .from('bill_reserves')
        .delete()
        .eq('id', reserve.id)
        .eq('user_id', session.sub);
      if (deleteError) {
        return res.status(400).json({ success: false, error: deleteError.message });
      }

      res.json({
        success: true,
        data: {
          deleted: true,
          released_amount: lockedBalance,
          source_balance: sourceBalanceAfter,
          transaction,
        },
      });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });
};
