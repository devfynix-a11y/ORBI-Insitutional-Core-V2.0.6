import { Request, Response } from 'express';
import { getSupabase } from '../supabaseClient.js';

export class SandboxController {
    /**
     * ACTIVATE USER (SANDBOX ONLY)
     * Sets the user's account status to 'active' to bypass ID-001.
     */
    static async activateUser(req: Request, res: Response) {
        const { userId } = req.body;
        if (!userId) return res.status(400).json({ success: false, error: 'MISSING_PARAMS: userId is required.' });

        const sb = getSupabase();
        if (!sb) return res.status(500).json({ error: 'DB_OFFLINE' });

        try {
            // Update Auth Metadata
            const { error: authError } = await sb.auth.admin.updateUserById(userId, {
                user_metadata: { account_status: 'active' }
            });

            if (authError) throw authError;

            // Update Public Table
            await sb.from('users').update({ account_status: 'active' }).eq('id', userId);

            res.json({ success: true, message: `User ${userId} activated for sandbox testing.` });
        } catch (e: any) {
            res.status(500).json({ success: false, error: e.message });
        }
    }
}
