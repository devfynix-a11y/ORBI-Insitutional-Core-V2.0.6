import { type RequestHandler, type Router } from 'express';
import { GoogleGenAI, Type } from '@google/genai';
import { OrbiKnowledge } from '../../constants/orbiKnowledge.js';

type Deps = {
  authenticate: RequestHandler;
  upload: any;
  LogicCore: any;
  getAdminSupabase: () => any;
};

async function callGeminiWithRetry(ai: GoogleGenAI, params: any, retries = 3, delay = 1000): Promise<any> {
  try {
    return await ai.models.generateContent(params);
  } catch (e: any) {
    if (retries > 0 && e.status === 503) {
      console.warn(`[Gemini] 503 error, retrying in ${delay}ms... (${retries} retries left)`);
      await new Promise((resolve) => setTimeout(resolve, delay));
      return callGeminiWithRetry(ai, params, retries - 1, delay * 2);
    }
    throw e;
  }
}

function getFirstUploadedFile(req: any) {
  const files = Array.isArray(req.files) ? req.files : [];
  return req.file || files[0] || null;
}

export const registerEngagementRoutes = (v1: Router, deps: Deps) => {
  const { authenticate, upload, LogicCore, getAdminSupabase } = deps;

  v1.post('/chat', authenticate as any, upload.any(), async (req, res) => {
    const { message } = req.body;
    const session = (req as any).session;
    const userId = session.sub;

    if (!message) return res.status(400).json({ success: false, error: 'Message required' });

    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) throw new Error('GEMINI_API_KEY_MISSING');
      const ai = new GoogleGenAI({ apiKey });

      const sb = getAdminSupabase();
      const { data: user } = await sb!.from('users').select('full_name, email, account_status').eq('id', userId).single();
      const { data: recentActivity } = await sb!
        .from('transactions')
        .select('amount, description, created_at')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(1);

      const context = { user, recentActivity };

      let prompt = `User context: ${JSON.stringify(context)}. User message: ${message}`;
      if (message === 'init') {
        const hour = new Date().getHours();
        const timeOfDay = hour < 12 ? 'morning' : hour < 18 ? 'afternoon' : 'evening';

        prompt = `User context: ${JSON.stringify(context)}. 
            Current time of day: ${timeOfDay}.
            Please provide a warm, professional welcome greeting to the user, ${user?.full_name || 'valued customer'}.
            Use the time of day (${timeOfDay}) in the greeting.
            Mention one of their recent activities from the context if available, or if their account status is not 'active', mention an account issue.
            Ask them how you can help them with Orbi services (payments, savings, corporate).`;
      }

      const systemInstruction = `
            You are the Orbi AI Agent. 
            
            KNOWLEDGE BASE:
            ${JSON.stringify(OrbiKnowledge, null, 2)}
            
            INSTRUCTIONS:
            1. Always use the provided KNOWLEDGE BASE to answer questions about Orbi.
            2. If a user asks about something not in the knowledge base, politely state that you don't have that information.
            3. Use a professional, helpful, and secure tone.
            4. Avoid technical jargon (e.g., 'ledger', 'settlement'); use user-friendly terms (e.g., 'payment', 'account').
            5. If the user provides a document, analyze it specifically for issues related to the Orbi Platform using the KNOWLEDGE BASE.
            6. CRITICAL: Do NOT use the word 'Fynix' or 'fynix'. Always use 'Orbi'.
        `;

      const contents: any = { parts: [{ text: prompt }] };
      const uploadedFile = getFirstUploadedFile(req);
      if (uploadedFile) {
        contents.parts.push({
          inlineData: {
            mimeType: uploadedFile.mimetype,
            data: uploadedFile.buffer.toString('base64'),
          },
        });
      }

      const response = await callGeminiWithRetry(ai, {
        model: uploadedFile ? 'gemini-2.5-flash' : 'gemini-2.5-flash',
        contents,
        config: { systemInstruction },
      });

      if (!response.text) {
        throw new Error('No response text from Gemini');
      }

      res.json({ success: true, data: response.text });
    } catch (e: any) {
      console.error('[Chat] Error:', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/insights', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const userId = session.sub;

    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) throw new Error('GEMINI_API_KEY_MISSING');
      const ai = new GoogleGenAI({ apiKey });

      const sb = getAdminSupabase();
      const { data: transactions } = await sb!
        .from('transactions')
        .select('amount, description, created_at, category')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(20);

      const { data: goals } = await sb!
        .from('goals')
        .select('name, target_amount, current_amount, funding_strategy, auto_allocation_enabled, linked_income_percentage, monthly_target')
        .eq('user_id', userId);

      const { data: categories } = await sb!
        .from('categories')
        .select('name, budget, spent_amount, hard_limit, period')
        .eq('user_id', userId);

      const allocatedToGoals = (goals || []).reduce((sum: number, g: any) => sum + Number(g.current_amount || 0), 0);
      const allocatedToBudgets = (categories || []).reduce((sum: number, c: any) => sum + Number(c.budget || 0), 0);
      const recentSpend = (transactions || []).reduce((sum: number, t: any) => sum + Number(t.amount || 0), 0);

      const context = {
        transactions,
        goals,
        categories,
        moneyState: {
          allocatedToGoals,
          allocatedToBudgets,
          totalAllocated: allocatedToGoals + allocatedToBudgets,
          recentObservedSpend: recentSpend,
        },
      };

      const systemInstruction = `
            You are the Orbi Financial Advisor. 
            Analyze the provided transaction history, savings goals, budget allocations, and money-state summary to provide personalized financial advice.
            
            Return the response in the following JSON format:
            {
                "spendingAlerts": ["string"],
                "budgetSuggestions": ["string"],
                "financialAdvice": ["string"]
            }
            
            GUIDELINES:
            - Base all advice ONLY on the provided user activity (transactions, goals, categories, and moneyState).
            - Focus on spending habits, savings progress, budget pressure, allocation discipline, and helpful next steps.
            - Explicitly reason about where money currently sits: available, budgeted, saved, locked, or spent.
            - Prefer concrete behavioral observations over generic advice.
            - Mention weak liquidity, overspending pressure, or over-concentration in allocations when the data supports it.
            - Use a professional, helpful, and secure tone.
            - Avoid technical jargon; use user-friendly terms.
            - CRITICAL: Do NOT use the word 'Fynix' or 'fynix'. Always use 'Orbi'.
        `;

      const response = await callGeminiWithRetry(ai, {
        model: 'gemini-2.5-flash',
        contents: `Analyze this financial data: ${JSON.stringify(context)}`,
        config: {
          systemInstruction,
          responseMimeType: 'application/json',
        },
      });

      let insights;
      try {
        insights = JSON.parse(response.text || '{}');
      } catch (e) {
        console.error('[Insights] JSON Parse Error:', e, 'Response:', response.text);
        insights = { spendingAlerts: [], budgetSuggestions: [], financialAdvice: ['Unable to generate insights at this time.'] };
      }
      res.json({ success: true, data: insights });
    } catch (e: any) {
      console.error('[Insights] Error:', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/receipt/scan', authenticate as any, upload.any(), async (req, res) => {
    const uploadedFile = getFirstUploadedFile(req);
    if (!uploadedFile) {
      return res.status(400).json({ success: false, error: 'No receipt image provided' });
    }

    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) throw new Error('GEMINI_API_KEY_MISSING');
      const ai = new GoogleGenAI({ apiKey });

      const imagePart = {
        inlineData: {
          mimeType: uploadedFile.mimetype,
          data: uploadedFile.buffer.toString('base64'),
        },
      };

      const response = await callGeminiWithRetry(ai, {
        model: 'gemini-2.5-flash',
        contents: { parts: [imagePart, { text: 'Extract the merchant name, total amount, currency, and date from this receipt.' }] },
        config: {
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              merchant: { type: Type.STRING },
              amount: { type: Type.NUMBER },
              currency: { type: Type.STRING },
              date: { type: Type.STRING },
            },
            required: ['merchant', 'amount', 'currency', 'date'],
          },
        },
      });

      const receiptData = JSON.parse(response.text || '{}');
      res.json({ success: true, data: receiptData });
    } catch (e: any) {
      console.error('[ReceiptScan] Error:', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/notifications', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);
    try {
      const result = await LogicCore.getUserMessages(session.sub, limit, offset);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/notifications/:id/read', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      await LogicCore.markMessageRead(session.sub, req.params.id);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/notifications/read-all', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      await LogicCore.markAllMessagesRead(session.sub);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.delete('/notifications/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      await LogicCore.deleteMessage(session.sub, req.params.id);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
};
