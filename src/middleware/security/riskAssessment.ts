import { NextFunction, Request, Response } from 'express';
import { RiskEngine } from '../../../backend/security/RiskEngine.js';

export const riskAssessment = async (req: Request, res: Response, next: NextFunction) => {
  if (req.path === '/health' || req.path.startsWith('/public')) return next();

  try {
    const context = {
      userId: (req as any).user?.sub,
      ip: req.ip || '0.0.0.0',
      appId: ((req.headers['x-orbi-app-id'] as string) || 'anonymous-node'),
    };

    const risk = await RiskEngine.evaluateRequest(req, context);

    if (risk.action === 'BLOCK') {
      return res.status(403).json({
        success: false,
        error: 'SECURITY_BLOCK',
        message: 'Request blocked by Risk Engine',
        score: risk.score,
      });
    }

    (req as any).risk = risk;
    next();
  } catch (err: any) {
    console.error('[RiskEngine] Evaluation Fault:', err.message);
    next();
  }
};
