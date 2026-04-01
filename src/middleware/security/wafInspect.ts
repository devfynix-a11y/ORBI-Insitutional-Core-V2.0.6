import { NextFunction, Request, Response } from 'express';
import { WAF } from '../../../backend/security/waf.js';

export const wafInspect = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (req.body && Object.keys(req.body).length > 0) {
      await WAF.inspect(req.body, req.ip);
    }
    next();
  } catch (err: any) {
    res.status(403).json({ success: false, error: 'WAF_REJECTION', message: err.message });
  }
};
