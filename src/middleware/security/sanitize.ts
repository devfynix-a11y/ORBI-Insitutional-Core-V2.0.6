import { NextFunction, Request, Response } from 'express';
import { SanitizerService } from '../../../backend/security/sanitizer.js';

export const sanitizeContent = (req: Request, _res: Response, next: NextFunction) => {
  if (req.body && Object.keys(req.body).length > 0) {
    req.body = SanitizerService.sanitize(req.body);
  }
  next();
};
