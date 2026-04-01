import { NextFunction, Request, Response } from 'express';
import { z } from 'zod';

export const validate = (schema: z.ZodSchema) =>
  (req: Request, res: Response, next: NextFunction) => {
    try {
      schema.parse(req.body);
      next();
    } catch (err: any) {
      res.status(400).json({
        success: false,
        error: 'VALIDATION_FAILED',
        details: err.errors?.map((e: any) => ({ path: e.path, message: e.message })) || [],
      });
    }
  };
