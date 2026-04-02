import { Request, Response, NextFunction } from 'express';
import { UUID } from '../../services/utils.js';
import { buildRequestLogContext, logger, withLogContext } from '../infrastructure/logger.js';

export const tracingMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const traceId = String(req.headers['x-trace-id'] || req.headers['x-request-id'] || UUID.generate());
    const correlationId = String(req.headers['x-correlation-id'] || req.headers['x-request-id'] || traceId);

    (req as any).traceId = traceId;
    (req as any).correlationId = correlationId;

    res.setHeader('X-Trace-Id', traceId);
    res.setHeader('X-Correlation-Id', correlationId);

    withLogContext(buildRequestLogContext(req, { correlation_id: correlationId }), () => {
        logger.debug('http.request_context_initialized', { trace_id: traceId, correlation_id: correlationId });
        next();
    });
};
