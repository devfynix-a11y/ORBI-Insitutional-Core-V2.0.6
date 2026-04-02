import { logger } from '../../backend/infrastructure/logger.js';
import type { Server as HttpServer } from 'http';

export const bootstrapHttp = async ({
  httpServer,
  port,
  onShutdown,
}: {
  httpServer: HttpServer;
  port: number;
  onShutdown?: () => Promise<void>;
}) => {
  await new Promise<void>((resolve) => {
    httpServer.listen(port, '0.0.0.0', () => {
      logger.info('http.server_started', { port });
      resolve();
    });
  });

  const gracefulShutdown = async () => {
    logger.warn('http.shutdown_signal_received');

    if (onShutdown) {
      await onShutdown();
    }

    await new Promise<void>((resolve) => {
      httpServer.close(() => {
        logger.info('http.server_stopped');
        resolve();
      });
    });

    process.exit(0);
  };

  process.on('SIGTERM', gracefulShutdown);
  process.on('SIGINT', gracefulShutdown);
};
