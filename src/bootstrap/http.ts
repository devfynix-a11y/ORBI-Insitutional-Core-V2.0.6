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
      console.info(`ORBI SOVEREIGN NODE v28.0 - RESTFUL API ACTIVE ON PORT ${port}`);
      resolve();
    });
  });

  const gracefulShutdown = async () => {
    console.info('\n[System] SIGTERM/SIGINT received. Initiating graceful shutdown...');

    if (onShutdown) {
      await onShutdown();
    }

    await new Promise<void>((resolve) => {
      httpServer.close(() => {
        console.info('[System] HTTP server closed. All connections drained.');
        resolve();
      });
    });

    process.exit(0);
  };

  process.on('SIGTERM', gracefulShutdown);
  process.on('SIGINT', gracefulShutdown);
};
