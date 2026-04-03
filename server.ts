import { httpServer, PORT, ALLOWED_ORIGINS, gatewayBackgroundJobsEnabled } from './src/app/createApp.js';
import { bootstrapRealtime } from './src/bootstrap/realtime.js';
import { bootstrapJobs } from './src/bootstrap/jobs.js';
import { bootstrapHttp } from './src/bootstrap/http.js';
import { logger } from './backend/infrastructure/logger.js';

const realtime = bootstrapRealtime({ httpServer, allowedOrigins: ALLOWED_ORIGINS });
let jobsController: { stop: () => Promise<void> } = {
  stop: async () => {},
};

await bootstrapHttp({ httpServer, port: PORT, onShutdown: async () => {
  await jobsController.stop();
  await realtime.stop();
} });

void bootstrapJobs({ gatewayBackgroundJobsEnabled })
  .then((jobs) => {
    jobsController = jobs;
    logger.info('jobs.bootstrap_completed');
  })
  .catch((error) => {
    logger.error('jobs.bootstrap_failed', undefined, error);
  });
