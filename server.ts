import { httpServer, PORT, ALLOWED_ORIGINS, gatewayBackgroundJobsEnabled } from './src/app/createApp.js';
import { bootstrapRealtime } from './src/bootstrap/realtime.js';
import { bootstrapJobs } from './src/bootstrap/jobs.js';
import { bootstrapHttp } from './src/bootstrap/http.js';

const realtime = bootstrapRealtime({ httpServer, allowedOrigins: ALLOWED_ORIGINS });
const jobs = await bootstrapJobs({ gatewayBackgroundJobsEnabled });
await bootstrapHttp({ httpServer, port: PORT, onShutdown: async () => {
  await jobs.stop();
  await realtime.stop();
} });
