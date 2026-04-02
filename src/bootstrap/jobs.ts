import { Server as LogicCore } from '../../backend/server.js';
import { NotificationSubscriber } from '../../backend/infrastructure/NotificationSubscriber.js';
import { settlementScheduler } from '../../backend/payments/settlementScheduler.js';
import { RecoveryService } from '../../services/security/recoveryService.js';
import { ReconEngine as LegacyRecon } from '../../backend/ledger/reconciliationService.js';
import { EntProcessor } from '../../backend/enterprise/wealth/EnterprisePaymentProcessor.js';
import { RedisClusterFactory } from '../../backend/infrastructure/RedisClusterFactory.js';
import { logger } from '../../backend/infrastructure/logger.js';

export const bootstrapJobs = async ({
  gatewayBackgroundJobsEnabled,
}: {
  gatewayBackgroundJobsEnabled: boolean;
}) => {
  await LogicCore.warmup();
  NotificationSubscriber.init();
  if (gatewayBackgroundJobsEnabled) {
    settlementScheduler.start();
  }

  try {
    logger.info('jobs.wal_recovery_started');
    await RecoveryService.recover();
    logger.info('jobs.wal_recovery_completed');
  } catch (e) {
    logger.error('jobs.wal_recovery_failed', undefined, e);
  }

  const backgroundInterval = gatewayBackgroundJobsEnabled
    ? (() => {
        let backgroundJobRunning = false;
        return setInterval(async () => {
          if (backgroundJobRunning) {
            return;
          }
          backgroundJobRunning = true;
          try {
            await LegacyRecon.reapStuckTransactions();
            await EntProcessor.settleProcessingTransactions();
          } catch (e) {
            logger.error('jobs.background_cycle_failed', undefined, e);
          } finally {
            backgroundJobRunning = false;
          }
        }, 60000);
      })()
    : null;

  return {
    stop: async () => {
      if (backgroundInterval) clearInterval(backgroundInterval);
      settlementScheduler.stop();
      await RedisClusterFactory.shutdownAll().catch((e) => {
        logger.error('jobs.redis_shutdown_failed', undefined, e);
      });
    },
  };
};
