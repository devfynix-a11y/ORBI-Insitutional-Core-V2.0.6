import { Server as LogicCore } from '../../backend/server.js';
import { NotificationSubscriber } from '../../backend/infrastructure/NotificationSubscriber.js';
import { settlementScheduler } from '../../backend/payments/settlementScheduler.js';
import { RecoveryService } from '../../services/security/recoveryService.js';
import { ReconEngine as LegacyRecon } from '../../backend/ledger/reconciliationService.js';
import { EntProcessor } from '../../backend/enterprise/wealth/EnterprisePaymentProcessor.js';
import { RedisClusterFactory } from '../../backend/infrastructure/RedisClusterFactory.js';

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
    console.log('[System] Initializing Fintech Security Core...');
    await RecoveryService.recover();
    console.log('[System] WAL Recovery Complete.');
  } catch (e) {
    console.error('[System] WAL Recovery Failed:', e);
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
            console.error('[System] Background Cycle Error:', e);
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
        console.error('[System] Error closing Redis connections:', e);
      });
    },
  };
};
