import { logger } from '../../backend/infrastructure/logger.js';
import { getAdminSupabase, getSupabase } from '../../services/supabaseClient.js';

const REQUIRED_ENV_PROD = [
  'JWT_SECRET',
  'RP_ID',
  'ORBI_WEB_ORIGIN',
  'ORBI_ANDROID_APP_HASH',
  'ORBI_MOBILE_ORIGIN',
  'KMS_MASTER_KEY',
  'WORKER_SECRET',
  'WORKER_SIGNING_SECRET',
  'ORBI_INTERNAL_MTLS_MODE',
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_ANON_KEY',
];

const OPTIONAL_ENV = [
  'ORBI_WEBHOOK_MAX_AGE_SECONDS',
  'ORBI_WEBHOOK_REPLAY_WINDOW_SECONDS',
  'ORBI_PROVIDER_TIMEOUT_MS',
  'ORBI_PROVIDER_MAX_ATTEMPTS',
  'ORBI_PROVIDER_RETRY_DELAY_MS',
  'ORBI_GATEWAY_URL',
  'ORBI_GATEWAY_BASE_URL',
  'ORBI_GATEWAY_API_KEY',
  'ORBI_GATEWAY_USER_ID',
  'ORBI_GATEWAY_USER_EMAIL',
  'REDIS_CLUSTER_NODES',
  'REDIS_URL',
  'REDIS_HOST',
];

const REQUIRED_RPC_DEPENDENCIES = [
  'post_transaction_v2',
  'append_ledger_entries_v1',
  'claim_internal_transfer_settlement',
  'complete_internal_transfer_settlement',
  'repair_wallet_balance_emergency',
];

const fatalIfMissing = (key: string) => {
  logger.fatal('startup.missing_required_env', { env_key: key });
  process.exit(1);
};

const warnOptional = (key: string) => {
  logger.warn('startup.missing_optional_env', { env_key: key });
};

export const validateStartupEnvironment = () => {
  const isProd = process.env.NODE_ENV === 'production';

  for (const key of REQUIRED_ENV_PROD) {
    if (isProd && !process.env[key]) {
      fatalIfMissing(key);
    }
  }

  for (const key of OPTIONAL_ENV) {
    if (!process.env[key]) {
      logger.info('startup.optional_env_unset', { env_key: key });
    }
  }

  if (isProd) {
    if (
      process.env.REDIS_TLS_ENABLED === 'true' &&
      process.env.REDIS_ALLOW_INSECURE_TLS === 'true'
    ) {
      logger.fatal('startup.invalid_prod_redis_tls', {
        redis_tls_enabled: process.env.REDIS_TLS_ENABLED,
        redis_allow_insecure_tls: process.env.REDIS_ALLOW_INSECURE_TLS,
      });
      process.exit(1);
    }

    if (process.env.ORBI_ANDROID_APP_HASH && !process.env.ORBI_ANDROID_PACKAGE_NAME) {
      logger.fatal('startup.invalid_android_origin_config', {
        has_android_app_hash: !!process.env.ORBI_ANDROID_APP_HASH,
        has_android_package_name: !!process.env.ORBI_ANDROID_PACKAGE_NAME,
      });
      process.exit(1);
    }

    if (process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS === 'false') {
      logger.fatal('startup.invalid_internal_auth_config', {
        require_signed_internal_requests: process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS,
      });
      process.exit(1);
    }

    if (process.env.ORBI_ALLOW_LEGACY_INTERNAL_WORKER_AUTH === 'true') {
      logger.fatal('startup.legacy_internal_auth_forbidden', {
        allow_legacy_internal_worker_auth: process.env.ORBI_ALLOW_LEGACY_INTERNAL_WORKER_AUTH,
      });
      process.exit(1);
    }

    if (String(process.env.ORBI_INTERNAL_MTLS_MODE || '').trim().toLowerCase() !== 'required') {
      logger.fatal('startup.invalid_internal_mtls_mode', {
        internal_mtls_mode: process.env.ORBI_INTERNAL_MTLS_MODE,
      });
      process.exit(1);
    }
  }
};

const validateProviderSecretDependencies = (isProd: boolean) => {
  const hasGatewayKey = Boolean(process.env.ORBI_GATEWAY_API_KEY);
  const hasGatewayUrl = Boolean(process.env.ORBI_GATEWAY_URL || process.env.ORBI_GATEWAY_BASE_URL);

  if (hasGatewayKey !== hasGatewayUrl) {
    const payload = {
      has_gateway_key: hasGatewayKey,
      has_gateway_url: hasGatewayUrl,
    };
    if (isProd) {
      logger.fatal('startup.invalid_gateway_config', payload);
      process.exit(1);
    } else {
      logger.warn('startup.invalid_gateway_config', payload);
    }
  }

  if (process.env.ORBI_REQUIRE_WEBHOOK_SIGNATURES !== 'false' && process.env.NODE_ENV === 'production') {
    if (process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE === 'true') {
      logger.fatal('startup.invalid_webhook_replay_store', {
        allow_local_replay_store: process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE,
      });
      process.exit(1);
    }
  }
};

const validateDbDependencies = async (isProd: boolean) => {
  const adminClient = getAdminSupabase();
  const publicClient = getSupabase();

  if (!adminClient || !publicClient) {
    const payload = {
      has_admin_client: !!adminClient,
      has_public_client: !!publicClient,
    };
    if (isProd) {
      logger.fatal('startup.missing_supabase_clients', payload);
      process.exit(1);
    } else {
      logger.warn('startup.missing_supabase_clients', payload);
      return;
    }
  }

  const shouldValidateDb = isProd || process.env.ORBI_VALIDATE_DB_ON_STARTUP === 'true';
  if (!shouldValidateDb || !adminClient) return;

  const timeoutMs = Number(process.env.ORBI_STARTUP_DB_TIMEOUT_MS || 5000);
  const withTimeout = async <T>(promise: PromiseLike<T>, label: string) => {
    const timer = new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`${label}_TIMEOUT`)), timeoutMs),
    );
    return Promise.race([Promise.resolve(promise), timer]);
  };

  try {
    const connectivityPromise = adminClient
      .from('transactions')
      .select('id')
      .limit(1)
      .maybeSingle()
      .then((result) => result);
    await withTimeout(connectivityPromise, 'DB_CONNECTIVITY');
  } catch (error: any) {
    logger.fatal('startup.db_unreachable', { message: error?.message || String(error) });
    process.exit(1);
  }

  const shouldValidateRpc = isProd || process.env.ORBI_VALIDATE_RPC_ON_STARTUP === 'true';
  if (!shouldValidateRpc) return;

  for (const rpcName of REQUIRED_RPC_DEPENDENCIES) {
    try {
      const result = await adminClient.rpc(rpcName as any, {} as any);
      if (result.error && /does not exist|missing function/i.test(String(result.error.message || ''))) {
        logger.fatal('startup.rpc_missing', { rpc: rpcName, message: result.error.message });
        process.exit(1);
      }
      if (result.error) {
        logger.warn('startup.rpc_probe_error', { rpc: rpcName, message: result.error.message });
      }
    } catch (error: any) {
      if (/does not exist|missing function/i.test(String(error?.message || ''))) {
        logger.fatal('startup.rpc_missing', { rpc: rpcName, message: error?.message || String(error) });
        process.exit(1);
      }
      logger.warn('startup.rpc_probe_error', { rpc: rpcName, message: error?.message || String(error) });
    }
  }
};

export const validateStartupDependencies = async () => {
  const isProd = process.env.NODE_ENV === 'production';

  validateProviderSecretDependencies(isProd);
  await validateDbDependencies(isProd);
};
