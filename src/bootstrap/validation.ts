export const validateStartupEnvironment = () => {
  const requiredEnv = [
    'JWT_SECRET',
    'RP_ID',
    'ORBI_WEB_ORIGIN',
    'ORBI_ANDROID_APP_HASH',
    'ORBI_MOBILE_ORIGIN',
    'KMS_MASTER_KEY',
    'WORKER_SECRET',
    'WORKER_SIGNING_SECRET',
    'ORBI_INTERNAL_MTLS_MODE',
  ];

  for (const key of requiredEnv) {
    if (process.env.NODE_ENV === 'production' && !process.env[key]) {
      console.error(`[Startup] CRITICAL_FAILURE: Missing required environment variable: ${key}`);
      process.exit(1);
    }
  }

  if (process.env.NODE_ENV === 'production') {
    if (
      process.env.REDIS_TLS_ENABLED === 'true' &&
      process.env.REDIS_ALLOW_INSECURE_TLS === 'true'
    ) {
      console.error('[Startup] CRITICAL_FAILURE: REDIS_ALLOW_INSECURE_TLS cannot be enabled in production.');
      process.exit(1);
    }

    if (process.env.ORBI_ANDROID_APP_HASH && !process.env.ORBI_ANDROID_PACKAGE_NAME) {
      console.error('[Startup] CRITICAL_FAILURE: ORBI_ANDROID_PACKAGE_NAME is required when ORBI_ANDROID_APP_HASH is configured.');
      process.exit(1);
    }

    if (process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS === 'false') {
      console.error('[Startup] CRITICAL_FAILURE: ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS cannot be disabled in production.');
      process.exit(1);
    }

    if (process.env.ORBI_ALLOW_LEGACY_INTERNAL_WORKER_AUTH === 'true') {
      console.error('[Startup] CRITICAL_FAILURE: ORBI_ALLOW_LEGACY_INTERNAL_WORKER_AUTH cannot be enabled in production.');
      process.exit(1);
    }

    if (String(process.env.ORBI_INTERNAL_MTLS_MODE || '').trim().toLowerCase() !== 'required') {
      console.error('[Startup] CRITICAL_FAILURE: ORBI_INTERNAL_MTLS_MODE must be set to required in production.');
      process.exit(1);
    }
  }
};
