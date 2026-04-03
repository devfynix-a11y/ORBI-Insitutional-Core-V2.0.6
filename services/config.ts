
/**
 * ORBI BACKEND CONFIGURATION
 * Optimized for Render Production Node
 */
const isProd = process.env.NODE_ENV === 'production';
const defaultBackendUrl = isProd
    ? ''
    : 'http://localhost:' + (process.env.PORT || '3000');
const configuredBackendUrl = (process.env.BACKEND_URL || defaultBackendUrl).trim();

if (isProd && !configuredBackendUrl) {
    throw new Error('BACKEND_URL is required in production');
}

const wsBaseUrl = configuredBackendUrl
    ? configuredBackendUrl.replace(/^http/i, 'ws')
    : '';

export const CONFIG = {
    BACKEND_URL: configuredBackendUrl,
    // Fix: Added WS_URL required by socketClient.ts, including the nexus-stream path
    WS_URL: wsBaseUrl ? `${wsBaseUrl}/nexus-stream` : '',
    APP_ID: process.env.ORBI_INSTITUTIONAL_APP_ID || process.env.ORBI_CORE_APP_ID || process.env.APP_ID || 'ORBI_INSTITUTIONAL_CORE_V2026',
    APP_ORIGIN: process.env.ORBI_INSTITUTIONAL_APP_ORIGIN || process.env.ORBI_CORE_APP_ORIGIN || 'ORBI_INSTITUTIONAL_CORE_V2026',
    // Fix: Added IS_REMOTE_BACKEND required by socketClient.ts
    IS_REMOTE_BACKEND: /^https?:\/\//i.test(configuredBackendUrl) && !/localhost|127\.0\.0\.1/i.test(configuredBackendUrl),
    
    // Security Parameters
    WAF: {
        MAX_PAYLOAD: "10mb",
        RATE_LIMIT_RPM: 1000
    },
    
    // Key Management
    KMS_MASTER_KEY: process.env.KMS_MASTER_KEY || process.env.KMS_MASTER_SALT,

    // Fix: Added PROVISIONING object required by storage.ts, InfrastructureNodeView.tsx and ResilienceEngine.ts
    PROVISIONING: {
        IS_HYDRATED: false,
        KMS_MASTER_KEY: (process.env.KMS_MASTER_KEY || process.env.KMS_MASTER_SALT) as string | undefined,
        SUPABASE_URL: process.env.SUPABASE_URL as string | undefined,
        SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY as string | undefined,
        API_KEY: process.env.GEMINI_API_KEY as string | undefined
    },

    // Fix: Added RESILIENCE settings required by ResilienceEngine.ts
    RESILIENCE: {
        HEAL_INTERVAL: 30000,
        BREAKER_COOLDOWN: 60000,
        BREAKER_THRESHOLD: 5
    },
    
    // Optimization: Added background job interval
    BACKGROUND_JOB_INTERVAL: 60000,

    // Transaction Limits
    LEDGER: {
        TX_LIMIT: 1000000,
        DAILY_LIMIT: 5000000,
        VELOCITY_LIMIT: 50,
        FREEZE_DURATION: 604800, // 7 days
        DAILY_TTL: 86400, // 24h
        VELOCITY_TTL: 3600, // 1h
    },
    
    get IS_PROVISIONED() {
        return !!process.env.SUPABASE_URL && !!(process.env.KMS_MASTER_KEY || process.env.KMS_MASTER_SALT);
    }
};
