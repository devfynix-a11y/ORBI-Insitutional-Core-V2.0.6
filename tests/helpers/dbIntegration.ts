import test, { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';

export type DbIntegrationOptions = {
  requireWrites?: boolean;
  requiredEnv?: string[];
};

export const dbIntegrationEnabled = process.env.ORBI_RUN_DB_INTEGRATION === 'true';
export const dbIntegrationWritesEnabled = process.env.ORBI_DB_INTEGRATION_ALLOW_WRITES === 'true';

export function hasDbIntegrationConfig(): boolean {
  return !!process.env.SUPABASE_URL && !!process.env.SUPABASE_SERVICE_ROLE_KEY;
}

export function hasRequiredEnv(keys: string[] = []): boolean {
  return keys.every((key) => !!process.env[key]);
}

export function createDbIntegrationClient(): SupabaseClient {
  assert.ok(process.env.SUPABASE_URL, 'SUPABASE_URL is required for DB integration tests');
  assert.ok(process.env.SUPABASE_SERVICE_ROLE_KEY, 'SUPABASE_SERVICE_ROLE_KEY is required for DB integration tests');

  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}

export function requireEnv(name: string): string {
  const value = process.env[name];
  assert.ok(value, `${name} is required for this DB integration test`);
  return value;
}

export function dbIntegrationTest(
  name: string,
  fn: (t: TestContext, client: SupabaseClient) => Promise<void> | void,
  options: DbIntegrationOptions = {},
) {
  const shouldSkip =
    !dbIntegrationEnabled ||
    !hasDbIntegrationConfig() ||
    (options.requireWrites && !dbIntegrationWritesEnabled) ||
    !hasRequiredEnv(options.requiredEnv || []);

  test(name, { skip: shouldSkip }, async (t) => {
    const client = createDbIntegrationClient();
    await fn(t, client);
  });
}
