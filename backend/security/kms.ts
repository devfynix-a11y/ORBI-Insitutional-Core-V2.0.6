
import { getSupabase, getAdminSupabase } from '../supabaseClient.js';
import { UUID, EnvUtils } from '../../services/utils.js';
import { CONFIG } from '../../services/config.js';
import { logger } from '../infrastructure/logger.js';

export type KeyType = 'AUTH' | 'ENCRYPTION' | 'SECRET_WRAPPING' | 'SYSTEM' | 'SIGNING';

interface KeyMetadata {
    id: string; 
    version: number; 
    type: KeyType; 
    status: 'ACTIVE' | 'ROTATED'; 
    wrappedJwk: string; 
    expiresAt: number;
}

const kmsLogger = logger.child({ component: 'kms' });

export const isRecoverableActiveKeyInsertConflict = (error: any): boolean => {
    const code = String(error?.code || '').trim();
    const message = String(error?.message || '').toLowerCase();
    return (
        code === '23505' &&
        (
            message.includes('kms_keys_one_active_per_type') ||
            (message.includes('kms_keys') && message.includes('active') && message.includes('type'))
        )
    );
};

export class SecureKMSService {
    private keys: Map<string, KeyMetadata> = new Map();
    private keyMaterial: Map<string, CryptoKey> = new Map();
    private activeKeyIds: Record<KeyType, string> = { AUTH: '', ENCRYPTION: '', SECRET_WRAPPING: '', SYSTEM: '', SIGNING: '' };
    
    private initPromise: Promise<void> | null = null;
    private isReady = false;

    public async waitReady() { 
        if (this.isReady) return;
        if (!this.initPromise) {
            this.initPromise = this.init();
        }
        return this.initPromise;
    }

    public async getActiveKey(type: KeyType): Promise<CryptoKey | null> {
        if (!this.isReady) await this.waitReady();
        const id = this.activeKeyIds[type];
        return this.keyMaterial.get(id) || null;
    }

    private validateSingleActiveKeyPerType(dbKeys: any[]) {
        const activeByType = new Map<KeyType, any[]>();

        for (const dbKey of dbKeys || []) {
            if (dbKey?.status !== 'ACTIVE') continue;
            const keyType = dbKey.type as KeyType;
            const existing = activeByType.get(keyType) || [];
            existing.push(dbKey);
            activeByType.set(keyType, existing);
        }

        for (const [type, activeKeys] of activeByType.entries()) {
            if (activeKeys.length <= 1) continue;

            const keyIds = activeKeys.map((key) => key.key_id);
            kmsLogger.fatal('kms.multiple_active_keys_detected', {
                key_type: type,
                key_ids: keyIds,
                active_key_count: activeKeys.length,
            });
            throw new Error(`[KMS] Multiple ACTIVE keys detected for ${type}: ${keyIds.join(', ')}`);
        }
    }

    private sortActiveDbKeys(activeKeys: any[]): any[] {
        return [...(activeKeys || [])].sort((left, right) => {
            const versionDelta = Number(right?.version || 0) - Number(left?.version || 0);
            if (versionDelta !== 0) {
                return versionDelta;
            }

            const createdAtDelta =
                new Date(String(right?.created_at || 0)).getTime() -
                new Date(String(left?.created_at || 0)).getTime();
            if (createdAtDelta !== 0) {
                return createdAtDelta;
            }

            return String(right?.key_id || '').localeCompare(String(left?.key_id || ''));
        });
    }

    private async resolveDuplicateUsableActiveKeysForType(
        type: KeyType,
        activeDbKeys: any[],
        sb: any,
    ): Promise<string> {
        const sortedActiveKeys = this.sortActiveDbKeys(activeDbKeys);
        const winner = sortedActiveKeys[0];
        const losers = sortedActiveKeys.slice(1);

        kmsLogger.error('kms.multiple_active_keys_recovering', {
            key_type: type,
            winner_key_id: winner?.key_id,
            duplicate_key_ids: sortedActiveKeys.map((key) => key?.key_id),
            duplicate_count: sortedActiveKeys.length,
        });

        await this.retireDbKeys(sb, losers, 'DUPLICATE_ACTIVE_KEY_RECOVERY');
        this.activeKeyIds[type] = winner.key_id;

        kmsLogger.warn('kms.multiple_active_keys_recovered', {
            key_type: type,
            active_key_id: winner.key_id,
            rotated_key_ids: losers.map((key) => key.key_id),
        });

        return winner.key_id;
    }

    private async retireDbKeys(sb: any, dbKeys: any[], reason: string) {
        const keyIds = dbKeys
            .map((dbKey) => String(dbKey?.key_id || '').trim())
            .filter(Boolean);

        if (!keyIds.length) {
            return;
        }

        const { error } = await sb
            .from('kms_keys')
            .update({ status: 'ROTATED' })
            .in('key_id', keyIds);

        if (error) {
            throw error;
        }

        for (const dbKey of dbKeys) {
            const keyType = dbKey.type as KeyType;
            kmsLogger.warn('kms.unusable_active_key_retired', {
                key_id: dbKey.key_id,
                key_type: keyType,
                previous_status: dbKey.status,
                retirement_reason: reason,
            });

            const existingMeta = this.keys.get(dbKey.key_id);
            if (existingMeta) {
                existingMeta.status = 'ROTATED';
            }

            if (this.activeKeyIds[keyType] === dbKey.key_id) {
                this.activeKeyIds[keyType] = '';
            }
        }
    }

    private async tryUnwrapDbKeyWithKnownSecrets(
        dbKey: any,
        uniqueSecrets: string[],
    ): Promise<CryptoKey | null> {
        for (const secret of uniqueSecrets) {
            try {
                const wrappingKey = await this.getWrappingKey(secret);
                const unwrapped = await this.unwrapDbKey(dbKey, wrappingKey);
                if (unwrapped) {
                    return unwrapped;
                }
            } catch {
                // Try the next candidate secret.
            }
        }

        return null;
    }

    private registerHydratedDbKey(dbKey: any, keyMaterial: CryptoKey) {
        const keyType = dbKey.type as KeyType;
        this.keys.set(dbKey.key_id, {
            id: dbKey.key_id,
            version: dbKey.version,
            type: keyType,
            status: dbKey.status as any,
            wrappedJwk: dbKey.wrapped_jwk,
            expiresAt: dbKey.expires_at ? new Date(dbKey.expires_at).getTime() : 0,
        });
        this.keyMaterial.set(dbKey.key_id, keyMaterial);
        if (dbKey.status === 'ACTIVE') {
            this.activeKeyIds[keyType] = dbKey.key_id;
        }
    }

    private async hydrateExistingActiveKeyForType(
        type: KeyType,
        sb: any,
        uniqueSecrets: string[],
    ): Promise<boolean> {
        const { data, error } = await sb
            .from('kms_keys')
            .select('*')
            .eq('type', type)
            .eq('status', 'ACTIVE')
            .order('version', { ascending: false })
            .order('created_at', { ascending: false })
            .limit(2);

        if (error) {
            throw error;
        }

        const activeDbKeys = data || [];
        if (activeDbKeys.length === 0) {
            return false;
        }

        this.validateSingleActiveKeyPerType(activeDbKeys);

        const winner = activeDbKeys[0];
        const unwrapped = await this.tryUnwrapDbKeyWithKnownSecrets(winner, uniqueSecrets);
        if (!unwrapped) {
            kmsLogger.error('kms.unwrap_failed', {
                key_id: winner.key_id,
                key_type: winner.type,
                key_status: winner.status,
            });
            await this.retireDbKeys(sb, [winner], 'UNWRAP_FAILED_AFTER_INSERT_CONFLICT');
            return false;
        }

        this.registerHydratedDbKey(winner, unwrapped);
        kmsLogger.info('kms.active_key_adopted_after_conflict', {
            key_type: type,
            key_id: winner.key_id,
            key_version: winner.version,
        });
        return true;
    }

    private async getWrappingKey(secret: string): Promise<CryptoKey> {
        const encoder = new TextEncoder();
        const masterKeyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(secret),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        const salt = process.env.KMS_SALT ? encoder.encode(process.env.KMS_SALT) : encoder.encode('orbi-kms-wrapping-salt-v1');
        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 310000,
                hash: 'SHA-256'
            },
            masterKeyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['wrapKey', 'unwrapKey']
        );
    }

    public async testUnwrapWithSecret(secret: string, saltOverride?: string): Promise<boolean> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const { data: dbKey, error } = await sb
            .from('kms_keys')
            .select('*')
            .order('version', { ascending: false })
            .limit(1)
            .maybeSingle();

        if (error || !dbKey) {
            throw new Error(error?.message || 'NO_KEYS_FOUND');
        }

        const encoder = new TextEncoder();
        const masterKeyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(secret),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        const saltValue = saltOverride || process.env.KMS_SALT || 'orbi-kms-wrapping-salt-v1';
        const salt = encoder.encode(saltValue);
        const wrappingKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 310000,
                hash: 'SHA-256'
            },
            masterKeyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['wrapKey', 'unwrapKey']
        );

        try {
            await this.unwrapDbKey(dbKey, wrappingKey);
            return true;
        } catch {
            return false;
        }
    }

    private async init() {
        try {
            const sb = getAdminSupabase() || getSupabase();
            if (!sb) {
                if (process.env.NODE_ENV === 'production') {
                    throw new Error("[KMS] Database connection not available for key hydration in production.");
                }
                kmsLogger.warn('kms.db_unavailable_fallback_deterministic');
                const possibleSecrets = await this.getPossibleSecrets(null);
                const primaryKeyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(possibleSecrets[0]), { name: 'PBKDF2' }, false, ['deriveKey']);
                return await this.initDeterministic(primaryKeyMaterial);
            }

            const uniqueSecrets = await this.getPossibleSecrets(sb);
            kmsLogger.info('kms.key_hydration_secrets_collected', { secret_count: uniqueSecrets.length });

            // Load ALL existing keys from DB (Active and Rotated) to ensure old data can still be decrypted
            const { data: dbKeys, error } = await sb.from('kms_keys').select('*').order('version', { ascending: false });
            if (error) {
                if (process.env.NODE_ENV === 'production') {
                    throw new Error(`[KMS] Could not fetch keys from DB in production: ${error.message}`);
                }
                kmsLogger.warn('kms.key_fetch_failed_fallback_deterministic', { error_message: error.message });
                const primaryKeyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(uniqueSecrets[0]), { name: 'PBKDF2' }, false, ['deriveKey']);
                return await this.initDeterministic(primaryKeyMaterial);
            }

            const types: KeyType[] = ['AUTH', 'ENCRYPTION', 'SECRET_WRAPPING', 'SYSTEM', 'SIGNING'];
            const primaryWrappingKey = await this.getWrappingKey(uniqueSecrets[0]);
            const usableActiveDbKeysByType = new Map<KeyType, any[]>();
            const unusableActiveDbKeys: any[] = [];
            
            // 1. Unwrap and load all keys (both ACTIVE and ROTATED)
            if (dbKeys && dbKeys.length > 0) {
                for (const dbKey of dbKeys) {
                    const unwrapped = await this.tryUnwrapDbKeyWithKnownSecrets(dbKey, uniqueSecrets);

                    if (unwrapped) {
                        this.registerHydratedDbKey(dbKey, unwrapped);
                        
                        if (dbKey.status === 'ACTIVE') {
                            const keyType = dbKey.type as KeyType;
                            const existing = usableActiveDbKeysByType.get(keyType) || [];
                            existing.push(dbKey);
                            usableActiveDbKeysByType.set(keyType, existing);
                        }
                    } else {
                        const unwrapPayload = { key_id: dbKey.key_id, key_type: dbKey.type, key_status: dbKey.status };
                        if (dbKey.status === 'ACTIVE') {
                            kmsLogger.error('kms.unwrap_failed', unwrapPayload);
                            unusableActiveDbKeys.push(dbKey);
                        } else {
                            kmsLogger.warn('kms.unwrap_failed_rotated_key', unwrapPayload);
                        }
                    }
                }
            }

            if (unusableActiveDbKeys.length > 0) {
                await this.retireDbKeys(sb, unusableActiveDbKeys, 'UNWRAP_FAILED');
            }

            for (const [type, activeKeys] of usableActiveDbKeysByType.entries()) {
                if (activeKeys.length === 1) {
                    this.activeKeyIds[type] = activeKeys[0].key_id;
                    continue;
                }

                if (activeKeys.length > 1) {
                    await this.resolveDuplicateUsableActiveKeysForType(type, activeKeys, sb);
                }
            }

            // 2. Ensure an ACTIVE key exists for every type
            for (const type of types) {
                if (!this.activeKeyIds[type]) {
                    kmsLogger.info('kms.provisioning_new_active_key', { key_type: type });
                    const existingTypeKeys = Array.from(this.keys.values()).filter(k => k.type === type);
                    const nextVersion = existingTypeKeys.length > 0 ? Math.max(...existingTypeKeys.map(k => k.version)) + 1 : 1;
                    await this.provisionNewKey(type, primaryWrappingKey, sb, nextVersion, uniqueSecrets);
                }
            }

            this.isReady = true;
            kmsLogger.info('kms.initialized_db_backed');
        } catch (e) {
            kmsLogger.error('kms.key_hydration_failed', undefined, e);
            throw e;
        }
    }

    private async initDeterministic(masterKeyMaterial: CryptoKey) {
        const encoder = new TextEncoder();
        const types: KeyType[] = ['AUTH', 'ENCRYPTION', 'SECRET_WRAPPING', 'SYSTEM', 'SIGNING'];
        for (const type of types) {
            const id = `key-v1-det-${type.toLowerCase()}`; 
            let key: CryptoKey;
            if (type === 'ENCRYPTION' || type === 'SECRET_WRAPPING') {
                const salt = process.env.KMS_SALT ? encoder.encode(`${process.env.KMS_SALT}-${type}`) : encoder.encode(`salt-v1-${type}`);
                key = await crypto.subtle.deriveKey(
                    { name: 'PBKDF2', salt: salt, iterations: 310000, hash: 'SHA-256' },
                    masterKeyMaterial,
                    { name: 'AES-GCM', length: 256 },
                    true,
                    ['encrypt', 'decrypt']
                );
            } else {
                const salt = process.env.KMS_SALT ? encoder.encode(`${process.env.KMS_SALT}-${type}`) : encoder.encode(`salt-v1-${type}`);
                key = await crypto.subtle.deriveKey(
                    { name: 'PBKDF2', salt: salt, iterations: 310000, hash: 'SHA-256' },
                    masterKeyMaterial,
                    { name: 'HMAC', hash: 'SHA-256', length: 256 },
                    true,
                    ['sign', 'verify']
                );
            }
            this.keys.set(id, { id, version: 1, type, status: 'ACTIVE', wrappedJwk: 'DETERMINISTIC', expiresAt: Date.now() + 31536000000 });
            this.keyMaterial.set(id, key);
            this.activeKeyIds[type] = id;
        }
        this.isReady = true;
        kmsLogger.info('kms.initialized_deterministic_fallback');
    }

    private async provisionNewKey(
        type: KeyType,
        wrappingKey: CryptoKey,
        sb: any,
        version: number = 1,
        uniqueSecrets: string[] = [],
    ) {
        const id = `key-v${version}-${type.toLowerCase()}-${UUID.generate().slice(0, 8)}`;
        let key: CryptoKey;

        if (type === 'ENCRYPTION' || type === 'SECRET_WRAPPING') {
            key = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            ) as CryptoKey;
        } else if (type === 'SIGNING') {
            // Audit ledger uses ECDSA
            const pair = await crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' },
                true,
                ['sign', 'verify']
            ) as CryptoKeyPair;
            key = pair.privateKey;
        } else {
            // AUTH and others use HMAC
            key = await crypto.subtle.generateKey(
                { name: 'HMAC', hash: 'SHA-256', length: 256 },
                true,
                ['sign', 'verify']
            ) as CryptoKey;
        }

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const wrapped = await crypto.subtle.wrapKey(
            'jwk',
            key,
            wrappingKey,
            { name: 'AES-GCM', iv }
        );

        const wrappedB64 = btoa(JSON.stringify({
            iv: btoa(String.fromCharCode(...iv)),
            data: btoa(String.fromCharCode(...new Uint8Array(wrapped)))
        }));

        const expiresAt = new Date(Date.now() + (365 * 24 * 60 * 60 * 1000)).toISOString();

        const { error } = await sb.from('kms_keys').insert({
            key_id: id,
            version,
            type,
            status: 'ACTIVE',
            wrapped_jwk: wrappedB64,
            expires_at: expiresAt
        });

        if (error) {
            if (isRecoverableActiveKeyInsertConflict(error)) {
                kmsLogger.warn('kms.provisioning_race_recovered', {
                    key_type: type,
                    attempted_key_id: id,
                    attempted_version: version,
                });

                const adopted = await this.hydrateExistingActiveKeyForType(type, sb, uniqueSecrets);
                if (adopted) {
                    return;
                }
            }

            throw error;
        }

        this.keys.set(id, {
            id,
            version,
            type,
            status: 'ACTIVE',
            wrappedJwk: wrappedB64,
            expiresAt: new Date(expiresAt).getTime()
        });
        this.keyMaterial.set(id, key);
        this.activeKeyIds[type] = id;
    }

    private async unwrapDbKey(dbKey: any, wrappingKey: CryptoKey): Promise<CryptoKey> {
        const payload = JSON.parse(atob(dbKey.wrapped_jwk));
        const iv = Uint8Array.from(atob(payload.iv), c => c.charCodeAt(0));
        const wrapped = Uint8Array.from(atob(payload.data), c => c.charCodeAt(0));

        let algorithm: any;
        let usages: KeyUsage[];

        if (dbKey.type === 'ENCRYPTION' || dbKey.type === 'SECRET_WRAPPING') {
            algorithm = { name: 'AES-GCM', length: 256 };
            usages = ['encrypt', 'decrypt'];
        } else if (dbKey.type === 'SIGNING') {
            // Audit ledger uses ECDSA
            algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
            usages = ['sign'];
        } else {
            // AUTH and others use HMAC
            algorithm = { name: 'HMAC', hash: 'SHA-256', length: 256 };
            usages = ['sign', 'verify'];
        }

        return await crypto.subtle.unwrapKey(
            'jwk',
            wrapped,
            wrappingKey,
            { name: 'AES-GCM', iv },
            algorithm,
            true,
            usages
        );
    }

    public getActiveVersion(type: KeyType): number {
        const id = this.activeKeyIds[type];
        return this.keys.get(id)?.version || 1;
    }

    public async getKeyByVersion(type: KeyType, version: number): Promise<CryptoKey | null> {
        if (!this.isReady) await this.waitReady();
        const meta = Array.from(this.keys.values()).find(k => k.type === type && k.version === version);
        return meta ? this.keyMaterial.get(meta.id) || null : null;
    }

    public async rotate(type: KeyType) {
        if (!this.isReady) await this.waitReady();
        kmsLogger.info('kms.key_rotation_started', { key_type: type });

        try {
            const sb = getAdminSupabase() || getSupabase();
            if (!sb) throw new Error("[KMS] Database unavailable for rotation.");

            // 1. Get current primary wrapping key
            const possibleSecrets = await this.getPossibleSecrets(sb);
            const primaryWrappingKey = await this.getWrappingKey(possibleSecrets[0]);

            // 2. Determine next version
            const existingTypeKeys = Array.from(this.keys.values()).filter(k => k.type === type);
            const nextVersion = existingTypeKeys.length > 0 ? Math.max(...existingTypeKeys.map(k => k.version)) + 1 : 1;

            // 3. Mark old active key as ROTATED in DB
            const oldActiveId = this.activeKeyIds[type];
            if (oldActiveId) {
                const { error: updateError } = await sb
                    .from('kms_keys')
                    .update({ status: 'ROTATED' })
                    .eq('key_id', oldActiveId);
                
                if (updateError) throw updateError;
                
                const oldMeta = this.keys.get(oldActiveId);
                if (oldMeta) oldMeta.status = 'ROTATED';
            }

            // 4. Provision new ACTIVE key
            await this.provisionNewKey(type, primaryWrappingKey, sb, nextVersion, possibleSecrets);
            
            kmsLogger.info('kms.key_rotation_succeeded', { key_type: type, new_version: nextVersion });
        } catch (e) {
            kmsLogger.error('kms.key_rotation_failed', { key_type: type }, e);
            throw e;
        }
    }

    private async getPossibleSecrets(sb: any): Promise<string[]> {
        let possibleSecrets = [
            process.env.KMS_MASTER_KEY,
            process.env.KMS_MASTER_SALT // Legacy fallback
        ].filter(Boolean) as string[];

        if (possibleSecrets.length === 0) {
            possibleSecrets.push('orbi-dev-master-secret-fallback');
        }

        if (sb) {
            try {
                const { data: configData } = await sb
                    .from('platform_configs')
                    .select('config_data')
                    .eq('config_key', 'kms_master_key')
                    .single();

                if (configData?.config_data?.master_key) {
                    possibleSecrets.unshift(configData.config_data.master_key);
                }
            } catch (e) {
                kmsLogger.warn('kms.master_key_fetch_failed', { error: e instanceof Error ? e.message : String(e) });
            }
        }
        
        return Array.from(new Set(possibleSecrets));
    }

    /**
     * EMERGENCY RECOVERY: Re-wraps all keys with a new master secret.
     * This allows rotating the KMS_MASTER_KEY without losing access to data.
     */
    public async reWrapAllKeys(newMasterSecret: string) {
        if (!this.isReady) await this.waitReady();
        kmsLogger.warn('kms.master_key_rewrap_started');

        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("[KMS] Database unavailable for re-wrap.");

        const newWrappingKey = await this.getWrappingKey(newMasterSecret);
        const keysToUpdate = Array.from(this.keys.values());

        for (const meta of keysToUpdate) {
            const key = this.keyMaterial.get(meta.id);
            if (!key) continue;

            const iv = crypto.getRandomValues(new Uint8Array(12));
            const wrapped = await crypto.subtle.wrapKey(
                'jwk',
                key,
                newWrappingKey,
                { name: 'AES-GCM', iv }
            );

            const wrappedB64 = btoa(JSON.stringify({
                iv: btoa(String.fromCharCode(...iv)),
                data: btoa(String.fromCharCode(...new Uint8Array(wrapped)))
            }));

            const { error } = await sb
                .from('kms_keys')
                .update({ wrapped_jwk: wrappedB64 })
                .eq('key_id', meta.id);

            if (error) {
                kmsLogger.error('kms.rewrap_update_failed', { key_id: meta.id }, error);
                throw error;
            }

            meta.wrappedJwk = wrappedB64;
            kmsLogger.info('kms.rewrap_key_succeeded', { key_id: meta.id });
        }

        // Update platform_configs to reflect the new master key
        await sb.from('platform_configs').upsert({
            config_key: 'kms_master_key',
            config_data: { master_key: newMasterSecret },
            updated_by: 'system_recovery'
        });

        kmsLogger.info('kms.master_key_rewrap_completed');
    }

    public async createRecoveryKit() {
        return { shards: ["OBI_SHARD_ALPHA", "OBI_SHARD_BETA", "OBI_SHARD_GAMMA"], expiresAt: Date.now() + 86400000 };
    }
}

export const KMS = new SecureKMSService();
