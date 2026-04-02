
import { UUID } from '../../services/utils.js';
import { getSupabase } from '../supabaseClient.js';
import { AuditLogEntry, AuditEventType } from '../../types.js';
import { SocketRegistry } from '../infrastructure/SocketRegistry.js';
import { Signatures } from './SignatureService.js';

export type { AuditEventType };

/**
 * ORBI IMMUTABLE AUDIT LEDGER (V13.5)
 * Hardened with per-entry verification protocol and direct transaction linkage.
 */
class AuditLogService {
    private logs: AuditLogEntry[] = [];
    private lastHash: string = '0000000000000000000000000000000000000000000000000000000000000000';
    private initPromise: Promise<void> | null = null;
    private integrityTimer: any | null = null;

    constructor() {
        this.ensureInitialized();
        this.startIntegrityMonitor();
    }

    private startIntegrityMonitor() {
        // Run integrity check every hour
        this.integrityTimer = setInterval(async () => {
            const { valid, report } = await this.verifyIntegrity();
            if (!valid) {
                console.error("[Audit] CRITICAL: AUDIT CHAIN COMPROMISED!", report);
                // In a real system, alert ThreatSentinel or trigger lockdown
                SocketRegistry.broadcast({
                    type: 'SECURITY_ALERT',
                    payload: { level: 'CRITICAL', message: 'Audit chain integrity failure detected.', details: report }
                });
            }
        }, 60 * 60 * 1000);
    }

    private async ensureInitialized() {
        if (!this.initPromise) {
            this.initPromise = this.reconstructChain();
        }
        return this.initPromise;
    }

    private async reconstructChain() {
        const sb = getSupabase();
        if (!sb) return;

        try {
            // Fetch the last 50 logs from Supabase
            const { data } = await sb.from('audit_trail')
                .select('*')
                .order('timestamp', { ascending: false })
                .limit(50);
                
            if (data && data.length > 0) {
                // Reverse to maintain chronological order
                const recentLogs: AuditLogEntry[] = data.reverse().map(d => ({
                    id: d.id, prevHash: d.prev_hash, hash: d.hash, timestamp: d.timestamp,
                    type: d.event_type as AuditEventType, actor_id: d.actor_id || 'system',
                    actor_name: d.metadata?.actor_name || 'ORBI Engine', action: d.action,
                    metadata: d.metadata, signature: d.signature, verificationStatus: 'UNCHECKED',
                    transaction_id: d.transaction_id
                }));
                
                this.logs = recentLogs;
                this.lastHash = this.logs[this.logs.length - 1].hash;
            }
        } catch (e) {
            console.error("[Audit] Failed to reconstruct chain from Supabase:", e);
        }
    }

    private async sha256(message: string): Promise<string> {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    private async signPayload(payload: string): Promise<string> {
        try {
            return await Signatures.sign(payload);
        } catch (e) { 
            console.error("[Audit] Signing fault:", e);
            return `signing_fault_${Date.now()}`; 
        }
    }

    public async verifyLogEntry(entry: AuditLogEntry): Promise<boolean> {
        const payload = `${entry.prevHash}|${entry.timestamp}|${entry.type}|${entry.actor_id}|${entry.transaction_id || ''}|${entry.action}|${JSON.stringify(entry.metadata)}`;
        const calculatedHash = await this.sha256(payload);
        if (calculatedHash !== entry.hash) return false;
        await new Promise(r => setTimeout(r, 600)); 
        return true;
    }

    public async log(type: AuditEventType, actorId: string, action: string, data: any, transactionId?: string | number) {
        await this.ensureInitialized();
        const timestamp = new Date().toISOString();
        const metadataObj = { ...data, actor_name: data.actor_name || 'ORBI Agent' };
        const id = UUID.generate();
        const payload = `${this.lastHash}|${timestamp}|${type}|${actorId}|${transactionId || ''}|${action}|${JSON.stringify(metadataObj)}`;
        const hash = await this.sha256(payload);
        const signature = await this.signPayload(payload);

        const entry: AuditLogEntry = {
            id, prevHash: this.lastHash, hash, timestamp, type, actor_id: actorId, 
            actor_name: metadataObj.actor_name, action, metadata: metadataObj, signature,
            verificationStatus: 'UNCHECKED',
            transaction_id: transactionId
        };

        this.logs.push(entry);
        this.lastHash = hash;

        // Broadcast to real-time clients
        SocketRegistry.broadcast({
            type: 'AUDIT_LOG',
            payload: entry
        });

        const sb = getSupabase();
        if (sb) {
            try {
                await sb.from('audit_trail').insert({
                    id: entry.id, prev_hash: entry.prevHash, hash: entry.hash,
                    timestamp: entry.timestamp, event_type: entry.type,
                    actor_id: actorId.length > 30 ? actorId : null, 
                    transaction_id: transactionId ? String(transactionId) : null,
                    action: entry.action, metadata: metadataObj, signature: entry.signature
                });
            } catch (e) {}
        }
    }

    public getLogs(): AuditLogEntry[] { return [...this.logs]; }

    public async verifyIntegrity(): Promise<{ valid: boolean, report: { failures: string[] } }> {
        await this.ensureInitialized();
        let prev = '0000000000000000000000000000000000000000000000000000000000000000';
        const failures: string[] = [];
        for (const log of this.logs) {
            if (log.prevHash !== prev) failures.push(log.id);
            prev = log.hash;
        }
        return { valid: failures.length === 0, report: { failures } };
    }
}

export const Audit = new AuditLogService();
