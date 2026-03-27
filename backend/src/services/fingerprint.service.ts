import crypto from "crypto";
import { getAdminSupabase } from "../../supabaseClient.js";

export interface DeviceData {
    model: string;
    os?: string;
    screenResolution?: string;
    timezone?: string;
    language?: string;
    appVersion?: string;
    deviceName?: string;
    deviceModel?: string;
    deviceCodeName?: string;
    manufacturer?: string;
    brand?: string;
    platform?: string;
}

export class FingerprintService {
    generateFingerprint(device: DeviceData): string {
        // Pick only stable hardware-ish fields so the same handset does not
        // look "new" after an app update, locale change, or timezone shift.
        const stableData = {
            platform: (device.platform || '').toString().trim().toLowerCase(),
            manufacturer: (device.manufacturer || '').toString().trim().toLowerCase(),
            brand: (device.brand || '').toString().trim().toLowerCase(),
            model: (device.deviceModel || device.model || '').toString().trim().toLowerCase(),
            deviceName: (device.deviceName || '').toString().trim().toLowerCase(),
            deviceCodeName: (device.deviceCodeName || '').toString().trim().toLowerCase(),
            screenResolution: (device.screenResolution || '').toString().trim().toLowerCase(),
        };
        const raw = JSON.stringify(stableData);
        return crypto
            .createHash("sha256")
            .update(raw)
            .digest("hex");
    }

    async validateDevice(userId: string, fingerprint: string): Promise<boolean> {
        const sb = getAdminSupabase();
        if (!sb) return true; // Default to "new" if DB is down for safety

        // 1. Check if device exists for this user
        const { data: device, error } = await sb
            .from('user_devices')
            .select('*')
            .eq('user_id', userId)
            .eq('device_fingerprint', fingerprint)
            .maybeSingle();

        if (error) {
            console.error("[Fingerprint] Error validating device:", error);
            return true; 
        }

        if (device) {
            // Update last active
            await sb.from('user_devices').update({ 
                last_active_at: new Date().toISOString() 
            }).eq('id', device.id);
            
            return false; // Not a new device
        } else {
            // 2. Register new device (initially untrusted)
            await sb.from('user_devices').insert({
                user_id: userId,
                device_fingerprint: fingerprint,
                is_trusted: false,
                status: 'active'
            });
            
            return true; // It is a new device
        }
    }
}

export const Fingerprint = new FingerprintService();
