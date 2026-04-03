import admin from 'firebase-admin';

import { logger } from './logger.js';

const pushLogger = logger.child({ component: 'firebase_push_service' });

type PushPayload = {
  token: string;
  title: string;
  body: string;
  data?: Record<string, any>;
  requestId?: string;
};

class FirebasePushService {
  private app: admin.app.App | null = null;
  private attemptedInit = false;

  private loadServiceAccount(): admin.ServiceAccount | null {
    const rawJson =
      process.env.FIREBASE_SERVICE_ACCOUNT_JSON?.trim() ||
      process.env.FIREBASE_ADMIN_SDK_JSON?.trim() ||
      '';
    const base64Json =
      process.env.FIREBASE_SERVICE_ACCOUNT_JSON_BASE64?.trim() || '';

    const candidate = rawJson || (base64Json
      ? Buffer.from(base64Json, 'base64').toString('utf8')
      : '');

    if (!candidate) return null;

    try {
      const parsed = JSON.parse(candidate);
      if (parsed.private_key && typeof parsed.private_key === 'string') {
        parsed.private_key = parsed.private_key.replace(/\\n/g, '\n');
      }
      return parsed as admin.ServiceAccount;
    } catch (error) {
      pushLogger.error('firebase_push.invalid_service_account_json', {}, error);
      return null;
    }
  }

  private ensureInitialized(): admin.app.App | null {
    if (this.app) return this.app;
    if (this.attemptedInit) return null;
    this.attemptedInit = true;

    try {
      const serviceAccount = this.loadServiceAccount();
      if (!serviceAccount) {
        pushLogger.warn('firebase_push.service_account_missing');
        return null;
      }

      const appName = 'orbi-sovereign-backend-push';
      this.app = admin.apps.find(
        (candidate): candidate is admin.app.App =>
          candidate != null && candidate.name === appName,
      ) ??
        admin.initializeApp(
          { credential: admin.credential.cert(serviceAccount) },
          appName,
        );

      pushLogger.info('firebase_push.initialized');
      return this.app!;
    } catch (error) {
      pushLogger.error('firebase_push.init_failed', {}, error);
      return null;
    }
  }

  async send({ token, title, body, data = {}, requestId }: PushPayload): Promise<boolean> {
    const firebaseApp = this.ensureInitialized();
    if (!firebaseApp) {
      pushLogger.warn('firebase_push.send_skipped_unavailable', {
        request_id: requestId,
      });
      return false;
    }

    try {
      const normalizedData: Record<string, string> = {};
      for (const [key, value] of Object.entries(data)) {
        if (value === undefined || value === null) continue;
        normalizedData[key] = typeof value === 'string' ? value : JSON.stringify(value);
      }

      const message: admin.messaging.Message = {
        token,
        notification: { title, body },
        data: normalizedData,
        android: {
          priority: 'high',
          notification: {
            channelId: 'orbi_foreground_notifications',
            sound: 'default',
          },
        },
        apns: {
          headers: {
            'apns-priority': '10',
          },
          payload: {
            aps: {
              sound: 'default',
              contentAvailable: true,
            },
          },
        },
      };

      const response = await firebaseApp.messaging().send(message);
      pushLogger.info('firebase_push.sent', {
        request_id: requestId,
        message_id: response,
      });
      return true;
    } catch (error: any) {
      const code = String(error?.code || '');
      pushLogger.error(
        'firebase_push.send_failed',
        {
          request_id: requestId,
          error_code: code,
        },
        error,
      );
      return false;
    }
  }
}

export const firebasePushService = new FirebasePushService();
