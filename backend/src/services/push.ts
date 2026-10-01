import type { Knex } from 'knex';
import type { AppConfig } from '../config.js';
import { Devices } from '../db/models.js';

export interface PushMessage {
  title: string;
  body: string;
  data?: Record<string, string>;
}

export interface PushResult {
  configured: boolean;
  attempted: number;
  sent: number;
  failed: number;
}

type MessagingLike = {
  sendEachForMulticast: (m: {
    tokens: string[];
    notification?: { title: string; body: string };
    data?: Record<string, string>;
  }) => Promise<{ successCount: number; failureCount: number }>;
};

let messaging: MessagingLike | null = null;
let initAttempted = false;

/**
 * FCM via firebase-admin HTTP v1. Credentials come ONLY from env at deploy
 * time (FIREBASE_SERVICE_ACCOUNT_JSON or GOOGLE_APPLICATION_CREDENTIALS) —
 * never from the repo. When unconfigured, sends are skipped with a warning.
 */
async function getMessaging(config: AppConfig): Promise<MessagingLike | null> {
  if (initAttempted) return messaging;
  initAttempted = true;
  try {
    const admin = await import('firebase-admin');
    const { getMessaging: getMsg } = await import('firebase-admin/messaging');
    if (config.firebaseServiceAccountJson) {
      const sa = JSON.parse(config.firebaseServiceAccountJson) as Record<string, unknown>;
      admin.initializeApp({ credential: admin.cert(sa as never) });
    } else if (config.googleApplicationCredentials) {
      process.env.GOOGLE_APPLICATION_CREDENTIALS = config.googleApplicationCredentials;
      admin.initializeApp();
    } else {
      console.warn('push: no Firebase credentials configured — push sends will be skipped');
      return null;
    }
    messaging = getMsg() as unknown as MessagingLike;
    return messaging;
  } catch (err) {
    console.warn('push: firebase-admin init failed — push sends will be skipped:', err instanceof Error ? err.message : err);
    return null;
  }
}

export async function sendToUser(db: Knex, config: AppConfig, userId: string, message: PushMessage): Promise<PushResult> {
  const devices = await Devices.byUser(db, userId);
  const tokens = devices.map((d) => d.token).filter(Boolean);
  if (tokens.length === 0) return { configured: true, attempted: 0, sent: 0, failed: 0 };
  const m = await getMessaging(config);
  if (!m) return { configured: false, attempted: tokens.length, sent: 0, failed: tokens.length };
  try {
    const res = await m.sendEachForMulticast({
      tokens,
      notification: { title: message.title, body: message.body },
      data: message.data ?? {},
    });
    return { configured: true, attempted: tokens.length, sent: res.successCount, failed: res.failureCount };
  } catch (err) {
    console.error('push send failed:', err instanceof Error ? err.message : err);
    return { configured: true, attempted: tokens.length, sent: 0, failed: tokens.length };
  }
}
