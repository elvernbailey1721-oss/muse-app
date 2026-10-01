/**
 * Mobile-shell startup. Loaded as <script type="module" src="js/main.js">
 * at the end of www/index.html — additive only, the PaintScope web app
 * itself is untouched.
 *
 * Startup order:
 *   1. Expose a small `window.PaintScopeMobile` handle (api, platform, auth).
 *   2. On native only: camera permission flow (the scanner needs it).
 *   3. On native only: silent session restore from the secure refresh token.
 *   4. On native only: push notification bootstrap; the FCM/APNs token is
 *      registered as a backend device whenever a session exists.
 *
 * Every native step is failure-isolated: if Capacitor or a plugin is missing
 * (desktop browser, web preview), the web app runs standalone.
 */

import { api, SSO_REDIRECT_URL, type AuthState } from './api.js';
import {
  closeSystemBrowser,
  ensureCameraPermission,
  initPushNotifications,
  isNative,
  nativePlatform,
  onAppUrlOpen,
} from './native.js';

declare global {
  interface Window {
    PaintScopeMobile?: {
      api: typeof api;
      isNative: boolean;
      platform: 'ios' | 'android' | 'web';
      authState: () => AuthState;
      ensureCameraPermission: typeof ensureCameraPermission;
    };
  }
}

let pendingPushToken: string | null = null;

async function registerPushToken(): Promise<void> {
  if (!pendingPushToken || api.authState !== 'logged-in') return;
  const platform = nativePlatform();
  // The backend only accepts ios/android device registrations.
  if (platform !== 'ios' && platform !== 'android') return;
  try {
    await api.registerDevice({
      platform,
      token: pendingPushToken,
      appVersion: '1.0.0',
    });
    pendingPushToken = null;
  } catch {
    /* retry on next auth change / app start */
  }
}

async function startup(): Promise<void> {
  const native = isNative();

  window.PaintScopeMobile = {
    api,
    isNative: native,
    platform: nativePlatform(),
    authState: () => api.authState,
    ensureCameraPermission,
  };

  api.onAuthChange((state) => {
    if (state === 'logged-in') void registerPushToken();
  });

  if (!native) return;

  // 0. SSO deep-link handoff: the backend bridge page fires
  // paintscope://auth/done#access_token=… after the provider round-trip.
  // Complete the login, then dismiss the system browser.
  onAppUrlOpen((url) => {
    if (!url.startsWith(SSO_REDIRECT_URL)) return;
    void (async () => {
      try {
        await api.finishSsoLoginFromUrl(url);
        await closeSystemBrowser();
      } catch (err) {
        console.warn('[paintscope-mobile] SSO deep-link handling failed:', err);
      }
    })();
  });

  // 1. Camera permission — the scanner is the app's reason for existing.
  try {
    const result = await ensureCameraPermission();
    if (result !== 'granted') {
      console.warn(`[paintscope-mobile] camera permission: ${result}`);
    }
  } catch (err) {
    console.warn('[paintscope-mobile] camera permission flow failed:', err);
  }

  // 2. Silent session restore (refresh token lives in Keychain/Keystore).
  try {
    await api.restoreSession();
  } catch (err) {
    console.warn('[paintscope-mobile] session restore failed:', err);
  }

  // 3. Push notifications.
  try {
    await initPushNotifications({
      onToken: (token) => {
        pendingPushToken = token;
        void registerPushToken();
      },
      onError: (message) => console.warn(`[paintscope-mobile] ${message}`),
    });
  } catch (err) {
    console.warn('[paintscope-mobile] push init failed:', err);
  }
}

void startup();
