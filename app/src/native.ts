/**
 * Capacitor native bridge.
 *
 * Plugins are reached through the runtime registry (`window.Capacitor.Plugins`)
 * rather than bare npm imports: this file ships as a plain
 * `<script type="module">` inside www/, where bare specifiers do not resolve.
 * Type-only imports are erased at compile time, so they are safe.
 */
import type { PermissionState } from '@capacitor/core';
import type { CameraPermissionState } from '@capacitor/camera';
import type { BrowserPlugin } from '@capacitor/browser';
import type { AppPlugin } from '@capacitor/app';

type CameraPermissionStatus = { camera: CameraPermissionState; photos?: CameraPermissionState };
type PushPermissionStatus = { receive: PermissionState };

interface CameraPlugin {
  checkPermissions(): Promise<CameraPermissionStatus>;
  requestPermissions(): Promise<CameraPermissionStatus>;
}

interface PushNotificationsPlugin {
  checkPermissions(): Promise<PushPermissionStatus>;
  requestPermissions(): Promise<PushPermissionStatus>;
  register(): Promise<void>;
  removeAllListeners(): Promise<void>;
  addListener(
    event: 'registration' | 'registrationError' | 'pushNotificationReceived' | 'pushNotificationActionPerformed',
    callback: (data: unknown) => void
  ): Promise<{ remove: () => void }>;
}

interface CapacitorGlobal {
  isNativePlatform?: () => boolean;
  getPlatform?: () => string;
  Plugins?: {
    Camera?: CameraPlugin;
    PushNotifications?: PushNotificationsPlugin;
    Browser?: BrowserPlugin;
    App?: AppPlugin;
    [key: string]: unknown;
  };
}

function capacitor(): CapacitorGlobal | null {
  try {
    return (globalThis as unknown as { Capacitor?: CapacitorGlobal }).Capacitor ?? null;
  } catch {
    return null;
  }
}

/** True inside the native WebView (Android/iOS shell); false in a browser. */
export function isNative(): boolean {
  const cap = capacitor();
  try {
    return cap?.isNativePlatform?.() === true;
  } catch {
    return false;
  }
}

export function nativePlatform(): 'ios' | 'android' | 'web' {
  const cap = capacitor();
  const p = cap?.getPlatform?.();
  return p === 'ios' || p === 'android' ? p : 'web';
}

export type CameraPermissionResult = 'granted' | 'denied' | 'unavailable';

/**
 * Camera permission flow for the scanner. Called once at startup:
 * check first (no prompt if already decided), request only when the state is
 * still "prompt". Never throws — returns a status the UI can act on.
 */
export async function ensureCameraPermission(): Promise<CameraPermissionResult> {
  const camera = capacitor()?.Plugins?.Camera;
  if (!camera) return 'unavailable';
  try {
    const current = await camera.checkPermissions();
    if (current.camera === 'granted' || current.camera === 'limited') return 'granted';
    if (current.camera === 'denied') return 'denied';
    const next = await camera.requestPermissions();
    return next.camera === 'granted' || next.camera === 'limited' ? 'granted' : 'denied';
  } catch {
    return 'denied';
  }
}

export interface PushInit {
  /** Called with the FCM (Android) / APNs (iOS) device token on registration. */
  onToken: (token: string) => void;
  onError?: (message: string) => void;
}

/**
 * Push notification bootstrap. Requests the receive permission, registers
 * with FCM/APNs, and wires the standard listeners. Requires the native
 * PushNotifications plugin plus (Android) google-services.json and (iOS) an
 * APNs key configured in the backend — see NATIVE_BUILD.md.
 */
export async function initPushNotifications(init: PushInit): Promise<void> {
  const push = capacitor()?.Plugins?.PushNotifications;
  if (!push) return;
  await push.removeAllListeners().catch(() => undefined);

  const check = await push.checkPermissions().catch(() => ({ receive: 'denied' as PermissionState }));
  if (check.receive !== 'granted') {
    const req = await push.requestPermissions().catch(() => ({ receive: 'denied' as PermissionState }));
    if (req.receive !== 'granted') {
      init.onError?.('Push notification permission not granted.');
      return;
    }
  }

  await push.addListener('registration', (data) => {
    const token = (data as { value?: string } | null)?.value;
    if (token) init.onToken(token);
  });
  await push.addListener('registrationError', (data) => {
    const message = (data as { error?: string } | null)?.error ?? 'unknown registration error';
    init.onError?.(`Push registration failed: ${message}`);
  });
  // Foreground notifications are delivered to the web app; badge/sound/alert
  // presentation is configured in capacitor.config.ts.
  await push.addListener('pushNotificationReceived', () => undefined);
  await push.addListener('pushNotificationActionPerformed', () => undefined);

  await push.register();
}

/**
 * Open a URL in the system browser (SFSafariViewController on iOS, Chrome
 * Custom Tab on Android). Used for SSO login so the identity provider sees a
 * real browser session with its own cookie jar — never the app WebView.
 * Falls back to a new tab when not running natively.
 */
export async function openSystemBrowser(url: string): Promise<void> {
  const browser = capacitor()?.Plugins?.Browser;
  if (browser?.open) {
    await browser.open({ url });
    return;
  }
  window.open(url, '_blank', 'noopener');
}

/** Close the system browser previously opened with openSystemBrowser(). No-op on web. */
export async function closeSystemBrowser(): Promise<void> {
  try {
    await capacitor()?.Plugins?.Browser?.close();
  } catch {
    /* already closed or unavailable */
  }
}

/**
 * Listen for deep links that reopen the app (e.g. paintscope://auth/done
 * fired by the backend SSO bridge page). Requires the URL scheme to be
 * registered: CFBundleURLTypes on iOS, intent-filter on Android.
 * Returns an unsubscribe function. Safe no-op where the App plugin is missing.
 */
export function onAppUrlOpen(callback: (url: string) => void): () => void {
  const app = capacitor()?.Plugins?.App;
  if (!app?.addListener) return () => undefined;
  let handle: { remove: () => void } | undefined;
  let cancelled = false;
  app
    .addListener('appUrlOpen', (data: { url: string }) => {
      if (!cancelled && typeof data?.url === 'string') callback(data.url);
    })
    .then((h) => {
      handle = h;
    })
    .catch(() => undefined);
  return () => {
    cancelled = true;
    handle?.remove();
  };
}
