/**
 * Secure key/value storage for auth secrets.
 *
 * PRIMARY (native): @aparajita/capacitor-secure-storage (v8.x, maintained;
 * last published 2026-09-23). Backed by iOS Keychain
 * (kSecAttrAccessibleWhenUnlocked) and Android EncryptedSharedPreferences
 * (AES-256 via Android Keystore). The plugin registers itself as
 * `Capacitor.Plugins.SecureStorage` with a string API:
 * getItem / setItem / removeItem / clear.
 *
 * FALLBACK (plain browser / dev): in-memory Map. Tokens live only for the
 * page session. We deliberately do NOT fall back to localStorage /
 * @capacitor/preferences — those are not encrypted and must never hold
 * refresh tokens.
 *
 * If the plugin ever becomes unmaintained, the documented fallback is a
 * minimal first-party Capacitor plugin (~150 lines per platform) wrapping
 * Keychain (iOS, Swift) and EncryptedSharedPreferences (Android, Kotlin).
 * See NATIVE_BUILD.md "Secure storage fallback plan".
 */

export interface SecureStore {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
  clear(): Promise<void>;
}

interface CapacitorGlobal {
  isNativePlatform?: () => boolean;
  Plugins?: Record<string, unknown>;
}

function nativePlugin(): SecureStore | null {
  try {
    const cap = (globalThis as unknown as { Capacitor?: CapacitorGlobal }).Capacitor;
    if (!cap || cap.isNativePlatform?.() !== true) return null;
    const plugin = cap.Plugins?.['SecureStorage'] as SecureStore | undefined;
    if (
      plugin &&
      typeof plugin.getItem === 'function' &&
      typeof plugin.setItem === 'function' &&
      typeof plugin.removeItem === 'function'
    ) {
      return plugin;
    }
    return null;
  } catch {
    return null;
  }
}

class MemoryStore implements SecureStore {
  private map = new Map<string, string>();
  async getItem(key: string): Promise<string | null> {
    return this.map.has(key) ? (this.map.get(key) as string) : null;
  }
  async setItem(key: string, value: string): Promise<void> {
    this.map.set(key, value);
  }
  async removeItem(key: string): Promise<void> {
    this.map.delete(key);
  }
  async clear(): Promise<void> {
    this.map.clear();
  }
}

const native = nativePlugin();

/** True when tokens are held in Keychain/Keystore; false on web fallback. */
export const isSecureStoreNative: boolean = native !== null;

/** Never use this for tokens outside api.ts — it is the single secret store. */
export const secureStore: SecureStore = native ?? new MemoryStore();

if (!isSecureStoreNative) {
  console.warn(
    '[paintscope-mobile] SecureStorage plugin unavailable — refresh token held in memory only (session-scoped).'
  );
}
