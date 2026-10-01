/**
 * Build-time configuration.
 *
 * The API base URL resolves in this order:
 *   1. Runtime override: `window.__PAINTSCOPE_API_URL__` (set by native code
 *      or an inline config snippet before js/main.js loads).
 *   2. Build-time token `__PAINTSCOPE_API_URL_BUILD__`, replaced by
 *      tools/build-web.mjs from the $PAINTSCOPE_API_URL environment variable.
 *   3. Default: http://localhost:3000 (sibling backend dev server).
 *
 * Production builds MUST set $PAINTSCOPE_API_URL to an https:// origin.
 * Android WebViews block cleartext http by default and the CSP's
 * connect-src only allows the configured origin.
 */

// Replaced verbatim by tools/build-web.mjs at build time. This identifier is
// intentionally distinct from the runtime window property name so the
// replacement can never touch the property access below.
declare const __PAINTSCOPE_API_URL_BUILD__: string | undefined;

const RUNTIME_KEY = '__PAINTSCOPE_API_URL__';

function resolveApiBaseUrl(): string {
  const runtime = (globalThis as unknown as Record<string, unknown>)[RUNTIME_KEY];
  if (typeof runtime === 'string' && runtime.length > 0) return runtime;
  if (
    typeof __PAINTSCOPE_API_URL_BUILD__ !== 'undefined' &&
    __PAINTSCOPE_API_URL_BUILD__
  ) {
    return __PAINTSCOPE_API_URL_BUILD__;
  }
  return 'http://localhost:3000';
}

export const API_BASE_URL: string = resolveApiBaseUrl();

/** Origin form (scheme + host + port) used for the CSP connect-src entry. */
export function apiOrigin(): string {
  try {
    return new URL(API_BASE_URL).origin;
  } catch {
    return API_BASE_URL;
  }
}
