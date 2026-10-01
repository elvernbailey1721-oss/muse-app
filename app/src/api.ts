/**
 * Typed client for the sibling PaintScope backend.
 *
 * Backend contract (base URL from src/config.ts) — verified against
 * backend/src/routes/*.ts. Wire format is snake_case throughout.
 *
 *   GET    /auth/providers                      -> { providers: [{ type, name, login_url }] }
 *   GET    /auth/discover?email=                -> { org, providers: [{ type, name, login_url }] }
 *   GET    /auth/login/:type?redirect=&org_id=  -> 302 to the identity provider
 *   POST   /auth/refresh        { refresh_token } -> { access_token, refresh_token, expires_in?, org? }
 *   POST   /auth/logout                         -> 204 (Authorization: Bearer <access>)
 *   GET    /me                                  -> { id, email, name, avatar_url, orgs, identities }
 *   PATCH  /me                  { name?, avatar_url? } -> { id, email, name, avatar_url }
 *   POST   /devices             { platform: ios|android, token, app_version? } -> 201 { id, platform }
 *   DELETE /devices/:id                          -> 204
 *   GET    /scans?limit=&offset=                  -> { scans: Scan[] } (requires org-bound session)
 *   POST   /scans  { name, colors[], detected_color?, thumbnail?, captured_at? } -> 201 Scan
 *   GET    /scans/:id                             -> Scan (requires org-bound session)
 *   DELETE /scans/:id                             -> 204 (requires org-bound session)
 *
 * Auth is SSO-only: there is no password login. The app opens the system
 * browser at /auth/login/:type?redirect=paintscope://auth/done; after the
 * provider round-trip the backend answers the browser navigation with a
 * small HTML bridge page that hands the tokens to the app via the
 * paintscope:// deep link (tokens in the URL fragment — never the query
 * string, so they never touch a server log). The app finishes the login
 * from that deep link. API clients (fetch, no HTML Accept) keep the JSON
 * shape instead.
 *
 * Token handling:
 *   - access token: module memory only (never persisted, never logged).
 *   - refresh token: secure storage (Keychain/Keystore on native, memory on web).
 *   - on 401: exactly one silent refresh (single-flight across concurrent
 *     requests), then exactly one retry. If the refresh fails the session is
 *     cleared and a logged-out state is surfaced to listeners.
 */

import { API_BASE_URL } from './config.js';
import { secureStore } from './secure-storage.js';
import { openSystemBrowser } from './native.js';

/** Deep link the backend redirects to after SSO (must be allowlisted server-side). */
export const SSO_REDIRECT_URL = 'paintscope://auth/done';

export interface User {
  id: string;
  email: string;
  name?: string | null;
  avatar_url?: string | null;
}

export interface UserProfile extends User {
  orgs: Array<{ id: string; name: string; slug: string; role: string }>;
  identities: Array<{
    provider_id: string;
    provider_type: string;
    email: string;
    email_verified: boolean;
    linked_at: string;
  }>;
}

/** Wire shape of the backend token responses (snake_case). */
export interface TokenPair {
  access_token: string;
  refresh_token: string;
  expires_in?: number;
  token_type?: string;
}

export interface SsoProvider {
  type: string;
  name: string;
  /** Relative login URL, e.g. "/auth/login/google" or "/auth/saml/<orgId>/login". */
  login_url: string;
}

export interface DeviceInput {
  platform: 'ios' | 'android';
  /** FCM (Android) / APNs (iOS) push token. */
  token: string;
  appVersion?: string;
}

export interface Device {
  id: string;
  platform: 'ios' | 'android';
}

export interface ScanInput {
  /** Required by the backend (max 200 chars). */
  name: string;
  /** Hex colors, e.g. ["#A8C3B9"]. Non-empty, max 64. */
  colors: string[];
  detected_color?: string | null;
  /** Base64 image data, max 2MB. */
  thumbnail?: string | null;
  captured_at?: string | null;
}

export interface Scan {
  id: string;
  user_id: string;
  org_id: string;
  name: string;
  colors: string[];
  detected_color: string | null;
  thumbnail: string | null;
  captured_at: string | null;
  created_at: string;
  updated_at: string;
}

export type AuthState = 'logged-in' | 'logged-out';

export class ApiError extends Error {
  readonly status: number;
  readonly body: string;
  constructor(status: number, body: string, message?: string) {
    super(message ?? `PaintScope API error ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

/** Thrown when the session cannot be refreshed; the client is logged out. */
export class AuthError extends ApiError {
  constructor(message = 'Session expired — please sign in again.') {
    super(401, '', message);
    this.name = 'AuthError';
  }
}

const REFRESH_TOKEN_KEY = 'paintscope.refreshToken';
const JSON_HEADERS: Record<string, string> = { 'Content-Type': 'application/json' };

type Listener = (state: AuthState) => void;

export class PaintScopeApi {
  private accessToken: string | null = null; // memory only — never persisted
  private refreshInFlight: Promise<boolean> | null = null;
  private listeners = new Set<Listener>();

  // ---------------------------------------------------------------- state

  get authState(): AuthState {
    return this.accessToken ? 'logged-in' : 'logged-out';
  }

  onAuthChange(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private emit(state: AuthState): void {
    for (const l of this.listeners) {
      try {
        l(state);
      } catch {
        /* listener errors must not break auth flow */
      }
    }
  }

  /** Attempt to re-establish a session from a stored refresh token (app start). */
  async restoreSession(): Promise<boolean> {
    const stored = await secureStore.getItem(REFRESH_TOKEN_KEY);
    if (!stored) return false;
    return this.refreshTokens();
  }

  // ---------------------------------------------------------------- SSO login

  /** Providers enabled for login (global scope). */
  async listProviders(): Promise<SsoProvider[]> {
    const res = await this.rawRequest<{ providers: SsoProvider[] }>('/auth/providers');
    return res.providers ?? [];
  }

  /** Org-scoped providers for an email domain (includes per-org SAML). */
  async discoverProviders(email: string): Promise<{ org: unknown | null; providers: SsoProvider[] }> {
    return this.rawRequest(`/auth/discover?email=${encodeURIComponent(email)}`);
  }

  /**
   * Start SSO login in the system browser. `loginUrl` is a backend login_url
   * (from listProviders/discoverProviders); the backend appends nothing — we
   * add the deep-link redirect the bridge page needs.
   *
   * On native this uses the system browser (SFSafariViewController / Chrome
   * Custom Tab) so the identity provider sees a real browser session. The
   * login completes via finishSsoLoginFromUrl() when the deep link fires.
   *
   * NOTE: the ?redirect= deep-link handoff is honored by the OIDC
   * /auth/login/:type flow. Per-org SAML login URLs do not accept it yet —
   * prefer listProviders() for the mobile login UI.
   */
  async startSsoLogin(loginUrl: string, opts: { orgId?: string } = {}): Promise<void> {
    const url = new URL(loginUrl, API_BASE_URL);
    url.searchParams.set('redirect', SSO_REDIRECT_URL);
    if (opts.orgId) url.searchParams.set('org_id', opts.orgId);
    await openSystemBrowser(url.toString());
  }

  /**
   * Finish SSO login from the deep link fired by the backend bridge page:
   * paintscope://auth/done#access_token=…&refresh_token=…&expires_in=…
   * Tokens arrive in the fragment — they are never in a query string.
   */
  async finishSsoLoginFromUrl(url: string): Promise<UserProfile> {
    let params: URLSearchParams;
    try {
      params = new URLSearchParams(new URL(url).hash.slice(1));
    } catch {
      throw new AuthError('Sign-in did not complete.');
    }
    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');
    if (!accessToken || !refreshToken) {
      throw new AuthError('Sign-in did not complete.');
    }
    const expiresIn = Number(params.get('expires_in') ?? '');
    await this.applyTokens({
      access_token: accessToken,
      refresh_token: refreshToken,
      ...(Number.isFinite(expiresIn) ? { expires_in: expiresIn } : {}),
    });
    return this.getMe();
  }

  async logout(): Promise<void> {
    try {
      if (this.accessToken) {
        await this.rawRequest<void>('/auth/logout', {
          method: 'POST',
          auth: true,
        });
      }
    } catch {
      /* logout is best-effort; local session is cleared regardless */
    }
    await this.clearAuth();
  }

  /**
   * Silent refresh with rotation. Single-flight: concurrent callers share one
   * network request. Returns true when a fresh access token was obtained.
   */
  async refreshTokens(): Promise<boolean> {
    if (!this.refreshInFlight) {
      this.refreshInFlight = this.doRefresh().finally(() => {
        this.refreshInFlight = null;
      });
    }
    return this.refreshInFlight;
  }

  private async doRefresh(): Promise<boolean> {
    const stored = await secureStore.getItem(REFRESH_TOKEN_KEY);
    if (!stored) {
      await this.clearAuth();
      return false;
    }
    let res: Response;
    try {
      // The refresh token is the credential here; it goes in the JSON body,
      // never in a log line and never in a URL.
      res = await fetch(`${API_BASE_URL}/auth/refresh`, {
        method: 'POST',
        headers: JSON_HEADERS,
        body: JSON.stringify({ refresh_token: stored }),
      });
    } catch {
      return false; // network down — keep existing state, caller decides
    }
    if (!res.ok) {
      await this.clearAuth(); // rotation failed / token revoked -> logged out
      return false;
    }
    const data = (await res.json()) as TokenPair;
    if (!data.access_token || !data.refresh_token) {
      await this.clearAuth();
      return false;
    }
    await this.applyTokens(data);
    return true;
  }

  private async applyTokens(t: TokenPair): Promise<void> {
    this.accessToken = t.access_token; // memory only
    await secureStore.setItem(REFRESH_TOKEN_KEY, t.refresh_token); // rotation
    this.emit('logged-in');
  }

  private async clearAuth(): Promise<void> {
    this.accessToken = null;
    try {
      await secureStore.removeItem(REFRESH_TOKEN_KEY);
    } catch {
      /* storage failure must not leave a half-logged-in client */
    }
    this.emit('logged-out');
  }

  // ---------------------------------------------------------------- core

  private async rawRequest<T>(
    path: string,
    init: RequestInit & { auth?: boolean } = {}
  ): Promise<T> {
    const { auth, ...fetchInit } = init;
    const headers: Record<string, string> = { ...(fetchInit.headers as Record<string, string> | undefined) };
    if (fetchInit.body !== undefined && !headers['Content-Type']) {
      Object.assign(headers, JSON_HEADERS);
    }
    if (auth && this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }
    const res = await fetch(`${API_BASE_URL}${path}`, { ...fetchInit, headers });
    if (res.status === 204) return undefined as T;
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new ApiError(res.status, body.slice(0, 2000));
    }
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  /**
   * Authenticated request. On 401: one silent refresh, then exactly one
   * retry. If the refresh fails, the session is cleared and AuthError is
   * thrown so UI can surface the logged-out state.
   */
  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    try {
      return await this.rawRequest<T>(path, { ...init, auth: true });
    } catch (err) {
      if (!(err instanceof ApiError) || err.status !== 401) throw err;
      const refreshed = await this.refreshTokens();
      if (!refreshed) throw new AuthError();
      try {
        return await this.rawRequest<T>(path, { ...init, auth: true });
      } catch (retryErr) {
        if (retryErr instanceof ApiError && retryErr.status === 401) {
          await this.clearAuth();
          throw new AuthError();
        }
        throw retryErr;
      }
    }
  }

  // ---------------------------------------------------------------- users

  getMe(): Promise<UserProfile> {
    return this.request<UserProfile>('/me');
  }

  patchMe(patch: { name?: string | null; avatar_url?: string | null }): Promise<User> {
    return this.request<User>('/me', { method: 'PATCH', body: JSON.stringify(patch) });
  }

  // ---------------------------------------------------------------- devices

  registerDevice(input: DeviceInput): Promise<Device> {
    const body: Record<string, string> = {
      platform: input.platform,
      token: input.token,
    };
    if (input.appVersion) body.app_version = input.appVersion;
    return this.request<Device>('/devices', { method: 'POST', body: JSON.stringify(body) });
  }

  async unregisterDevice(id: string): Promise<void> {
    await this.request<void>(`/devices/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  // ---------------------------------------------------------------- scans

  async listScans(opts: { limit?: number; offset?: number } = {}): Promise<Scan[]> {
    const qp = new URLSearchParams();
    if (opts.limit !== undefined) qp.set('limit', String(opts.limit));
    if (opts.offset !== undefined) qp.set('offset', String(opts.offset));
    const qs = qp.toString();
    const res = await this.request<{ scans: Scan[] }>(`/scans${qs ? `?${qs}` : ''}`);
    return res.scans ?? [];
  }

  getScan(id: string): Promise<Scan> {
    return this.request<Scan>(`/scans/${encodeURIComponent(id)}`);
  }

  createScan(input: ScanInput): Promise<Scan> {
    return this.request<Scan>('/scans', { method: 'POST', body: JSON.stringify(input) });
  }

  async deleteScan(id: string): Promise<void> {
    await this.request<void>(`/scans/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  // NOTE: the backend has no PATCH /scans/:id — scans are immutable after
  // creation (create a new scan instead). There is intentionally no
  // updateScan() here so no client can depend on a 404.
}

/** Shared client instance for the mobile shell. */
export const api = new PaintScopeApi();
