import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { authHeader, setupTestApp, type TestContext } from './helpers/testApp.js';
import { Identities, Providers, Users } from '../src/db/models.js';
import { decryptProviderConfig, encryptProviderConfig } from '../src/auth/providers.js';

let t: TestContext;

beforeAll(async () => {
  t = await setupTestApp();
});

afterAll(async () => {
  await t.close();
});

async function setGlobalOidcConfig(patch: Record<string, unknown>) {
  const row = await Providers.resolve(t.db, 'oidc', null);
  if (!row) throw new Error('no global oidc provider row');
  const existing = decryptProviderConfig(t.config.configEncryptionKey, row.config_encrypted);
  await Providers.update(t.db, row.id, {
    config_encrypted: encryptProviderConfig(t.config.configEncryptionKey, { ...existing, ...patch }),
  });
  return row.id;
}

describe('SSO login flows (mock OIDC issuer)', () => {
  it('completes a provider login: user + identity created, tokens issued', async () => {
    const r = await t.ssoLogin();
    expect(r.status).toBe(200);
    expect(r.accessToken).toBeTruthy();
    expect(r.refreshToken).toBeTruthy();
    expect(r.body.user.email).toBe('alice@example.com');
    expect(r.body.org).toBeNull(); // no memberships yet

    const providerId = (await Providers.resolve(t.db, 'oidc', null))!.id;
    const identity = await Identities.byProviderSub(t.db, providerId, 'mock-sub-1');
    expect(identity).toBeTruthy();
    expect(identity!.user_id).toBe(r.userId);
    const user = await Users.byId(t.db, r.userId!);
    expect(user!.email).toBe('alice@example.com');
  });

  it('reuses the same user on repeat login with the same subject', async () => {
    const first = await t.ssoLogin();
    const second = await t.ssoLogin();
    expect(second.status).toBe(200);
    expect(second.userId).toBe(first.userId);
    const users = await t.db('users').count('* as n').first();
    expect(Number(users!.n)).toBe(1);
  });

  it('rejects a bad authorization code (provider failure)', async () => {
    // Start a real flow to get a valid state, then swap in a bogus code.
    const r1 = await fetch(`${t.baseUrl}/auth/login/oidc`, { redirect: 'manual' });
    expect(r1.status).toBe(302);
    const state = new URL(r1.headers.get('location')!).searchParams.get('state')!;
    const cb = await fetch(`${t.baseUrl}/auth/callback/oidc?code=bogus-code&state=${state}`);
    expect(cb.status).toBe(401);
    const audit = await t.db('audit_events').where({ action: 'login_failure' }).orderBy('created_at', 'desc').first();
    expect(audit).toBeTruthy();
  });

  it('rejects an invalid/tampered state (CSRF protection)', async () => {
    const cb = await fetch(`${t.baseUrl}/auth/callback/oidc?code=x&state=tampered-state`);
    expect(cb.status).toBe(401);
    expect((await cb.json()).error).toBe('login_failed');
  });

  it('rejects a replayed state (single-use)', async () => {
    const r1 = await fetch(`${t.baseUrl}/auth/login/oidc`, { redirect: 'manual' });
    const idpUrl = r1.headers.get('location')!;
    const r2 = await fetch(idpUrl, { redirect: 'manual' });
    const cbUrl = new URL(r2.headers.get('location')!);
    cbUrl.host = new URL(t.baseUrl).host;
    const first = await fetch(cbUrl.toString());
    expect(first.status).toBe(200);
    const replay = await fetch(cbUrl.toString());
    expect(replay.status).toBe(401); // state already consumed
  });

  it('rejects tokens with wrong issuer (issuer confusion)', async () => {
    const r = await t.ssoLogin({ scenario: { wrongIssuer: true } });
    expect(r.status).toBe(401);
  });

  it('rejects tokens with wrong audience', async () => {
    const r = await t.ssoLogin({ scenario: { badAudience: true } });
    expect(r.status).toBe(401);
  });

  it('rejects expired tokens', async () => {
    const r = await t.ssoLogin({ scenario: { expired: true } });
    expect(r.status).toBe(401);
  });

  it('rejects nonce mismatch (replay protection)', async () => {
    const r = await t.ssoLogin({ scenario: { nonceMismatch: true } });
    expect(r.status).toBe(401);
  });

  it('rejects login when the provider is disabled', async () => {
    const row = await Providers.resolve(t.db, 'oidc', null);
    await Providers.update(t.db, row!.id, { enabled: false });
    try {
      const r1 = await fetch(`${t.baseUrl}/auth/login/oidc`, { redirect: 'manual' });
      expect(r1.status).toBe(404);
    } finally {
      await Providers.update(t.db, row!.id, { enabled: true });
    }
  });

  it('rejects login for a revoked identity (stale identity)', async () => {
    const login = await t.ssoLogin({ scenario: { sub: 'revoked-sub-9' } });
    expect(login.status).toBe(200);
    const providerId = (await Providers.resolve(t.db, 'oidc', null))!.id;
    const identity = await Identities.byProviderSub(t.db, providerId, 'revoked-sub-9');
    await t.db('identities').where({ id: identity!.id }).update({ revoked: true });
    const retry = await t.ssoLogin({ scenario: { sub: 'revoked-sub-9' } });
    expect(retry.status).toBe(403);
  });
});

describe('identity linking rules', () => {
  it('does NOT merge on unverified email (fail closed)', async () => {
    const a = await t.ssoLogin({ scenario: { sub: 'link-a', email: 'victim@example.com', emailVerified: true } });
    expect(a.status).toBe(200);
    // Attacker presents the same email but unverified.
    const b = await t.ssoLogin({ scenario: { sub: 'link-b', email: 'victim@example.com', emailVerified: false } });
    expect(b.status).toBe(200);
    expect(b.userId).not.toBe(a.userId);
    const attacker = await Users.byId(t.db, b.userId!);
    expect(attacker!.email).toBeNull(); // unverified email never lands on users.email
  });

  it('does NOT link on verified email when allowEmailLink is off', async () => {
    const a = await t.ssoLogin({ scenario: { sub: 'link-c', email: 'nolink@example.com', emailVerified: true } });
    const b = await t.ssoLogin({ scenario: { sub: 'link-d', email: 'nolink@example.com', emailVerified: true } });
    expect(b.status).toBe(200);
    expect(b.userId).not.toBe(a.userId);
  });

  it('links on verified email ONLY when allowEmailLink is explicitly on', async () => {
    const a = await t.ssoLogin({ scenario: { sub: 'link-e', email: 'linkme@example.com', emailVerified: true } });
    await setGlobalOidcConfig({ allowEmailLink: true });
    try {
      const b = await t.ssoLogin({ scenario: { sub: 'link-f', email: 'linkme@example.com', emailVerified: true } });
      expect(b.status).toBe(200);
      expect(b.userId).toBe(a.userId);
      const linked = await t.db('audit_events').where({ action: 'identity_linked' }).first();
      expect(linked).toBeTruthy();
    } finally {
      await setGlobalOidcConfig({ allowEmailLink: false });
    }
  });
});

describe('refresh rotation, reuse detection, logout', () => {
  it('rotates refresh tokens and detects reuse (revokes family)', async () => {
    const login = await t.ssoLogin({ scenario: { sub: 'refresh-a' } });
    const oldRefresh = login.refreshToken!;
    const r1 = await fetch(`${t.baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: oldRefresh }),
    });
    expect(r1.status).toBe(200);
    const j1 = await r1.json();
    expect(j1.refresh_token).toBeTruthy();
    expect(j1.refresh_token).not.toBe(oldRefresh);

    // Reuse of the rotated token -> whole family revoked.
    const r2 = await fetch(`${t.baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: oldRefresh }),
    });
    expect(r2.status).toBe(401);

    // The successor is now dead too (family revoked).
    const r3 = await fetch(`${t.baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: j1.refresh_token }),
    });
    expect(r3.status).toBe(401);
  });

  it('logout revokes the refresh family server-side', async () => {
    const login = await t.ssoLogin({ scenario: { sub: 'logout-a' } });
    const lo = await fetch(`${t.baseUrl}/auth/logout`, {
      method: 'POST',
      headers: { ...authHeader(login.accessToken!), 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: login.refreshToken }),
    });
    expect(lo.status).toBe(200);
    const audit = await t.db('audit_events').where({ action: 'logout' }).first();
    expect(audit).toBeTruthy();

    // The access token dies with the session — not after its 15-minute TTL.
    const me = await fetch(`${t.baseUrl}/me`, { headers: authHeader(login.accessToken!) });
    expect(me.status).toBe(401);

    const r = await fetch(`${t.baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: login.refreshToken }),
    });
    expect(r.status).toBe(401);
  });

  it('switches org context only for real memberships', async () => {
    const login = await t.ssoLogin({ scenario: { sub: 'orgswitch-a' } });
    const { orgId } = await t.makeOrg(login.userId!, 'member');
    const sw = await fetch(`${t.baseUrl}/auth/org`, {
      method: 'POST',
      headers: { ...authHeader(login.accessToken!), 'Content-Type': 'application/json' },
      body: JSON.stringify({ org_id: orgId }),
    });
    expect(sw.status).toBe(200);
    expect((await sw.json()).org.role).toBe('member');

    const bad = await fetch(`${t.baseUrl}/auth/org`, {
      method: 'POST',
      headers: { ...authHeader(login.accessToken!), 'Content-Type': 'application/json' },
      body: JSON.stringify({ org_id: '00000000-0000-0000-0000-000000000000' }),
    });
    expect(bad.status).toBe(403);
  });
});

describe('post-login redirect allowlist (exact match)', () => {
  const allowlisted = 'http://127.0.0.1:1/auth/done'; // matches APP_REDIRECT_ALLOWLIST in testApp

  it('returns the redirect only on exact allowlist match', async () => {
    const good = await t.ssoLogin({ scenario: { sub: 'redir-good' }, redirect: allowlisted });
    expect(good.status).toBe(200);
    expect(good.body.redirect).toBe(allowlisted);

    const withQuery = await t.ssoLogin({ scenario: { sub: 'redir-query' }, redirect: `${allowlisted}?evil=1` });
    expect(withQuery.status).toBe(200);
    expect(withQuery.body.redirect).toBeNull();

    const otherPath = await t.ssoLogin({ scenario: { sub: 'redir-path' }, redirect: 'http://127.0.0.1:1/other' });
    expect(otherPath.status).toBe(200);
    expect(otherPath.body.redirect).toBeNull();

    const noRedirect = await t.ssoLogin({ scenario: { sub: 'redir-none' } });
    expect(noRedirect.status).toBe(200);
    expect(noRedirect.body.redirect).toBeNull();
  });
});

describe('provider config hardening', () => {
  it('microsoft fails closed without an explicit tenant id', async () => {
    const { resolveProviderConfig } = await import('../src/auth/providers.js');
    const base = t.config.providers.microsoft;
    const cfgNoTenant = { ...t.config, providers: { ...t.config.providers, microsoft: { ...base, enabled: true, clientId: 'id', clientSecret: 's3cr3t', tenantId: undefined } } };
    const r1 = await resolveProviderConfig({ db: t.db, config: cfgNoTenant }, 'microsoft', null);
    expect(r1.config).toBeNull();
    expect(r1.disabledReason).toContain('MICROSOFT_TENANT_ID');

    const cfgTenant = { ...t.config, providers: { ...t.config.providers, microsoft: { ...base, enabled: true, clientId: 'id', clientSecret: 's3cr3t', tenantId: 'my-tenant' } } };
    const r2 = await resolveProviderConfig({ db: t.db, config: cfgTenant }, 'microsoft', null);
    expect(r2.config).not.toBeNull();
    expect(r2.config!.discoveryUrl).toContain('my-tenant');
    expect(r2.config!.issuer).toContain('my-tenant');
  });

  it('apple uses fixed endpoints with no discovery document', async () => {
    const { resolveProviderConfig, providerDefaults } = await import('../src/auth/providers.js');
    const defs = providerDefaults('apple', t.config.providers.apple);
    expect(defs.discoveryUrl).toBeUndefined();
    expect(defs.endpoints.authorization).toBe('https://appleid.apple.com/auth/authorize');
    expect(defs.endpoints.token).toBe('https://appleid.apple.com/auth/token');
    expect(defs.endpoints.jwks).toBe('https://appleid.apple.com/auth/keys');
    const base = t.config.providers.apple;
    const cfg = { ...t.config, providers: { ...t.config.providers, apple: { ...base, enabled: true, clientId: 'com.example.app.signin', apple: { teamId: 'TEAMID1234', keyId: 'KEYID12345', privateKeyPem: 'x' } } } };
    const r = await resolveProviderConfig({ db: t.db, config: cfg }, 'apple', null);
    expect(r.config).not.toBeNull();
    expect(r.config!.skipDiscovery).toBe(true);
  });
});

describe('SSO never grants membership', () => {
  it('a fresh SSO login creates no org memberships', async () => {
    const login = await t.ssoLogin({ scenario: { sub: 'no-membership' } });
    expect(login.status).toBe(200);
    const rows = await t.db('org_memberships').where({ user_id: login.userId });
    expect(rows).toHaveLength(0);
    expect(login.body.org).toBeNull();
  });
});

describe('atomic refresh rotation', () => {
  it('concurrent rotations of the same token: exactly one wins', async () => {
    const login = await t.ssoLogin({ scenario: { sub: 'race-a' } });
    const oldRefresh = login.refreshToken!;
    const attempts = await Promise.all(
      Array.from({ length: 5 }, () =>
        fetch(`${t.baseUrl}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: oldRefresh }),
        }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })),
      ),
    );
    const wins = attempts.filter((a) => a.status === 200);
    expect(wins).toHaveLength(1);
    expect(wins[0].body.refresh_token).toBeTruthy();
    // Losers saw the revoked token and triggered reuse detection: family is dead.
    const { sha256Hex } = await import('../src/crypto.js');
    const winnerRow = await t.db('refresh_tokens').where({ token_hash: sha256Hex(wins[0].body.refresh_token) }).first();
    expect(winnerRow).toBeTruthy();
    const live = await t.db('refresh_tokens')
      .where({ family_id: winnerRow.family_id })
      .where((qb) => qb.where({ revoked: false }).orWhereNull('revoked'));
    expect(live).toHaveLength(0);
  });
});

describe('SSO native-app bridge page', () => {
  const allowlisted = 'http://127.0.0.1:1/auth/done';

  /** Drive a full mock-OIDC flow to the callback URL, then hit the callback with custom headers. */
  async function hitCallback(redirect: string | undefined, accept: string) {
    t.mock.setNextScenario({});
    const qp = redirect ? `?redirect=${encodeURIComponent(redirect)}` : '';
    const r1 = await fetch(`${t.baseUrl}/auth/login/oidc${qp}`, { redirect: 'manual' });
    expect(r1.status).toBe(302);
    const r2 = await fetch(r1.headers.get('location')!, { redirect: 'manual' });
    expect(r2.status).toBe(302);
    const cb = new URL(r2.headers.get('location')!);
    cb.host = new URL(t.baseUrl).host;
    cb.protocol = 'http:';
    return fetch(cb.toString(), { redirect: 'manual', headers: { accept } });
  }

  it('serves the HTML bridge with tokens in the fragment for browser navigations', async () => {
    const r = await hitCallback(allowlisted, 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('text/html');
    expect(r.headers.get('referrer-policy')).toBe('no-referrer');
    const html = await r.text();
    expect(html).toContain(`${allowlisted}#`);
    const m = html.match(/auth\/done#([^"'\s<]+)/);
    expect(m).toBeTruthy();
    const params = new URLSearchParams(m![1].replace(/&amp;/g, '&'));
    expect(params.get('access_token')).toBeTruthy();
    expect(params.get('refresh_token')).toBeTruthy();
    expect(params.get('expires_in')).toBeTruthy();
    expect(params.get('token_type')).toBe('Bearer');
    // Tokens must never appear in a query string (server-visible).
    expect(html).not.toMatch(/\?access_token=/);
    expect(html).not.toMatch(/\?refresh_token=/);
  });

  it('returns JSON for API clients even when a redirect was requested', async () => {
    const r = await hitCallback(allowlisted, 'application/json');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('application/json');
    const body = await r.json();
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBeTruthy();
    expect(body.redirect).toBe(allowlisted);
  });

  it('returns JSON for default fetch clients (Accept: */*)', async () => {
    const r = await hitCallback(allowlisted, '*/*');
    expect(r.headers.get('content-type')).toContain('application/json');
    const body = await r.json();
    expect(body.access_token).toBeTruthy();
  });

  it('falls back to JSON when no redirect was requested', async () => {
    const r = await hitCallback(undefined, 'text/html,application/xhtml+xml');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('application/json');
    const body = await r.json();
    expect(body.redirect).toBeNull();
  });

  it('falls back to JSON for a non-allowlisted redirect', async () => {
    const r = await hitCallback('http://127.0.0.1:1/evil', 'text/html,application/xhtml+xml');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('application/json');
    const body = await r.json();
    expect(body.redirect).toBeNull();
    expect(body.access_token).toBeTruthy();
  });
});
