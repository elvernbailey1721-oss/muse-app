import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import type { Knex } from 'knex';
import type { AppConfig } from '../../src/config.js';
import { loadConfig } from '../../src/config.js';
import { createKnex } from '../../src/db/knex.js';
import { runMigrations } from '../../src/db/migrateRunner.js';
import { createApp } from '../../src/app.js';
import { startMockIdp, type MockIdp, type MockScenario } from './mockIdp.js';
import { Memberships, Organizations, Users, type Role } from '../../src/db/models.js';
import { createSession } from '../../src/auth/tokens.js';

export interface LoginResult {
  status: number;
  body: any;
  accessToken?: string;
  refreshToken?: string;
  userId?: string;
}

export interface TestContext {
  baseUrl: string;
  db: Knex;
  config: AppConfig;
  mock: MockIdp;
  close: () => Promise<void>;
  /** Full SSO round-trip through the mock IdP (default provider: generic oidc). */
  ssoLogin: (opts?: { scenario?: MockScenario; provider?: string; orgId?: string; redirect?: string }) => Promise<LoginResult>;
  /** Create org + owner membership for a user via models. */
  makeOrg: (userId: string, role?: Role, domain?: string) => Promise<{ orgId: string }>;
  /** Mint a token pair directly (bypasses SSO; for RBAC/tenant tests). */
  sessionFor: (userId: string, orgId: string | null, role: Role | null) => Promise<{ accessToken: string; refreshToken: string }>;
}

export async function setupTestApp(): Promise<TestContext> {
  const mock = await startMockIdp();

  process.env.JWT_SECRET = '0123456789abcdef'.repeat(4); // 64 chars
  process.env.CONFIG_ENCRYPTION_KEY = 'abcdef0123456789'.repeat(4); // 64 hex chars
  process.env.APP_BASE_URL = 'http://127.0.0.1:1'; // placeholder; flow helper rewrites hosts
  process.env.APP_REDIRECT_ALLOWLIST = 'http://127.0.0.1:1/auth/done';
  process.env.OIDC_ENABLED = 'true';
  process.env.OIDC_ISSUER = mock.issuer;
  process.env.OIDC_CLIENT_ID = mock.clientId;
  process.env.OIDC_CLIENT_SECRET = mock.clientSecret;
  process.env.OIDC_ALLOW_EMAIL_LINK = 'false';
  process.env.OIDC_SKIP_DISCOVERY = 'true';
  process.env.OIDC_AUTHORIZATION_ENDPOINT = `${mock.issuer}/authorize`;
  process.env.OIDC_TOKEN_ENDPOINT = `${mock.issuer}/token`;
  process.env.OIDC_USERINFO_ENDPOINT = `${mock.issuer}/userinfo`;
  process.env.OIDC_JWKS_URI = `${mock.issuer}/jwks`;
  // Test-only: the mock IdP is plain HTTP; openid-client enforces HTTPS.
  // NEVER set this outside the test suite.
  process.env.OIDC_TEST_ALLOW_HTTP = '1';

  const config = loadConfig();
  const db = createKnex({ filename: ':memory:' });
  await runMigrations(db);
  const app = createApp({ db, config });
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;

  const ssoLogin = async (opts: { scenario?: MockScenario; provider?: string; orgId?: string; redirect?: string } = {}): Promise<LoginResult> => {
    const provider = opts.provider ?? 'oidc';
    mock.setNextScenario(opts.scenario ?? {});
    const qp = new URLSearchParams();
    if (opts.orgId) qp.set('org_id', opts.orgId);
    if (opts.redirect) qp.set('redirect', opts.redirect);
    const qs = qp.toString();
    const loginUrl = `${baseUrl}/auth/login/${provider}${qs ? `?${qs}` : ''}`;
    const r1 = await fetch(loginUrl, { redirect: 'manual' });
    if (r1.status !== 302) {
      const body = await r1.text();
      return { status: r1.status, body: safeJson(body) };
    }
    const idpUrl = r1.headers.get('location')!;
    const r2 = await fetch(idpUrl, { redirect: 'manual' });
    if (r2.status !== 302) {
      return { status: r2.status, body: await r2.text() };
    }
    // Rewrite the placeholder APP_BASE_URL host to the real test server.
    const cb = new URL(r2.headers.get('location')!);
    cb.host = `127.0.0.1:${port}`;
    cb.protocol = 'http:';
    const r3 = await fetch(cb.toString(), { redirect: 'manual' });
    const body = safeJson(await r3.text());
    return {
      status: r3.status,
      body,
      accessToken: body.access_token,
      refreshToken: body.refresh_token,
      userId: body.user?.id,
    };
  };

  const makeOrg = async (userId: string, role: Role = 'owner', domain?: string) => {
    const n = Math.random().toString(36).slice(2, 8);
    const org = await Organizations.create(db, {
      name: `Org ${n}`,
      slug: `org-${n}`,
      domain: domain ?? null,
    });
    await Memberships.create(db, userId, org.id, role);
    return { orgId: org.id };
  };

  const sessionFor = async (userId: string, orgId: string | null, role: Role | null) => {
    const user = await Users.byId(db, userId);
    if (!user) throw new Error('sessionFor: unknown user');
    const pair = await createSession(db, config.jwtSecret, user, orgId, role);
    return { accessToken: pair.accessToken, refreshToken: pair.refreshToken };
  };

  return {
    baseUrl,
    db,
    config,
    mock,
    close: async () => {
      await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
      await mock.close();
      await db.destroy();
    },
    ssoLogin,
    makeOrg,
    sessionFor,
  };
}

function safeJson(text: string): any {
  try {
    return JSON.parse(text);
  } catch {
    return { _raw: text };
  }
}

export function authHeader(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
}
