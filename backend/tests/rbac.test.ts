import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { authHeader, setupTestApp, type TestContext } from './helpers/testApp.js';
import { sendToUser } from '../src/services/push.js';

let t: TestContext;

beforeAll(async () => {
  t = await setupTestApp();
});

afterAll(async () => {
  await t.close();
});

interface Actor {
  userId: string;
  orgId: string;
  accessToken: string;
}

/** Full SSO + org + membership, as a real mobile client would do. */
async function onboard(sub: string, role: 'owner' | 'admin' | 'member' = 'owner'): Promise<Actor> {
  const login = await t.ssoLogin({ scenario: { sub, email: `${sub}@example.com` } });
  if (login.status !== 200) throw new Error(`sso login failed for ${sub}: ${login.status}`);
  const { orgId } = await t.makeOrg(login.userId!, role);
  const { accessToken } = await t.sessionFor(login.userId!, orgId, role);
  return { userId: login.userId!, orgId, accessToken };
}

describe('tenant isolation + RBAC', () => {
  let a: Actor;
  let b: Actor;
  let scanIdA: string;

  beforeAll(async () => {
    a = await onboard('tenant-a', 'owner');
    b = await onboard('tenant-b', 'owner');

    const created = await fetch(`${t.baseUrl}/scans`, {
      method: 'POST',
      headers: authHeader(a.accessToken),
      body: JSON.stringify({ name: 'A scan', colors: ['#ff0000'], detected_color: '#ff0000' }),
    });
    expect(created.status).toBe(201);
    scanIdA = (await created.json()).id;
  });

  it('org B cannot list org A scans (tenant isolation)', async () => {
    const res = await fetch(`${t.baseUrl}/scans`, { headers: authHeader(b.accessToken) });
    expect(res.status).toBe(200);
    expect((await res.json()).scans).toHaveLength(0);
  });

  it('org B cannot read org A scan by id', async () => {
    const res = await fetch(`${t.baseUrl}/scans/${scanIdA}`, { headers: authHeader(b.accessToken) });
    expect(res.status).toBe(404);
  });

  it('org B cannot delete org A scan', async () => {
    const res = await fetch(`${t.baseUrl}/scans/${scanIdA}`, {
      method: 'DELETE',
      headers: authHeader(b.accessToken),
    });
    expect(res.status).toBe(404);
  });

  it('a member cannot delete a scan; owner can (RBAC)', async () => {
    const login = await t.ssoLogin({ scenario: { sub: 'tenant-member', email: 'tenant-member@example.com' } });
    const { accessToken } = await t.sessionFor(login.userId!, a.orgId, 'member');
    // add membership row as member
    await t.db('org_memberships').insert({
      id: crypto.randomUUID(),
      user_id: login.userId!,
      org_id: a.orgId,
      role: 'member',
    });
    const denied = await fetch(`${t.baseUrl}/scans/${scanIdA}`, {
      method: 'DELETE',
      headers: authHeader(accessToken),
    });
    expect(denied.status).toBe(403);

    const allowed = await fetch(`${t.baseUrl}/scans/${scanIdA}`, {
      method: 'DELETE',
      headers: authHeader(a.accessToken),
    });
    expect(allowed.status).toBe(200);
  });

  it('a member cannot change member roles; an owner can', async () => {
    const denied = await fetch(`${t.baseUrl}/orgs/${a.orgId}/members/${b.userId}`, {
      method: 'PATCH',
      headers: authHeader(b.accessToken),
      body: JSON.stringify({ role: 'admin' }),
    });
    expect(denied.status).toBe(403);

    // make b a member of org A first via owner action
    await t.db('org_memberships').insert({
      id: crypto.randomUUID(),
      user_id: b.userId,
      org_id: a.orgId,
      role: 'member',
    });
    const allowed = await fetch(`${t.baseUrl}/orgs/${a.orgId}/members/${b.userId}`, {
      method: 'PATCH',
      headers: authHeader(a.accessToken),
      body: JSON.stringify({ role: 'admin' }),
    });
    expect(allowed.status).toBe(200);
    expect((await allowed.json()).role).toBe('admin');
  });

  it('denied actions are audited', async () => {
    const row = await t.db('audit_events').where({ action: 'authz_denied' }).first();
    expect(row).toBeTruthy();
  });

  it('org switching cannot escape membership (no tenant hop)', async () => {
    const res = await fetch(`${t.baseUrl}/auth/org`, {
      method: 'POST',
      headers: { ...authHeader(a.accessToken), 'Content-Type': 'application/json' },
      body: JSON.stringify({ org_id: b.orgId }),
    });
    expect(res.status).toBe(403);
  });
});

describe('/me and devices', () => {
  let actor: Actor;

  beforeAll(async () => {
    actor = await onboard('me-devices', 'owner');
  });

  it('GET /me returns identities and memberships', async () => {
    const res = await fetch(`${t.baseUrl}/me`, { headers: authHeader(actor.accessToken) });
    expect(res.status).toBe(200);
    const j = await res.json();
    expect(j.email).toBe('me-devices@example.com');
    expect(j.identities).toHaveLength(1);
    expect(j.identities[0].provider_type).toBe('oidc');
    expect(j.orgs[0].id).toBe(actor.orgId);
  });

  it('PATCH /me updates the name; email is identity-managed and ignored', async () => {
    const res = await fetch(`${t.baseUrl}/me`, {
      method: 'PATCH',
      headers: authHeader(actor.accessToken),
      body: JSON.stringify({ name: 'Test User', email: 'hacker@evil.com' }),
    });
    expect(res.status).toBe(200);
    expect((await res.json()).name).toBe('Test User');
    const check = await fetch(`${t.baseUrl}/me`, { headers: authHeader(actor.accessToken) });
    expect((await check.json()).email).toBe('me-devices@example.com'); // email unchanged
  });

  it('device register/list/delete is user-scoped', async () => {
    const reg = await fetch(`${t.baseUrl}/devices`, {
      method: 'POST',
      headers: authHeader(actor.accessToken),
      body: JSON.stringify({ platform: 'ios', token: 'fcm-token-1', app_version: '1.0' }),
    });
    expect(reg.status).toBe(201);
    const deviceId = (await reg.json()).id;

    const other = await onboard('me-devices-2', 'owner');
    const otherReg = await fetch(`${t.baseUrl}/devices`, {
      method: 'POST',
      headers: authHeader(other.accessToken),
      body: JSON.stringify({ platform: 'android', token: 'fcm-token-2' }),
    });
    expect(otherReg.status).toBe(201);

    // other user cannot see actor's devices
    const list = await fetch(`${t.baseUrl}/devices`, { headers: authHeader(other.accessToken) });
    expect((await list.json()).devices).toHaveLength(1);

    // other user cannot delete actor's device
    const del = await fetch(`${t.baseUrl}/devices/${deviceId}`, {
      method: 'DELETE',
      headers: authHeader(other.accessToken),
    });
    expect(del.status).toBe(404);

    // push without credentials is a graceful no-op
    const push = await sendToUser(t.db, t.config, actor.userId, { title: 'hi', body: 'test' });
    expect(push.configured).toBe(false);
    expect(push.attempted).toBe(1);
  });
});
