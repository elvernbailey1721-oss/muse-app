import { Router, type Request, type Response } from 'express';
import { randomToken, sha256Hex } from '../crypto.js';
import type { AppConfig, ProviderType } from '../config.js';
import { PROVIDER_TYPES } from '../config.js';
import {
  Memberships,
  Organizations,
  Users,
  toBool,
  type UserRow,
} from '../db/models.js';
import { audit } from '../services/audit.js';
import { authenticate, getClientIp, param, type RequestContext } from '../auth/middleware.js';
import { resolveProviderConfig, type EffectiveProviderConfig, type ProviderContext } from '../auth/providers.js';
import { providerRowForLogin, resolveUserForIdentity, LinkError } from '../auth/linking.js';
import { finishLogin, startLogin, LoginError, type VerifiedProfile } from '../auth/oidc.js';
import { finishSamlLogin, samlMetadata, startSamlLogin } from '../auth/samlSp.js';
import {
  createSession,
  issueAccessToken,
  revokeFamilyByToken,
  rotateRefreshToken,
} from '../auth/tokens.js';
import { RefreshTokens } from '../db/models.js';
import { isValidRole } from '../auth/roles.js';

function reqMeta(req: Request) {
  return { ip: getClientIp(req), userAgent: req.headers['user-agent'] ?? null };
}

function publicUser(user: UserRow) {
  return { id: user.id, email: user.email, name: user.name, avatar_url: user.avatar_url };
}

function validRedirect(config: AppConfig, redirect: string | undefined): string | null {
  // Exact-match only: the allowlist holds full URIs (scheme://host/path, e.g. a
  // mobile deep link like paintscope://auth/done) and the requested redirect
  // must equal one byte-for-byte. Origin-wide matching is deliberately NOT
  // used — an allowlisted origin would permit redirects to
  // attacker-influenced paths on that origin.
  if (!redirect) return null;
  try {
    new URL(redirect); // must at least parse as a URI (rejects javascript: etc. unless allowlisted)
    return config.redirectAllowlist.includes(redirect) ? redirect : null;
  } catch {
    return null;
  }
}

interface OrgBinding {
  orgId: string | null;
  role: string | null;
  orgName: string | null;
}

/**
 * Bind the session to an org. org_id NEVER comes from the client unchecked:
 * - fixedOrgId (SAML / org-scoped provider): membership required, or JIT
 *   provision when the provider explicitly allows it; otherwise fail closed.
 * - requestedOrgId: must be an existing membership, else first membership.
 */
async function bindOrg(
  pctx: ProviderContext,
  user: UserRow,
  requestedOrgId: string | null,
  fixedOrgId: string | null,
  meta: { ip?: string | null; userAgent?: string | null },
): Promise<OrgBinding> {
  // SSO authenticates only — it NEVER grants privileges. Org memberships are
  // created by explicit admin action (POST /orgs/:orgId/members); there is no
  // just-in-time provisioning. Org-scoped SSO without a membership fails closed.
  const { db } = pctx;
  if (fixedOrgId) {
    const membership = await Memberships.byUserAndOrg(db, user.id, fixedOrgId);
    if (membership) {
      const org = await Organizations.byId(db, fixedOrgId);
      return { orgId: fixedOrgId, role: membership.role, orgName: org?.name ?? null };
    }
    await audit(db, 'authz_denied', {
      actorUserId: user.id,
      orgId: fixedOrgId,
      ip: meta.ip,
      userAgent: meta.userAgent,
      meta: { reason: 'no_membership', detail: 'org-scoped SSO requires existing membership' },
    });
    throw new LinkError('no_org_membership', 'User is not a member of this organization', 403);
  }

  const memberships = await Memberships.byUser(db, user.id);
  if (memberships.length === 0) return { orgId: null, role: null, orgName: null };
  let chosen = memberships[0];
  if (requestedOrgId) {
    const match = memberships.find((m) => m.org_id === requestedOrgId);
    if (match) chosen = match;
  }
  const org = await Organizations.byId(db, chosen.org_id);
  return { orgId: chosen.org_id, role: chosen.role, orgName: org?.name ?? null };
}

/** Shared SSO completion: provider freshness, linking, org binding, session, audit. */
async function completeSsoLogin(
  rc: RequestContext,
  req: Request,
  res: Response,
  args: {
    eff: EffectiveProviderConfig;
    profile: VerifiedProfile;
    postLoginRedirect?: string | null;
    fixedOrgId?: string | null;
    requestedOrgId?: string | null;
  },
) {
  const { db, config } = rc;
  const meta = reqMeta(req);
  const pctx: ProviderContext = { db, config };

  // Stale/disabled provider check at login time (config may have changed mid-flow).
  const fresh = await resolveProviderConfig(pctx, args.eff.type, args.eff.orgId);
  if (!fresh.config) {
    await audit(db, 'login_failure', {
      ip: meta.ip,
      userAgent: meta.userAgent,
      meta: { provider_type: args.eff.type, reason: 'provider_disabled', detail: fresh.disabledReason },
    });
    res.status(401).json({ error: 'login_failed', message: 'Provider is disabled' });
    return;
  }

  const providerId = await providerRowForLogin(pctx, args.eff.orgId, args.eff.type, fresh.config.name);
  let outcome;
  try {
    outcome = await resolveUserForIdentity(pctx, providerId, fresh.config.allowEmailLink, args.profile, meta);
  } catch (err) {
    if (err instanceof LinkError) {
      await audit(db, 'login_failure', {
        ip: meta.ip,
        userAgent: meta.userAgent,
        meta: { provider_type: args.eff.type, reason: err.code, email: args.profile.email },
      });
      res.status(err.status).json({ error: 'login_failed', message: err.message });
      return;
    }
    throw err;
  }

  let binding: OrgBinding;
  try {
    binding = await bindOrg(pctx, outcome.user, args.requestedOrgId ?? null, args.fixedOrgId ?? null, meta);
  } catch (err) {
    if (err instanceof LinkError) {
      res.status(err.status).json({ error: 'login_failed', message: err.message });
      return;
    }
    throw err;
  }

  // Session fixation defense: brand-new refresh family on every login.
  const pair = await createSession(db, config.jwtSecret, outcome.user, binding.orgId, binding.role, meta);
  await audit(db, 'login', {
    actorUserId: outcome.user.id,
    orgId: binding.orgId,
    ip: meta.ip,
    userAgent: meta.userAgent,
    meta: {
      provider_type: args.eff.type,
      email: outcome.user.email,
      role: binding.role,
      detail: outcome.createdUser ? 'new_user' : outcome.linkedToExisting ? 'email_linked' : 'existing_identity',
    },
  });
  const payload = {
    access_token: pair.accessToken,
    refresh_token: pair.refreshToken,
    token_type: 'Bearer',
    expires_in: pair.expiresIn,
    user: publicUser(outcome.user),
    org: binding.orgId ? { id: binding.orgId, name: binding.orgName, role: binding.role } : null,
    // Client-side hint only: the exact-allowlisted ?redirect= URL from login start,
    // or null when none was requested.
    redirect: args.postLoginRedirect ?? null,
  };

  // Browser navigation with an allowlisted deep-link redirect: hand the tokens
  // to the native app via the bridge page instead of raw JSON.
  const accept = String(req.headers.accept ?? '');
  const wantsHtml = /(text\/html|application\/xhtml\+xml)/i.test(accept);
  if (args.postLoginRedirect && wantsHtml) {
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.set('Referrer-Policy', 'no-referrer');
    res.send(
      ssoBridgePage(args.postLoginRedirect, {
        accessToken: pair.accessToken,
        refreshToken: pair.refreshToken,
        expiresIn: pair.expiresIn,
      }),
    );
    return;
  }

  res.json(payload);
}

/**
 * Native-app login handoff page.
 *
 * When SSO login was started from a browser with an exact-allowlisted
 * ?redirect= deep link (e.g. paintscope://auth/done), the provider round-trip
 * ends with a browser navigation to the callback URL. This page hands the
 * freshly minted tokens to the app on the SAME device via that deep link.
 *
 * Security properties (all deliberate):
 * - Tokens travel in the URL FRAGMENT (#...), never the query string:
 *   fragments are never sent to any server, never appear in server logs, and
 *   are not transmitted on redirect.
 * - The deep-link target passed through validRedirect(): exact byte-for-byte
 *   match against the configured allowlist. No open redirects.
 * - Referrer-Policy: no-referrer so the token-bearing URL never leaks.
 * - Only served when the request explicitly accepts HTML (a real browser
 *   navigation). API/fetch clients keep the JSON shape below.
 */
function ssoBridgePage(redirect: string, tokens: { accessToken: string; refreshToken: string; expiresIn: number }): string {
  const esc = (s: string): string =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const frag = new URLSearchParams({
    access_token: tokens.accessToken,
    refresh_token: tokens.refreshToken,
    token_type: 'Bearer',
    expires_in: String(tokens.expiresIn),
  }).toString();
  const target = `${redirect}#${frag}`;
  const safe = esc(target);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Signed in — returning to PaintScope</title>
</head>
<body>
<p>Signed in. Returning to PaintScope…</p>
<p><a href="${safe}">Tap here if you are not redirected automatically</a>.</p>
<script>location.replace(${JSON.stringify(target)});</script>
</body>
</html>`;
}

function loginErrorStatus(err: LoginError): number {
  switch (err.code) {
    case 'missing_state':
    case 'missing_code':
    case 'missing_response':
      return 400;
    default:
      return 401;
  }
}

export function authRoutes(rc: RequestContext): Router {
  const r = Router();
  const { db, config } = rc;
  const pctx: ProviderContext = { db, config };
  const auth = authenticate(rc);

  const parseType = (v: string): ProviderType | null =>
    (PROVIDER_TYPES as string[]).includes(v) ? (v as ProviderType) : null;

  /** Public: which providers are available for login (no secrets). */
  r.get('/auth/providers', async (_req, res) => {
    const out: Array<{ type: string; name: string; login_url: string }> = [];
    for (const type of PROVIDER_TYPES) {
      if (type === 'saml') continue; // saml is per-org: use /auth/discover
      const { config: eff } = await resolveProviderConfig(pctx, type, null);
      if (eff) out.push({ type, name: eff.name, login_url: `/auth/login/${type}` });
    }
    res.json({ providers: out });
  });

  /** Domain-based SSO discovery: email -> org -> its enabled providers. */
  r.get('/auth/discover', async (req, res) => {
    const email = String(req.query.email ?? '');
    const domain = email.includes('@') ? email.split('@')[1].toLowerCase() : '';
    if (!domain) {
      res.status(400).json({ error: 'bad_request', message: 'Valid email required' });
      return;
    }
    const org = await Organizations.byDomain(db, domain);
    if (!org) {
      res.json({ org: null, providers: [] });
      return;
    }
    const providers: Array<{ type: string; name: string; login_url: string }> = [];
    for (const type of PROVIDER_TYPES) {
      const { config: eff } = await resolveProviderConfig(pctx, type, org.id);
      if (!eff) continue;
      providers.push({
        type,
        name: eff.name,
        login_url: type === 'saml' ? `/auth/saml/${org.id}/login` : `/auth/login/${type}?org_id=${org.id}`,
      });
    }
    res.json({ org: { id: org.id, name: org.name }, providers });
  });

  /** Begin OIDC/OAuth2 login. */
  r.get('/auth/login/:type', async (req, res) => {
    const type = parseType(param(req, 'type'));
    if (!type) {
      res.status(404).json({ error: 'not_found', message: 'Unknown provider' });
      return;
    }
    if (type === 'saml') {
      res.status(400).json({ error: 'bad_request', message: 'Use /auth/saml/:orgId/login for SAML' });
      return;
    }
    const orgId = typeof req.query.org_id === 'string' ? req.query.org_id : null;
    if (orgId && !(await Organizations.byId(db, orgId))) {
      res.status(400).json({ error: 'bad_request', message: 'Unknown org_id' });
      return;
    }
    const { config: eff, disabledReason } = await resolveProviderConfig(pctx, type, orgId);
    if (!eff) {
      await audit(db, 'login_failure', {
        ...reqMeta(req),
        meta: { provider_type: type, reason: 'provider_disabled', detail: disabledReason },
      });
      res.status(404).json({ error: 'not_found', message: 'Provider not enabled' });
      return;
    }
    try {
      const { url } = await startLogin({ db, config, eff }, {
        orgId,
        postLoginRedirect: validRedirect(config, typeof req.query.redirect === 'string' ? req.query.redirect : undefined),
      });
      res.redirect(302, url);
    } catch (err) {
      console.error('login start failed:', err);
      res.status(500).json({ error: 'server_error', message: 'Could not start login' });
    }
  });

  /** OIDC/OAuth2 callback (GET; Apple uses form_post so POST is accepted too). */
  const callbackHandler = async (req: Request, res: Response) => {
    const type = parseType(param(req, 'type'));
    if (!type || type === 'saml') {
      res.status(404).json({ error: 'not_found', message: 'Unknown provider' });
      return;
    }
    // Peek at the state row first (without consuming) to resolve org-specific
    // provider overrides; finishLogin consumes it single-use below.
    const rawState = String(req.query.state ?? req.body?.state ?? '');
    const stateRow = rawState
      ? await db('auth_states').where({ state_hash: sha256Hex(rawState) }).first()
      : null;
    const startOrg: string | null = stateRow?.org_id ?? null;
    const { config: eff, disabledReason } = await resolveProviderConfig(pctx, type, startOrg);
    if (!eff) {
      await audit(db, 'login_failure', { ...reqMeta(req), meta: { provider_type: type, reason: 'provider_disabled', detail: disabledReason } });
      res.status(401).json({ error: 'login_failed', message: 'Provider not enabled' });
      return;
    }
    try {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(req.query)) if (typeof v === 'string') params.set(k, v);
      if (req.body && typeof req.body === 'object') {
        for (const [k, v] of Object.entries(req.body)) if (typeof v === 'string') params.set(k, v);
      }
      const finished = await finishLogin({ db, config, eff }, params);
      await completeSsoLogin(rc, req, res, { eff, profile: finished.profile, postLoginRedirect: finished.postLoginRedirect, requestedOrgId: startOrg });
    } catch (err) {
      if (err instanceof LoginError) {
        await audit(db, 'login_failure', {
          ...reqMeta(req),
          meta: { provider_type: type, reason: err.code, detail: err.message },
        });
        res.status(loginErrorStatus(err)).json({ error: 'login_failed', message: err.message });
        return;
      }
      if (err instanceof LinkError) {
        res.status(err.status).json({ error: 'login_failed', message: err.message });
        return;
      }
      console.error('callback failed:', err);
      res.status(500).json({ error: 'server_error', message: 'Login failed' });
    }
  };
  r.get('/auth/callback/:type', callbackHandler);
  r.post('/auth/callback/:type', callbackHandler);

  /** Begin per-org SAML login. */
  r.get('/auth/saml/:orgId/login', async (req, res) => {
    const org = await Organizations.byId(db, param(req, 'orgId'));
    if (!org) {
      res.status(404).json({ error: 'not_found', message: 'Unknown organization' });
      return;
    }
    const { config: eff, disabledReason } = await resolveProviderConfig(pctx, 'saml', org.id);
    if (!eff) {
      res.status(404).json({ error: 'not_found', message: `SAML not enabled for this organization (${disabledReason ?? 'misconfigured'})` });
      return;
    }
    try {
      const url = await startSamlLogin(db, config, eff, org.id, randomToken(16));
      res.redirect(302, url);
    } catch (err) {
      console.error('saml login start failed:', err);
      res.status(500).json({ error: 'server_error', message: 'Could not start SAML login' });
    }
  });

  /** SAML Assertion Consumer Service. */
  r.post('/auth/saml/:orgId/acs', async (req, res) => {
    const org = await Organizations.byId(db, param(req, 'orgId'));
    if (!org) {
      res.status(404).json({ error: 'not_found', message: 'Unknown organization' });
      return;
    }
    const { config: eff } = await resolveProviderConfig(pctx, 'saml', org.id);
    if (!eff) {
      await audit(db, 'login_failure', { ...reqMeta(req), orgId: org.id, meta: { provider_type: 'saml', reason: 'provider_disabled' } });
      res.status(401).json({ error: 'login_failed', message: 'SAML not enabled for this organization' });
      return;
    }
    try {
      const body: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.body ?? {})) if (typeof v === 'string') body[k] = v;
      const profile = await finishSamlLogin(db, config, eff, org.id, body);
      await completeSsoLogin(rc, req, res, { eff, profile, fixedOrgId: org.id });
    } catch (err) {
      if (err instanceof LoginError) {
        await audit(db, 'login_failure', {
          ...reqMeta(req),
          orgId: org.id,
          meta: { provider_type: 'saml', reason: err.code, detail: err.message },
        });
        res.status(loginErrorStatus(err)).json({ error: 'login_failed', message: err.message });
        return;
      }
      if (err instanceof LinkError) {
        res.status(err.status).json({ error: 'login_failed', message: err.message });
        return;
      }
      console.error('saml acs failed:', err);
      res.status(500).json({ error: 'server_error', message: 'Login failed' });
    }
  });

  /** SP metadata for the org (given to the IdP admin during setup). */
  r.get('/auth/saml/:orgId/metadata', async (req, res) => {
    const { config: eff } = await resolveProviderConfig(pctx, 'saml', param(req, 'orgId'));
    if (!eff) {
      res.status(404).json({ error: 'not_found', message: 'SAML not enabled for this organization' });
      return;
    }
    const xml = await samlMetadata(db, config, eff, param(req, 'orgId'));
    res.type('application/xml').send(xml);
  });

  /** Rotate a refresh token. */
  r.post('/auth/refresh', async (req, res) => {
    const rawToken = typeof req.body?.refresh_token === 'string' ? req.body.refresh_token : '';
    if (!rawToken) {
      res.status(400).json({ error: 'bad_request', message: 'refresh_token required' });
      return;
    }
    const meta = reqMeta(req);
    const result = await rotateRefreshToken(db, rawToken, meta);
    if (!result.ok) {
      await audit(db, 'login_failure', {
        ...meta,
        meta: { reason: `refresh_${result.reason}`, detail: 'refresh token rotation failed' },
      });
      res.status(401).json({ error: 'invalid_grant', message: `Refresh failed: ${result.reason}` });
      return;
    }
    // Re-bind org from current memberships (never trust the old binding blindly).
    const requestedOrg = typeof req.body?.org_id === 'string' ? req.body.org_id : null;
    const binding = await bindOrg(pctx, result.user, requestedOrg, null, meta).catch(() => ({ orgId: null, role: null, orgName: null }));
    const accessToken = await issueAccessToken(config.jwtSecret, result.user, binding.orgId, binding.role, result.familyId);
    res.json({
      access_token: accessToken,
      refresh_token: result.refreshToken,
      token_type: 'Bearer',
      expires_in: 900,
      org: binding.orgId ? { id: binding.orgId, name: binding.orgName, role: binding.role } : null,
    });
  });

  /** Logout: revoke the refresh family (or everything) server-side. */
  r.post('/auth/logout', auth, async (req, res) => {
    const meta = reqMeta(req);
    const rawToken = typeof req.body?.refresh_token === 'string' ? req.body.refresh_token : null;
    if (rawToken) {
      await revokeFamilyByToken(db, rawToken);
    } else {
      await RefreshTokens.revokeUser(db, req.auth!.userId);
    }
    await audit(db, 'logout', { actorUserId: req.auth!.userId, orgId: req.auth!.org_id, ...meta });
    res.json({ ok: true });
  });

  /** Switch org context (issues a new org-bound token pair). */
  r.post('/auth/org', auth, async (req, res) => {
    const orgId = typeof req.body?.org_id === 'string' ? req.body.org_id : null;
    if (!orgId) {
      res.status(400).json({ error: 'bad_request', message: 'org_id required' });
      return;
    }
    const membership = await Memberships.byUserAndOrg(db, req.auth!.userId, orgId);
    if (!membership) {
      await audit(db, 'authz_denied', {
        actorUserId: req.auth!.userId,
        orgId,
        ...reqMeta(req),
        meta: { reason: 'no_membership', detail: 'org switch denied' },
      });
      res.status(403).json({ error: 'forbidden', message: 'Not a member of this organization' });
      return;
    }
    if (!isValidRole(membership.role)) {
      res.status(500).json({ error: 'server_error', message: 'Invalid role on membership' });
      return;
    }
    const user = await Users.byId(db, req.auth!.userId);
    if (!user || toBool(user.disabled)) {
      res.status(401).json({ error: 'unauthorized', message: 'Account disabled' });
      return;
    }
    const org = await Organizations.byId(db, orgId);
    // Org switch keeps the same session family (no new refresh token): the
    // client keeps its existing refresh token; logout still kills everything.
    const accessToken = await issueAccessToken(config.jwtSecret, user, orgId, membership.role, req.auth!.fid);
    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      org: { id: orgId, name: org?.name ?? null, role: membership.role },
    });
  });

  return r;
}
