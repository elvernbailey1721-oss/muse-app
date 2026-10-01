import { Router } from 'express';
import type { ProviderType } from '../config.js';
import { PROVIDER_TYPES } from '../config.js';
import { Memberships, Organizations, Providers, Users, toBool } from '../db/models.js';
import { audit } from '../services/audit.js';
import { authenticate, getClientIp, param, requireOrgRole, type RequestContext } from '../auth/middleware.js';
import { assertValidRole } from '../auth/roles.js';
import {
  decryptProviderConfig,
  encryptProviderConfig,
  saveOrgProvider,
  type DbProviderConfig,
} from '../auth/providers.js';

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;

function sanitizeProviderRow(row: {
  id: string;
  type: string;
  name: string;
  org_id: string | null;
  enabled: number | boolean;
  created_at: string;
  updated_at: string;
}) {
  return {
    id: row.id,
    type: row.type,
    name: row.name,
    org_id: row.org_id,
    enabled: toBool(row.enabled),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function validateProviderConfig(type: string, cfg: unknown): { ok: true; cfg: DbProviderConfig } | { ok: false; message: string } {
  if (!cfg || typeof cfg !== 'object') return { ok: false, message: 'config must be an object' };
  const c = cfg as Record<string, unknown>;
  if (type === 'saml') {
    const saml = c.saml as Record<string, unknown> | undefined;
    if (!saml || typeof saml !== 'object') return { ok: false, message: 'config.saml is required' };
    if (typeof saml.entryPoint !== 'string' || !saml.entryPoint) return { ok: false, message: 'config.saml.entryPoint required' };
    if (!saml.idpCert) return { ok: false, message: 'config.saml.idpCert required' };
    if (typeof saml.spEntityId !== 'string' || !saml.spEntityId) return { ok: false, message: 'config.saml.spEntityId required' };
  } else {
    if (typeof c.clientId !== 'string' || !c.clientId) return { ok: false, message: 'config.clientId required' };
    if (type !== 'apple' && typeof c.clientSecret !== 'string' && !(c as { skipDiscovery?: boolean }).skipDiscovery) {
      return { ok: false, message: 'config.clientSecret required' };
    }
    if (type === 'apple' && !(c.apple && typeof c.apple === 'object')) {
      return { ok: false, message: 'config.apple signing material required' };
    }
    if ((type === 'okta' || type === 'auth0' || type === 'oidc') && typeof c.issuer !== 'string' && !c.endpoints) {
      return { ok: false, message: 'config.issuer or config.endpoints required' };
    }
  }
  if (c.allowEmailLink !== undefined && typeof c.allowEmailLink !== 'boolean') {
    return { ok: false, message: 'config.allowEmailLink must be boolean' };
  }
  return { ok: true, cfg: c as unknown as DbProviderConfig };
}

export function adminRoutes(rc: RequestContext): Router {
  const r = Router();
  const { db, config } = rc;
  const auth = authenticate(rc);
  const memberOf = requireOrgRole(rc, 'member');
  const adminOf = requireOrgRole(rc, 'admin');
  const ownerOf = requireOrgRole(rc, 'owner');

  /** Create an organization; caller becomes owner. */
  r.post('/orgs', auth, async (req, res) => {
    const { name, slug, domain } = req.body ?? {};
    if (typeof name !== 'string' || !name || name.length > 200) {
      res.status(400).json({ error: 'bad_request', message: 'name required' });
      return;
    }
    if (typeof slug !== 'string' || !SLUG_RE.test(slug)) {
      res.status(400).json({ error: 'bad_request', message: 'slug must match [a-z0-9-]' });
      return;
    }
    if (domain !== undefined && (typeof domain !== 'string' || domain.length > 253)) {
      res.status(400).json({ error: 'bad_request', message: 'Invalid domain' });
      return;
    }
    try {
      const org = await Organizations.create(db, { name, slug, domain: domain ?? null });
      await Memberships.create(db, req.auth!.userId, org.id, 'owner');
      res.status(201).json({ id: org.id, name: org.name, slug: org.slug, domain: org.domain });
    } catch {
      res.status(409).json({ error: 'conflict', message: 'slug or domain already taken' });
    }
  });

  r.get('/orgs/:orgId', auth, memberOf, async (req, res) => {
    const org = await Organizations.byId(db, param(req, 'orgId'));
    if (!org) {
      res.status(404).json({ error: 'not_found', message: 'Organization not found' });
      return;
    }
    res.json({ id: org.id, name: org.name, slug: org.slug, domain: org.domain, role: req.orgMembership!.role });
  });

  r.patch('/orgs/:orgId', auth, adminOf, async (req, res) => {
    const { name, domain } = req.body ?? {};
    const patch: { name?: string; domain?: string | null } = {};
    if (name !== undefined) {
      if (typeof name !== 'string' || !name || name.length > 200) {
        res.status(400).json({ error: 'bad_request', message: 'Invalid name' });
        return;
      }
      patch.name = name;
    }
    if (domain !== undefined) {
      if (domain !== null && (typeof domain !== 'string' || domain.length > 253)) {
        res.status(400).json({ error: 'bad_request', message: 'Invalid domain' });
        return;
      }
      patch.domain = domain ? domain.toLowerCase() : null;
    }
    try {
      await db('organizations').where({ id: param(req, 'orgId') }).update({ ...patch, updated_at: new Date().toISOString() });
      const org = await Organizations.byId(db, param(req, 'orgId'));
      res.json({ id: org!.id, name: org!.name, slug: org!.slug, domain: org!.domain });
    } catch {
      res.status(409).json({ error: 'conflict', message: 'domain already taken' });
    }
  });

  r.get('/orgs/:orgId/members', auth, memberOf, async (req, res) => {
    const members = await Memberships.byOrg(db, param(req, 'orgId'));
    const out = [];
    for (const m of members) {
      const u = await Users.byId(db, m.user_id);
      out.push({ user_id: m.user_id, email: u?.email ?? null, name: u?.name ?? null, role: m.role, created_at: m.created_at });
    }
    res.json({ members: out });
  });

  /** Add a member. Granting owner requires the caller to be owner. */
  r.post('/orgs/:orgId/members', auth, adminOf, async (req, res) => {
    const { user_id, role } = req.body ?? {};
    try {
      assertValidRole(role);
    } catch {
      res.status(400).json({ error: 'bad_request', message: 'role must be owner|admin|member' });
      return;
    }
    if (role === 'owner' && req.orgMembership!.role !== 'owner') {
      await audit(db, 'authz_denied', {
        actorUserId: req.auth!.userId,
        orgId: param(req, 'orgId'),
        ip: getClientIp(req),
        userAgent: req.headers['user-agent'] ?? null,
        meta: { reason: 'owner_grant_denied', detail: 'only owners can grant owner' },
      });
      res.status(403).json({ error: 'forbidden', message: 'Only owners can grant the owner role' });
      return;
    }
    if (typeof user_id !== 'string' || !user_id) {
      res.status(400).json({ error: 'bad_request', message: 'user_id required' });
      return;
    }
    const user = await Users.byId(db, user_id);
    if (!user || toBool(user.disabled)) {
      res.status(404).json({ error: 'not_found', message: 'User not found' });
      return;
    }
    const existing = await Memberships.byUserAndOrg(db, user_id, param(req, 'orgId'));
    if (existing) {
      res.status(409).json({ error: 'conflict', message: 'Already a member' });
      return;
    }
    await Memberships.create(db, user_id, param(req, 'orgId'), role);
    res.status(201).json({ user_id, role });
  });

  /**
   * Change a member's role. SSO NEVER grants roles — this explicit owner-only
   * action is the only privilege path (privilege-escalation defense).
   */
  r.patch('/orgs/:orgId/members/:userId', auth, ownerOf, async (req, res) => {
    const { role } = req.body ?? {};
    try {
      assertValidRole(role);
    } catch {
      res.status(400).json({ error: 'bad_request', message: 'role must be owner|admin|member' });
      return;
    }
    const target = await Memberships.byUserAndOrg(db, param(req, 'userId'), param(req, 'orgId'));
    if (!target) {
      res.status(404).json({ error: 'not_found', message: 'Membership not found' });
      return;
    }
    if (target.role === 'owner' && role !== 'owner') {
      const owners = (await Memberships.byOrg(db, param(req, 'orgId'))).filter((m) => m.role === 'owner');
      if (owners.length <= 1) {
        res.status(409).json({ error: 'conflict', message: 'Cannot demote the last owner' });
        return;
      }
    }
    await Memberships.setRole(db, param(req, 'userId'), param(req, 'orgId'), role);
    res.json({ user_id: param(req, 'userId'), role });
  });

  r.delete('/orgs/:orgId/members/:userId', auth, adminOf, async (req, res) => {
    const target = await Memberships.byUserAndOrg(db, param(req, 'userId'), param(req, 'orgId'));
    if (!target) {
      res.status(404).json({ error: 'not_found', message: 'Membership not found' });
      return;
    }
    if (target.role === 'owner') {
      const owners = (await Memberships.byOrg(db, param(req, 'orgId'))).filter((m) => m.role === 'owner');
      if (owners.length <= 1) {
        res.status(409).json({ error: 'conflict', message: 'Cannot remove the last owner' });
        return;
      }
      if (req.orgMembership!.role !== 'owner') {
        res.status(403).json({ error: 'forbidden', message: 'Only owners can remove an owner' });
        return;
      }
    }
    await Memberships.remove(db, param(req, 'userId'), param(req, 'orgId'));
    res.json({ ok: true });
  });

  // ---- Provider configs (org-scoped; secrets encrypted at rest, never returned) ----

  r.get('/orgs/:orgId/providers', auth, adminOf, async (req, res) => {
    const rows = await Providers.byOrg(db, param(req, 'orgId'));
    res.json({ providers: rows.map(sanitizeProviderRow) });
  });

  r.post('/orgs/:orgId/providers', auth, adminOf, async (req, res) => {
    const { type, name, config: cfg, enabled } = req.body ?? {};
    if (!(PROVIDER_TYPES as string[]).includes(type)) {
      res.status(400).json({ error: 'bad_request', message: 'Invalid provider type' });
      return;
    }
    if (typeof name !== 'string' || !name || name.length > 200) {
      res.status(400).json({ error: 'bad_request', message: 'name required' });
      return;
    }
    const v = validateProviderConfig(type, cfg);
    if (!v.ok) {
      res.status(400).json({ error: 'bad_request', message: v.message });
      return;
    }
    const meta = { ip: getClientIp(req), userAgent: req.headers['user-agent'] ?? null };
    try {
      const id = await saveOrgProvider({ db, config }, param(req, 'orgId'), type as ProviderType, name, v.cfg, enabled ?? true);
      await audit(db, 'provider_config_changed', {
        actorUserId: req.auth!.userId,
        orgId: param(req, 'orgId'),
        ...meta,
        meta: { provider_type: type, provider_name: name, detail: 'provider_created_or_updated' },
      });
      res.status(201).json({ id });
    } catch {
      res.status(500).json({ error: 'server_error', message: 'Could not save provider' });
    }
  });

  r.patch('/orgs/:orgId/providers/:providerId', auth, adminOf, async (req, res) => {
    const row = await Providers.byId(db, param(req, 'providerId'));
    if (!row || row.org_id !== param(req, 'orgId')) {
      res.status(404).json({ error: 'not_found', message: 'Provider not found' });
      return;
    }
    const patch: { name?: string; enabled?: boolean; config_encrypted?: string } = {};
    if (req.body.name !== undefined) {
      if (typeof req.body.name !== 'string' || !req.body.name || req.body.name.length > 200) {
        res.status(400).json({ error: 'bad_request', message: 'Invalid name' });
        return;
      }
      patch.name = req.body.name;
    }
    if (req.body.enabled !== undefined) {
      if (typeof req.body.enabled !== 'boolean') {
        res.status(400).json({ error: 'bad_request', message: 'enabled must be boolean' });
        return;
      }
      patch.enabled = req.body.enabled;
    }
    if (req.body.config !== undefined) {
      // Merge with existing config so secrets not re-sent are preserved;
      // secrets are re-encrypted at rest and never echoed back.
      const existing = decryptProviderConfig(config.configEncryptionKey, row.config_encrypted);
      const merged = { ...existing, ...(req.body.config as Record<string, unknown>) };
      const v = validateProviderConfig(row.type, merged);
      if (!v.ok) {
        res.status(400).json({ error: 'bad_request', message: v.message });
        return;
      }
      patch.config_encrypted = encryptProviderConfig(config.configEncryptionKey, v.cfg);
    }
    await Providers.update(db, row.id, patch);
    await audit(db, 'provider_config_changed', {
      actorUserId: req.auth!.userId,
      orgId: param(req, 'orgId'),
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'] ?? null,
      meta: { provider_type: row.type, provider_name: row.name, detail: 'provider_updated' },
    });
    res.json({ ok: true });
  });

  r.delete('/orgs/:orgId/providers/:providerId', auth, adminOf, async (req, res) => {
    const row = await Providers.byId(db, param(req, 'providerId'));
    if (!row || row.org_id !== param(req, 'orgId')) {
      res.status(404).json({ error: 'not_found', message: 'Provider not found' });
      return;
    }
    await Providers.remove(db, row.id);
    await audit(db, 'provider_config_changed', {
      actorUserId: req.auth!.userId,
      orgId: param(req, 'orgId'),
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'] ?? null,
      meta: { provider_type: row.type, provider_name: row.name, detail: 'provider_deleted' },
    });
    res.json({ ok: true });
  });

  return r;
}
