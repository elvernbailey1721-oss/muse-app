import type { Knex } from 'knex';
import { newId } from '../crypto.js';

export interface UserRow {
  id: string;
  email: string | null;
  name: string | null;
  avatar_url: string | null;
  disabled: number | boolean;
  created_at: string;
  updated_at: string;
}

export interface OrganizationRow {
  id: string;
  name: string;
  slug: string;
  domain: string | null;
  created_at: string;
  updated_at: string;
}

export type Role = 'owner' | 'admin' | 'member';

export interface MembershipRow {
  id: string;
  user_id: string;
  org_id: string;
  role: Role;
  created_at: string;
}

export interface ProviderRow {
  id: string;
  type: string;
  name: string;
  org_id: string | null;
  config_encrypted: string;
  enabled: number | boolean;
  created_at: string;
  updated_at: string;
}

export interface IdentityRow {
  id: string;
  user_id: string;
  provider_id: string;
  provider_sub: string;
  email: string | null;
  email_verified: number | boolean;
  revoked: number | boolean;
  linked_at: string;
  created_at: string;
  updated_at: string;
}

export interface RefreshTokenRow {
  id: string;
  user_id: string;
  family_id: string;
  token_hash: string;
  revoked: number | boolean;
  successor_hash: string | null;
  expires_at: string;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
}

export interface DeviceRow {
  id: string;
  user_id: string;
  platform: 'ios' | 'android';
  token: string;
  app_version: string | null;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

export interface ScanRow {
  id: string;
  user_id: string;
  org_id: string;
  name: string;
  colors_json: string;
  detected_color: string | null;
  thumbnail: string | null;
  captured_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AuditEventRow {
  id: string;
  actor_user_id: string | null;
  action: string;
  org_id: string | null;
  ip: string | null;
  user_agent: string | null;
  meta_json: string | null;
  created_at: string;
}

export interface AuthStateRow {
  id: string;
  state_hash: string;
  provider_key: string;
  code_verifier: string | null;
  nonce: string | null;
  redirect_uri: string | null;
  org_id: string | null;
  post_login_redirect: string | null;
  used: number | boolean;
  expires_at: string;
  created_at: string;
}

export function toBool(v: number | boolean | null | undefined): boolean {
  return v === true || v === 1;
}

export const Users = {
  async create(db: Knex, data: { email?: string | null; name?: string | null; avatar_url?: string | null }): Promise<UserRow> {
    const row: UserRow = {
      id: newId(),
      email: data.email ?? null,
      name: data.name ?? null,
      avatar_url: data.avatar_url ?? null,
      disabled: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    await db('users').insert(row);
    return row;
  },
  byId(db: Knex, id: string): Promise<UserRow | undefined> {
    return db('users').where({ id }).first();
  },
  byEmail(db: Knex, email: string): Promise<UserRow | undefined> {
    return db('users').whereRaw('LOWER(email) = LOWER(?)', [email]).first();
  },
  async update(db: Knex, id: string, patch: Partial<Pick<UserRow, 'name' | 'avatar_url' | 'email'>>): Promise<void> {
    await db('users')
      .where({ id })
      .update({ ...patch, updated_at: new Date().toISOString() });
  },
};

export const Organizations = {
  async create(db: Knex, data: { name: string; slug: string; domain?: string | null }): Promise<OrganizationRow> {
    const row = {
      id: newId(),
      name: data.name,
      slug: data.slug,
      domain: data.domain ? data.domain.toLowerCase() : null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    await db('organizations').insert(row);
    return row as OrganizationRow;
  },
  byId(db: Knex, id: string): Promise<OrganizationRow | undefined> {
    return db('organizations').where({ id }).first();
  },
  byDomain(db: Knex, domain: string): Promise<OrganizationRow | undefined> {
    return db('organizations').whereRaw('LOWER(domain) = LOWER(?)', [domain]).first();
  },
};

export const Memberships = {
  async create(db: Knex, userId: string, orgId: string, role: Role): Promise<MembershipRow> {
    const row = { id: newId(), user_id: userId, org_id: orgId, role, created_at: new Date().toISOString() };
    await db('org_memberships').insert(row);
    return row as MembershipRow;
  },
  byUserAndOrg(db: Knex, userId: string, orgId: string): Promise<MembershipRow | undefined> {
    return db('org_memberships').where({ user_id: userId, org_id: orgId }).first();
  },
  byUser(db: Knex, userId: string): Promise<MembershipRow[]> {
    return db('org_memberships').where({ user_id: userId }).orderBy('created_at', 'asc');
  },
  byOrg(db: Knex, orgId: string): Promise<MembershipRow[]> {
    return db('org_memberships').where({ org_id: orgId }).orderBy('created_at', 'asc');
  },
  async setRole(db: Knex, userId: string, orgId: string, role: Role): Promise<void> {
    await db('org_memberships').where({ user_id: userId, org_id: orgId }).update({ role });
  },
  async remove(db: Knex, userId: string, orgId: string): Promise<number> {
    return db('org_memberships').where({ user_id: userId, org_id: orgId }).del();
  },
};

export const Providers = {
  async create(
    db: Knex,
    data: { type: string; name: string; org_id: string | null; config_encrypted: string; enabled?: boolean },
  ): Promise<ProviderRow> {
    const row = {
      id: newId(),
      type: data.type,
      name: data.name,
      org_id: data.org_id,
      config_encrypted: data.config_encrypted,
      enabled: data.enabled ?? true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    await db('providers').insert(row);
    return row as ProviderRow;
  },
  byId(db: Knex, id: string): Promise<ProviderRow | undefined> {
    return db('providers').where({ id }).first();
  },
  /** Org-specific row first, then global row. */
  async resolve(db: Knex, type: string, orgId: string | null): Promise<ProviderRow | undefined> {
    if (orgId) {
      const orgRow = await db('providers').where({ type, org_id: orgId }).first();
      if (orgRow) return orgRow;
    }
    return db('providers').where({ type }).whereNull('org_id').first();
  },
  byOrg(db: Knex, orgId: string): Promise<ProviderRow[]> {
    return db('providers').where({ org_id: orgId }).orderBy('type', 'asc');
  },
  async update(db: Knex, id: string, patch: Partial<Pick<ProviderRow, 'config_encrypted' | 'enabled' | 'name'>>): Promise<void> {
    await db('providers')
      .where({ id })
      .update({ ...patch, updated_at: new Date().toISOString() });
  },
  async remove(db: Knex, id: string): Promise<number> {
    return db('providers').where({ id }).del();
  },
};

export const Identities = {
  async create(
    db: Knex,
    data: { user_id: string; provider_id: string; provider_sub: string; email?: string | null; email_verified?: boolean },
  ): Promise<IdentityRow> {
    const row = {
      id: newId(),
      user_id: data.user_id,
      provider_id: data.provider_id,
      provider_sub: data.provider_sub,
      email: data.email ?? null,
      email_verified: data.email_verified ?? false,
      revoked: false,
      linked_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    await db('identities').insert(row);
    return row as IdentityRow;
  },
  byProviderSub(db: Knex, providerId: string, providerSub: string): Promise<IdentityRow | undefined> {
    return db('identities').where({ provider_id: providerId, provider_sub: providerSub }).first();
  },
  byUser(db: Knex, userId: string): Promise<IdentityRow[]> {
    return db('identities').where({ user_id: userId }).orderBy('created_at', 'asc');
  },
  async touch(db: Knex, id: string, email: string | null, emailVerified: boolean): Promise<void> {
    await db('identities')
      .where({ id })
      .update({ email, email_verified: emailVerified, updated_at: new Date().toISOString() });
  },
};

export const RefreshTokens = {
  async create(
    db: Knex,
    data: { user_id: string; family_id: string; token_hash: string; expires_at: string; ip?: string | null; user_agent?: string | null },
  ): Promise<RefreshTokenRow> {
    const row = {
      id: newId(),
      user_id: data.user_id,
      family_id: data.family_id,
      token_hash: data.token_hash,
      revoked: false,
      successor_hash: null,
      expires_at: data.expires_at,
      ip: data.ip ?? null,
      user_agent: data.user_agent ?? null,
      created_at: new Date().toISOString(),
    };
    await db('refresh_tokens').insert(row);
    return row as RefreshTokenRow;
  },
  byHash(db: Knex, tokenHash: string): Promise<RefreshTokenRow | undefined> {
    return db('refresh_tokens').where({ token_hash: tokenHash }).first();
  },
  bySuccessor(db: Knex, successorHash: string): Promise<RefreshTokenRow | undefined> {
    return db('refresh_tokens').where({ successor_hash: successorHash }).first();
  },
  async revokeFamily(db: Knex, familyId: string): Promise<number> {
    return db('refresh_tokens').where({ family_id: familyId }).update({ revoked: true });
  },
  /** A family is active while it still has at least one live (unrevoked) token.
   *  Logout and reuse-detection revoke the whole family, which also kills
   *  outstanding access tokens bound to it. */
  async familyActive(db: Knex, familyId: string): Promise<boolean> {
    const row = await db('refresh_tokens')
      .where({ family_id: familyId })
      // Knex renders `false` per-dialect (0 on SQLite, FALSE on Postgres) —
      // keeps this portable; the IS NULL leg is a safety net for legacy rows.
      .where((qb) => qb.where({ revoked: false }).orWhereNull('revoked'))
      .first('id');
    return !!row;
  },
  async revokeUser(db: Knex, userId: string): Promise<number> {
    return db('refresh_tokens').where({ user_id: userId }).update({ revoked: true });
  },
};

export const Devices = {
  async upsert(
    db: Knex,
    data: { user_id: string; platform: 'ios' | 'android'; token: string; app_version?: string | null },
  ): Promise<DeviceRow> {
    const existing = await db('devices').where({ user_id: data.user_id, token: data.token }).first();
    const now = new Date().toISOString();
    if (existing) {
      await db('devices')
        .where({ id: existing.id })
        .update({ platform: data.platform, app_version: data.app_version ?? null, last_seen_at: now, updated_at: now });
      return { ...existing, platform: data.platform, app_version: data.app_version ?? null, last_seen_at: now, updated_at: now };
    }
    const row = {
      id: newId(),
      user_id: data.user_id,
      platform: data.platform,
      token: data.token,
      app_version: data.app_version ?? null,
      last_seen_at: now,
      created_at: now,
      updated_at: now,
    };
    await db('devices').insert(row);
    return row as DeviceRow;
  },
  byUser(db: Knex, userId: string): Promise<DeviceRow[]> {
    return db('devices').where({ user_id: userId }).orderBy('last_seen_at', 'desc');
  },
  byId(db: Knex, id: string): Promise<DeviceRow | undefined> {
    return db('devices').where({ id }).first();
  },
  async remove(db: Knex, id: string): Promise<number> {
    return db('devices').where({ id }).del();
  },
};

export interface ScanInput {
  name: string;
  colors: string[];
  detected_color?: string | null;
  thumbnail?: string | null;
  captured_at?: string | null;
}

export const Scans = {
  async create(db: Knex, userId: string, orgId: string, input: ScanInput): Promise<ScanRow> {
    const now = new Date().toISOString();
    const row = {
      id: newId(),
      user_id: userId,
      org_id: orgId,
      name: input.name,
      colors_json: JSON.stringify(input.colors),
      detected_color: input.detected_color ?? null,
      thumbnail: input.thumbnail ?? null,
      captured_at: input.captured_at ?? null,
      created_at: now,
      updated_at: now,
    };
    await db('scans').insert(row);
    return row as ScanRow;
  },
  /** Tenant isolation: always filtered by org_id from the session. */
  listByOrg(db: Knex, orgId: string, limit = 50, offset = 0): Promise<ScanRow[]> {
    return db('scans').where({ org_id: orgId }).orderBy('created_at', 'desc').limit(limit).offset(offset);
  },
  byIdInOrg(db: Knex, id: string, orgId: string): Promise<ScanRow | undefined> {
    return db('scans').where({ id, org_id: orgId }).first();
  },
  async remove(db: Knex, id: string, orgId: string): Promise<number> {
    return db('scans').where({ id, org_id: orgId }).del();
  },
};

export const AuditEvents = {
  async append(
    db: Knex,
    data: { actor_user_id?: string | null; action: string; org_id?: string | null; ip?: string | null; user_agent?: string | null; meta_json?: string | null },
  ): Promise<void> {
    await db('audit_events').insert({
      id: newId(),
      actor_user_id: data.actor_user_id ?? null,
      action: data.action,
      org_id: data.org_id ?? null,
      ip: data.ip ?? null,
      user_agent: data.user_agent ?? null,
      meta_json: data.meta_json ?? null,
      created_at: new Date().toISOString(),
    });
  },
  list(db: Knex, limit = 100): Promise<AuditEventRow[]> {
    return db('audit_events').orderBy('created_at', 'desc').limit(limit);
  },
};

export const AuthStates = {
  async create(
    db: Knex,
    data: { state_hash: string; provider_key: string; code_verifier?: string | null; nonce?: string | null; redirect_uri?: string | null; org_id?: string | null; post_login_redirect?: string | null; ttlSeconds?: number },
  ): Promise<AuthStateRow> {
    const now = Date.now();
    const row = {
      id: newId(),
      state_hash: data.state_hash,
      provider_key: data.provider_key,
      code_verifier: data.code_verifier ?? null,
      nonce: data.nonce ?? null,
      redirect_uri: data.redirect_uri ?? null,
      org_id: data.org_id ?? null,
      post_login_redirect: data.post_login_redirect ?? null,
      used: false,
      expires_at: new Date(now + (data.ttlSeconds ?? 600) * 1000).toISOString(),
      created_at: new Date(now).toISOString(),
    };
    await db('auth_states').insert(row);
    return row as AuthStateRow;
  },
  /** Atomically consume a state (single-use): returns the row only if unused and unexpired. */
  async consume(db: Knex, stateHash: string): Promise<AuthStateRow | undefined> {
    const now = new Date().toISOString();
    const row = await db('auth_states').where({ state_hash: stateHash }).first();
    if (!row || toBool(row.used)) return undefined;
    if (String(row.expires_at) < now) return undefined;
    const updated = await db('auth_states').where({ id: row.id, used: false }).update({ used: true });
    if (updated === 0) return undefined;
    return row as AuthStateRow;
  },
  async purgeExpired(db: Knex): Promise<number> {
    return db('auth_states').where('expires_at', '<', new Date().toISOString()).del();
  },
};

export const UsedAssertions = {
  /** Returns true if the assertion id was already seen (replay), false if newly recorded. */
  async checkAndRecord(db: Knex, assertionId: string, providerKey: string, ttlSeconds = 3600): Promise<boolean> {
    const existing = await db('used_assertions').where({ assertion_id: assertionId }).first();
    if (existing) return true;
    try {
      await db('used_assertions').insert({
        id: newId(),
        assertion_id: assertionId,
        provider_key: providerKey,
        expires_at: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
        created_at: new Date().toISOString(),
      });
    } catch {
      return true; // lost a race — treat as replay
    }
    return false;
  },
  async purgeExpired(db: Knex): Promise<number> {
    return db('used_assertions').where('expires_at', '<', new Date().toISOString()).del();
  },
};
