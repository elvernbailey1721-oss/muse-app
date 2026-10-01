import type { Knex } from 'knex';
import type { AppConfig, ClaimMapping, ProviderEnvConfig, ProviderType } from '../config.js';
import { Providers, toBool } from '../db/models.js';
import { decryptSecret, encryptSecret } from '../crypto.js';

export interface ProviderEndpoints {
  authorization?: string;
  token?: string;
  userinfo?: string;
  jwks?: string;
  issuer?: string;
}

/** Decrypted operator-supplied config stored on a providers row. */
export interface DbProviderConfig {
  clientId?: string;
  clientSecret?: string;
  issuer?: string;
  tenantId?: string;
  scopes?: string[];
  allowEmailLink?: boolean;
  claimMapping?: ClaimMapping;
  endpoints?: ProviderEndpoints;
  skipDiscovery?: boolean;
  apple?: { teamId: string; keyId: string; privateKeyPem: string };
  saml?: SamlProviderConfig;
  enabled?: boolean;
}

export interface SamlProviderConfig {
  /** IdP SSO URL (entry point). */
  entryPoint: string;
  /** IdP signing certificate(s) — array enables rotation with kid selection. */
  idpCert: string | string[];
  /** Our SP entity ID. */
  spEntityId: string;
  /** Expected audience (defaults to spEntityId). */
  audience?: string;
  /** SAML NameID -> provider_sub. Defaults to NameID value. */
  nameIdClaim?: string;
  claimMapping?: ClaimMapping;
  /** Sign AuthnRequests (requires spPrivateKey + spCert). */
  wantAuthnRequestsSigned?: boolean;
  spPrivateKey?: string;
  spCert?: string;
}

/** Fully resolved, ready-to-use provider configuration. */
export interface EffectiveProviderConfig {
  key: string; // "<type>:<orgId|global>"
  type: ProviderType;
  orgId: string | null;
  providerId: string | null; // DB row id; null when env-only
  name: string;
  clientId?: string;
  clientSecret?: string;
  issuer?: string;
  discoveryUrl?: string;
  endpoints: ProviderEndpoints;
  skipDiscovery: boolean;
  scopes: string[];
  allowEmailLink: boolean;
  claimMapping?: ClaimMapping;
  apple?: { teamId: string; keyId: string; privateKeyPem: string };
  saml?: SamlProviderConfig;
  /** GitHub-style OAuth2: no discovery, no id_token — profile comes from userinfo. */
  oauth2Only: boolean;
}

export interface ProviderContext {
  db: Knex;
  config: AppConfig;
}

export function encryptProviderConfig(key: Buffer, cfg: DbProviderConfig): string {
  return encryptSecret(key, JSON.stringify(cfg));
}

export function decryptProviderConfig(key: Buffer, encrypted: string): DbProviderConfig {
  return JSON.parse(decryptSecret(key, encrypted)) as DbProviderConfig;
}

function prefixOf(type: ProviderType): string {
  return type.toUpperCase();
}

function envEndpoints(prefix: string): ProviderEndpoints | undefined {
  const p = (n: string) => process.env[`${prefix}_${n}`] || undefined;
  const authorization = p('AUTHORIZATION_ENDPOINT');
  const token = p('TOKEN_ENDPOINT');
  const userinfo = p('USERINFO_ENDPOINT');
  const jwks = p('JWKS_URI');
  if (!authorization && !token && !userinfo && !jwks) return undefined;
  return { authorization, token, userinfo, jwks };
}

function envSkipDiscovery(prefix: string): boolean {
  return ['1', 'true', 'yes'].includes((process.env[`${prefix}_SKIP_DISCOVERY`] ?? '').toLowerCase());
}

/**
 * Static, documentation-verified defaults per provider.
 * - Google:      OIDC discovery https://accounts.google.com/.well-known/openid-configuration
 * - Microsoft:   OIDC discovery https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration
 * - Apple:       OIDC discovery https://appleid.apple.com/.well-known/openid-configuration
 * - GitHub:      OAuth2 only — NO discovery document, NO id_token (verified 2026: still true);
 *                profile via https://api.github.com/user, verified emails via /user/emails; PKCE S256.
 * - LinkedIn:    OIDC discovery https://www.linkedin.com/oauth/.well-known/openid-configuration
 * - Okta/Auth0:  OIDC discovery <issuer>/.well-known/openid-configuration
 * - oidc:        generic — operator-supplied issuer or explicit endpoints
 * - saml:        DB-configured per organization only
 */
export function providerDefaults(type: ProviderType, env: ProviderEnvConfig): {
  discoveryUrl?: string;
  endpoints: ProviderEndpoints;
  oauth2Only: boolean;
} {
  const prefix = prefixOf(type);
  const ep = envEndpoints(prefix);
  switch (type) {
    case 'google':
      return { discoveryUrl: 'https://accounts.google.com/.well-known/openid-configuration', endpoints: ep ?? {}, oauth2Only: false };
    case 'microsoft': {
      // Tenant-specific discovery only: the "common" endpoint publishes a
      // templated issuer (https://login.microsoftonline.com/{tenantid}/v2.0)
      // that cannot validate tokens. resolveProviderConfig() fails closed
      // when no tenant id is configured.
      const tenant = env.tenantId;
      return {
        discoveryUrl: tenant
          ? `https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`
          : undefined,
        endpoints: ep ?? {},
        oauth2Only: false,
      };
    }
    case 'apple':
      // Apple publishes no OIDC discovery document; endpoints are documented
      // constants (verified 2026-09-29). skipDiscovery defaults to true.
      return {
        endpoints: {
          authorization: 'https://appleid.apple.com/auth/authorize',
          token: 'https://appleid.apple.com/auth/token',
          // No userinfo: Apple returns profile claims in the id_token itself.
          jwks: 'https://appleid.apple.com/auth/keys',
          issuer: 'https://appleid.apple.com',
          ...ep,
        },
        oauth2Only: false,
      };
    case 'github':
      return {
        endpoints: {
          authorization: ep?.authorization ?? 'https://github.com/login/oauth/authorize',
          token: ep?.token ?? 'https://github.com/login/oauth/access_token',
          userinfo: ep?.userinfo ?? 'https://api.github.com/user',
          ...ep,
        },
        oauth2Only: true,
      };
    case 'linkedin':
      return { discoveryUrl: 'https://www.linkedin.com/oauth/.well-known/openid-configuration', endpoints: ep ?? {}, oauth2Only: false };
    case 'okta':
    case 'auth0':
      return {
        discoveryUrl: env.issuer ? `${env.issuer.replace(/\/$/, '')}/.well-known/openid-configuration` : undefined,
        endpoints: ep ?? {},
        oauth2Only: false,
      };
    case 'oidc':
      return {
        discoveryUrl: env.issuer ? `${env.issuer.replace(/\/$/, '')}/.well-known/openid-configuration` : undefined,
        endpoints: ep ?? {},
        oauth2Only: false,
      };
    case 'saml':
      return { endpoints: {}, oauth2Only: false };
  }
}

export interface ResolveResult {
  config: EffectiveProviderConfig | null;
  /** Why resolution failed (for logging/audit — never leaks secrets). */
  disabledReason?: string;
}

/**
 * Resolve the effective config for a provider: org-specific DB row first,
 * then global DB row, then env config. Fail closed when disabled or when
 * required credentials are missing.
 */
export async function resolveProviderConfig(
  ctx: ProviderContext,
  type: ProviderType,
  orgId: string | null,
): Promise<ResolveResult> {
  const { db, config } = ctx;
  const env = config.providers[type];
  const key = `${type}:${orgId ?? 'global'}`;

  const row = await Providers.resolve(db, type, orgId);
  let dbCfg: DbProviderConfig | null = null;
  if (row) {
    try {
      dbCfg = decryptProviderConfig(config.configEncryptionKey, row.config_encrypted);
    } catch {
      return { config: null, disabledReason: 'provider config failed to decrypt' };
    }
    const rowEnabled = dbCfg.enabled ?? toBool(row.enabled);
    if (!rowEnabled) return { config: null, disabledReason: 'provider disabled (DB)' };
  } else if (!env.enabled) {
    return { config: null, disabledReason: 'provider disabled (env)' };
  }

  const defaults = providerDefaults(type, env);
  const eff: EffectiveProviderConfig = {
    key,
    type,
    orgId,
    providerId: row?.id ?? null,
    name: row?.name ?? `${type} (env)`,
    clientId: dbCfg?.clientId ?? env.clientId,
    clientSecret: dbCfg?.clientSecret ?? env.clientSecret,
    issuer: dbCfg?.issuer ?? env.issuer,
    discoveryUrl: defaults.discoveryUrl,
    endpoints: { ...defaults.endpoints, ...(dbCfg?.endpoints ?? {}), ...(env.endpoints ?? {}) },
    // Apple has no discovery document: skipDiscovery defaults to true there.
    skipDiscovery: dbCfg?.skipDiscovery ?? (type === 'apple' ? true : envSkipDiscovery(prefixOf(type))) ?? false,
    scopes: dbCfg?.scopes ?? env.scopes,
    allowEmailLink: dbCfg?.allowEmailLink ?? env.allowEmailLink,
    claimMapping: dbCfg?.claimMapping ?? env.claimMapping,
    apple: dbCfg?.apple ?? env.apple,
    saml: dbCfg?.saml,
    oauth2Only: defaults.oauth2Only,
  };

  // Credential completeness per provider (fail closed).
  if (type === 'saml') {
    if (!eff.saml?.entryPoint || !eff.saml?.idpCert || !eff.saml?.spEntityId) {
      return { config: null, disabledReason: 'saml provider missing entryPoint/idpCert/spEntityId' };
    }
    return { config: eff };
  }
  if (!eff.clientId) return { config: null, disabledReason: `missing ${prefixOf(type)}_CLIENT_ID` };
  if (type === 'apple') {
    if (!eff.apple) return { config: null, disabledReason: 'missing APPLE_TEAM_ID/APPLE_KEY_ID/APPLE_PRIVATE_KEY' };
  } else if (!eff.clientSecret) {
    return { config: null, disabledReason: `missing ${prefixOf(type)}_CLIENT_SECRET` };
  }
  if ((type === 'okta' || type === 'auth0' || type === 'oidc') && !eff.skipDiscovery) {
    if (!eff.issuer && !eff.discoveryUrl) {
      return { config: null, disabledReason: `missing ${prefixOf(type)}_ISSUER` };
    }
  }
  if (eff.skipDiscovery && (!eff.endpoints.authorization || !eff.endpoints.token)) {
    return { config: null, disabledReason: 'skipDiscovery requires explicit authorization/token endpoints' };
  }
  if (type === 'microsoft') {
    const tenantId = dbCfg?.tenantId ?? env.tenantId;
    if (!tenantId && !eff.skipDiscovery) {
      return {
        config: null,
        disabledReason:
          'microsoft requires MICROSOFT_TENANT_ID: the "common" endpoint publishes a templated issuer that cannot validate id_tokens',
      };
    }
    if (tenantId) {
      eff.discoveryUrl = `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`;
      if (!eff.issuer) eff.issuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;
    }
  }
  return { config: eff };
}

/** Ensure a providers row exists for an env-configured provider (FK target for identities). */
export async function ensureProviderRow(
  ctx: ProviderContext,
  orgId: string | null,
  type: string,
  name: string,
): Promise<string> {
  const { db, config } = ctx;
  const existing = await Providers.resolve(db, type, orgId);
  if (existing) return existing.id;
  try {
    const row = await Providers.create(db, {
      type,
      name,
      org_id: orgId,
      config_encrypted: encryptProviderConfig(config.configEncryptionKey, { envBacked: true } as unknown as DbProviderConfig),
      enabled: true,
    });
    return row.id;
  } catch {
    // Lost a race — re-read.
    const reread = await Providers.resolve(db, type, orgId);
    if (!reread) throw new Error('failed to ensure provider row');
    return reread.id;
  }
}

/** Persist an org-scoped provider row (encrypted at rest). Used by admin routes + tests. */
export async function saveOrgProvider(
  ctx: ProviderContext,
  orgId: string,
  type: ProviderType,
  name: string,
  cfg: DbProviderConfig,
  enabled = true,
) {
  const { db, config } = ctx;
  const existing = await db('providers').where({ type, org_id: orgId }).first();
  const encrypted = encryptProviderConfig(config.configEncryptionKey, cfg);
  if (existing) {
    await Providers.update(db, existing.id, { config_encrypted: encrypted, enabled, name });
    return existing.id;
  }
  const row = await Providers.create(db, { type, name, org_id: orgId, config_encrypted: encrypted, enabled });
  return row.id;
}
