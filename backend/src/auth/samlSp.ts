import { SAML, ValidateInResponseTo, type CacheProvider, type Profile, type SamlConfig } from '@node-saml/node-saml';
import type { Knex } from 'knex';
import type { AppConfig } from '../config.js';
import { UsedAssertions } from '../db/models.js';
import { newId } from '../crypto.js';
import { applyClaimMapping, type VerifiedProfile } from './oidc.js';
import type { EffectiveProviderConfig } from './providers.js';
import { LoginError } from './oidc.js';

/**
 * DB-backed CacheProvider so AuthnRequest IDs survive restarts and work
 * across instances. Enables strict InResponseTo validation (replay of a
 * captured Response against a different request is rejected).
 */
export function dbCacheProvider(db: Knex): CacheProvider {
  return {
    async saveAsync(key: string, value: string) {
      const expiresAt = new Date(Date.now() + 8 * 3600 * 1000).toISOString();
      await db('used_assertions')
        .insert({
          id: newId(),
          assertion_id: `saml-req:${key}`,
          provider_key: 'saml-request',
          expires_at: expiresAt,
          created_at: new Date().toISOString(),
        })
        .onConflict('assertion_id')
        .merge({ expires_at: expiresAt });
      return { value, createdAt: Date.now() };
    },
    async getAsync(key: string) {
      const row = await db('used_assertions').where({ assertion_id: `saml-req:${key}` }).first();
      if (!row) return null;
      if (String(row.expires_at) < new Date().toISOString()) return null;
      return row.provider_key;
    },
    async removeAsync(key: string | null) {
      if (!key) return null;
      const row = await db('used_assertions').where({ assertion_id: `saml-req:${key}` }).first();
      await db('used_assertions').where({ assertion_id: `saml-req:${key}` }).del();
      return row ? row.provider_key : null;
    },
  };
}

function acsUrl(config: AppConfig, orgId: string): string {
  return `${config.appBaseUrl}/auth/saml/${orgId}/acs`;
}

export function buildSamlInstance(db: Knex, config: AppConfig, eff: EffectiveProviderConfig, orgId: string): SAML {
  const samlCfg = eff.saml!;
  const options: SamlConfig = {
    // IdP material
    entryPoint: samlCfg.entryPoint,
    idpCert: samlCfg.idpCert,
    issuer: samlCfg.spEntityId, // our SP entity ID
    callbackUrl: acsUrl(config, orgId),
    // Security: strict checks
    validateInResponseTo: ValidateInResponseTo.always,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
    acceptedClockSkewMs: 5 * 60 * 1000,
    cacheProvider: dbCacheProvider(db),
    audience: samlCfg.audience ?? samlCfg.spEntityId,
    additionalParams: {},
    additionalAuthorizeParams: {},
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    allowCreate: true,
  };
  if (samlCfg.wantAuthnRequestsSigned && samlCfg.spPrivateKey) {
    // Presence of privateKey makes getAuthorizeUrlAsync sign the AuthnRequest.
    options.privateKey = samlCfg.spPrivateKey;
    if (samlCfg.spCert) options.publicCert = samlCfg.spCert;
    options.signatureAlgorithm = 'sha256';
  }
  return new SAML(options);
}

/** Begin SP-initiated SSO: returns the IdP redirect URL. */
export async function startSamlLogin(
  db: Knex,
  config: AppConfig,
  eff: EffectiveProviderConfig,
  orgId: string,
  relayState: string,
): Promise<string> {
  const saml = buildSamlInstance(db, config, eff, orgId);
  return saml.getAuthorizeUrlAsync(relayState, undefined, {});
}

function profileToClaims(profile: Profile, nameIdClaim?: string): Record<string, unknown> {
  const attrs = (profile.attributes ?? {}) as Record<string, unknown>;
  const claims: Record<string, unknown> = { ...attrs };
  // Subject precedence: operator-configured stable attribute FIRST, then a
  // persistent NameID. Transient NameIDs (per-session, non-correlatable) are
  // rejected unless the operator configured a stable subject attribute —
  // otherwise accounts would be orphaned or mis-linked across sessions.
  const isTransient = /transient/i.test(profile.nameIDFormat ?? '');
  let sub: string | null = null;
  if (nameIdClaim && typeof attrs[nameIdClaim] === 'string' && (attrs[nameIdClaim] as string).trim()) {
    sub = (attrs[nameIdClaim] as string).trim();
  } else if (!isTransient && profile.nameID) {
    sub = profile.nameID;
  }
  if (!sub) {
    throw new LoginError(
      'saml_unstable_subject',
      'SAML subject is not stable: configure the provider `nameIdClaim` to a persistent attribute or use a persistent NameID format',
    );
  }
  claims.sub = sub;
  // Common attribute name fallbacks.
  const first = (...keys: string[]): unknown => {
    for (const k of keys) if (claims[k] !== undefined) return claims[k];
    return undefined;
  };
  claims.email ??= first('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', 'email', 'mail');
  claims.name ??= first('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', 'displayName', 'name');
  claims.given_name ??= first('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', 'givenName');
  claims.family_name ??= first('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname', 'sn');
  return claims;
}

function extractResponseId(samlResponseB64: string): string | null {
  try {
    const xml = Buffer.from(samlResponseB64, 'base64').toString('utf8');
    const m = xml.match(/<saml2p?:Response[^>]*\bID="([^"]+)"/) ?? xml.match(/<Response[^>]*\bID="([^"]+)"/);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

/** Validate the ACS POST: signature, audience, expiry, InResponseTo, replay. */
export async function finishSamlLogin(
  db: Knex,
  config: AppConfig,
  eff: EffectiveProviderConfig,
  orgId: string,
  body: Record<string, string>,
): Promise<VerifiedProfile> {
  const samlResponse = body.SAMLResponse;
  if (!samlResponse) throw new LoginError('missing_response', 'Missing SAMLResponse');

  // Replay protection on the Response ID before/after validation.
  const responseId = extractResponseId(samlResponse);
  if (responseId) {
    const replayed = await UsedAssertions.checkAndRecord(db, `saml:${eff.key}:${responseId}`, eff.key, 3600);
    if (replayed) throw new LoginError('replay_detected', 'SAML Response already processed');
  }

  const saml = buildSamlInstance(db, config, eff, orgId);
  let profile: Profile | null;
  try {
    ({ profile } = await saml.validatePostResponseAsync({ SAMLResponse: samlResponse }));
  } catch (err) {
    throw new LoginError('saml_validation_failed', err instanceof Error ? err.message : 'SAML validation failed');
  }
  if (!profile) throw new LoginError('saml_validation_failed', 'No profile in SAML response');
  if (!profile.nameID) throw new LoginError('saml_missing_nameid', 'SAML response missing NameID');

  const claims = profileToClaims(profile, eff.saml?.nameIdClaim);
  const mapped = applyClaimMapping(eff.saml?.claimMapping, claims);
  // SAML email_verified is IdP-asserted; treat presence of a mapped email as verified
  // only when the IdP says so. Default: unverified (fail closed on linking).
  return mapped;
}

/** SP metadata XML for the org (hand to the IdP admin during setup). */
export async function samlMetadata(db: Knex, config: AppConfig, eff: EffectiveProviderConfig, orgId: string): Promise<string> {
  const saml = buildSamlInstance(db, config, eff, orgId);
  return saml.generateServiceProviderMetadata(null, eff.saml?.spCert ?? null);
}
