import * as jose from 'jose';
import {
  Configuration,
  allowInsecureRequests,
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  discovery,
  fetchUserInfo,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
  type ServerMetadata,
} from 'openid-client';
import type { Knex } from 'knex';
import type { AppConfig, ClaimMapping } from '../config.js';
import { AuthStates, UsedAssertions } from '../db/models.js';
import { sha256Hex } from '../crypto.js';
import type { EffectiveProviderConfig } from './providers.js';

export interface LoginStart {
  url: string;
  state: string;
}

export interface VerifiedProfile {
  sub: string;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
  givenName: string | null;
  familyName: string | null;
  avatarUrl: string | null;
  raw: Record<string, unknown>;
}

export interface LoginContext {
  db: Knex;
  config: AppConfig;
  eff: EffectiveProviderConfig;
}

function callbackUrl(config: AppConfig, eff: EffectiveProviderConfig): string {
  return `${config.appBaseUrl}/auth/callback/${eff.type}`;
}

async function appleClientSecret(eff: EffectiveProviderConfig): Promise<string> {
  const apple = eff.apple;
  if (!apple || !eff.clientId) throw new Error('Apple provider misconfigured');
  const key = await jose.importPKCS8(apple.privateKeyPem, 'ES256');
  // Apple requires a short-lived ES256 JWT as client_secret (max 6 months).
  return new jose.SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: apple.keyId })
    .setIssuer(apple.teamId)
    .setSubject(eff.clientId)
    .setAudience('https://appleid.apple.com')
    .setIssuedAt()
    .setExpirationTime('10m')
    .sign(key);
}

async function clientSecretFor(eff: EffectiveProviderConfig): Promise<string | undefined> {
  if (eff.type === 'apple') return appleClientSecret(eff);
  return eff.clientSecret;
}

/**
 * Build an openid-client Configuration: via OIDC discovery (HTTPS, issuer
 * validated by the library against the discovery document — issuer-confusion
 * protection), or from explicit operator-configured endpoints (skipDiscovery).
 */
export async function buildClientConfiguration(eff: EffectiveProviderConfig): Promise<Configuration> {
  const secret = await clientSecretFor(eff);
  if (!eff.skipDiscovery && eff.discoveryUrl) {
    return discovery(new URL(eff.discoveryUrl), eff.clientId!, secret);
  }
  const issuer =
    eff.issuer ??
    eff.endpoints.issuer ??
    (eff.discoveryUrl ? eff.discoveryUrl.replace(/\/\.well-known\/openid-configuration$/, '') : undefined) ??
    'https://localhost/mock-issuer';
  const server: ServerMetadata = {
    issuer,
    authorization_endpoint: eff.endpoints.authorization!,
    token_endpoint: eff.endpoints.token!,
    userinfo_endpoint: eff.endpoints.userinfo,
    jwks_uri: eff.endpoints.jwks,
  };
  const config = new Configuration(server, eff.clientId!, secret);
  // TEST-ONLY escape hatch: openid-client enforces HTTPS for all IdP traffic.
  // Local mock issuers in the test suite are plain HTTP. Enabled ONLY when
  // OIDC_TEST_ALLOW_HTTP=1 (never set in production; .env.example warns).
  if (process.env.OIDC_TEST_ALLOW_HTTP === '1') {
    allowInsecureRequests(config);
  }
  return config;
}

/** Begin the authorization-code flow. State/nonce/PKCE verifier stored single-use in DB. */
export async function startLogin(
  ctx: LoginContext,
  opts: { orgId?: string | null; postLoginRedirect?: string | null } = {},
): Promise<LoginStart> {
  const { db, config, eff } = ctx;
  const state = randomState();
  const nonce = eff.oauth2Only ? null : randomNonce();
  const codeVerifier = randomPKCECodeVerifier();
  const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
  const redirectUri = callbackUrl(config, eff);

  await AuthStates.create(db, {
    state_hash: sha256Hex(state),
    provider_key: eff.key,
    code_verifier: codeVerifier,
    nonce,
    redirect_uri: redirectUri,
    org_id: opts.orgId ?? null,
    post_login_redirect: opts.postLoginRedirect ?? null,
  });

  if (eff.oauth2Only) {
    // GitHub-style OAuth2: manual authorization URL (no id_token involved).
    const params = new URLSearchParams({
      client_id: eff.clientId!,
      redirect_uri: redirectUri,
      state,
      scope: eff.scopes.join(' '),
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });
    return { url: `${eff.endpoints.authorization}?${params.toString()}`, state };
  }

  const cfg = await buildClientConfiguration(eff);
  const params: Record<string, string> = {
    redirect_uri: redirectUri,
    scope: eff.scopes.join(' '),
    state,
    nonce: nonce!,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    response_type: 'code',
  };
  // Apple forces form_post when scopes are requested — our callback accepts POST.
  const url = buildAuthorizationUrl(cfg, params);
  return { url: url.toString(), state };
}

/** Apply configurable claim mapping (IdP claims -> profile fields). */
export function applyClaimMapping(mapping: ClaimMapping | undefined, claims: Record<string, unknown>): VerifiedProfile {
  const m = mapping ?? {};
  const pick = (key: keyof ClaimMapping, fallback: string): unknown =>
    claims[m[key] ?? fallback] ?? claims[fallback];
  const sub = pick('sub', 'sub');
  if (typeof sub !== 'string' || !sub) throw new Error('IdP response missing sub claim');
  const emailVerifiedRaw = pick('emailVerified', 'email_verified');
  const email = pick('email', 'email');
  return {
    sub,
    email: typeof email === 'string' ? email : null,
    emailVerified: emailVerifiedRaw === true || emailVerifiedRaw === 'true' || emailVerifiedRaw === 1,
    name: asString(pick('name', 'name')),
    givenName: asString(pick('givenName', 'given_name')),
    familyName: asString(pick('familyName', 'family_name')),
    avatarUrl: asString(pick('avatar', 'picture')),
    raw: claims,
  };
}

function asString(v: unknown): string | null {
  return typeof v === 'string' && v ? v : null;
}

/**
 * Complete the flow: validate state (single-use, CSRF), exchange the code with
 * PKCE, and validate the id_token (issuer/audience/signature/JWKS/expiry/nonce
 * — all enforced by openid-client). Returns the verified profile.
 */
export interface FinishedLogin {
  profile: VerifiedProfile;
  /** Exact-allowlisted post-login redirect, or null when none was requested. */
  postLoginRedirect: string | null;
}

export async function finishLogin(ctx: LoginContext, callbackParams: URLSearchParams): Promise<FinishedLogin> {
  const { db, config, eff } = ctx;
  const state = callbackParams.get('state');
  if (!state) throw new LoginError('missing_state', 'Authorization response missing state');
  const stored = await AuthStates.consume(db, sha256Hex(state));
  if (!stored || stored.provider_key !== eff.key) {
    throw new LoginError('invalid_state', 'Invalid or already-used state');
  }
  const postLoginRedirect = stored.post_login_redirect ?? null;
  const currentUrl = new URL(callbackUrl(config, eff));
  for (const [k, v] of callbackParams) currentUrl.searchParams.set(k, v);

  if (callbackParams.get('error')) {
    throw new LoginError('provider_error', `Provider returned error: ${callbackParams.get('error_description') ?? callbackParams.get('error')}`);
  }
  const code = callbackParams.get('code');
  if (!code) throw new LoginError('missing_code', 'Authorization response missing code');

  if (eff.oauth2Only) {
    const profile = await finishOAuth2Login(ctx, code, stored.redirect_uri ?? callbackUrl(config, eff), stored.code_verifier!);
    return { profile, postLoginRedirect };
  }

  const cfg = await buildClientConfiguration(eff);
  // authorizationCodeGrant validates: state, nonce, PKCE, iss (against the
  // discovered issuer — issuer-confusion safe), aud, signature via JWKS, exp.
  const tokens = await authorizationCodeGrant(cfg, currentUrl, {
    expectedState: state,
    expectedNonce: stored.nonce ?? undefined,
    pkceCodeVerifier: stored.code_verifier ?? undefined,
  }).catch((err: unknown) => {
    throw new LoginError('token_exchange_failed', err instanceof Error ? err.message : 'token exchange failed');
  });

  const claims = tokens.claims();
  if (!claims) throw new LoginError('missing_id_token', 'No ID token in token response');
  // Replay protection on the token jti when present.
  const jti = typeof claims.jti === 'string' ? claims.jti : null;
  if (jti) {
    const replayed = await UsedAssertions.checkAndRecord(db, `oidc:${eff.key}:${jti}`, eff.key, 900);
    if (replayed) throw new LoginError('replay_detected', 'ID token already used');
  }

  let merged: Record<string, unknown> = { ...(claims as unknown as Record<string, unknown>) };
  // Prefer userinfo for profile attributes when available (signed by the IdP session).
  if (tokens.access_token && eff.endpoints.userinfo !== undefined) {
    try {
      const ui = await fetchUserInfo(cfg, tokens.access_token, claims.sub);
      merged = { ...merged, ...(ui as unknown as Record<string, unknown>) };
    } catch {
      // userinfo is best-effort; id_token claims remain authoritative.
    }
  }
  const profile = applyClaimMapping(eff.claimMapping, merged);
  return { profile, postLoginRedirect };
}

/** GitHub-style OAuth2: exchange code + PKCE, then fetch profile via the API. */
async function finishOAuth2Login(
  ctx: LoginContext,
  code: string,
  redirectUri: string,
  codeVerifier: string,
): Promise<VerifiedProfile> {
  const { eff } = ctx;
  const tokenRes = await fetch(eff.endpoints.token!, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'User-Agent': 'PaintScope-Mobile/1.0' },
    body: JSON.stringify({
      client_id: eff.clientId,
      client_secret: eff.clientSecret,
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    }),
  });
  if (!tokenRes.ok) throw new LoginError('token_exchange_failed', `token endpoint returned ${tokenRes.status}`);
  const tokenJson = (await tokenRes.json()) as { access_token?: string; error?: string; error_description?: string };
  if (tokenJson.error || !tokenJson.access_token) {
    throw new LoginError('token_exchange_failed', tokenJson.error_description ?? tokenJson.error ?? 'no access token');
  }
  const headers = {
    Authorization: `Bearer ${tokenJson.access_token}`,
    Accept: 'application/vnd.github+json',
    'User-Agent': 'PaintScope-Mobile/1.0',
  };
  const userRes = await fetch(eff.endpoints.userinfo!, { headers });
  if (!userRes.ok) throw new LoginError('userinfo_failed', `userinfo returned ${userRes.status}`);
  const user = (await userRes.json()) as {
    id?: number;
    login?: string;
    name?: string | null;
    avatar_url?: string | null;
    email?: string | null;
    email_verified?: boolean;
  };
  if (!user.id) throw new LoginError('userinfo_failed', 'userinfo missing id');

  // GitHub emails are NOT verified by default — fetch the verified flag explicitly.
  // (Only for real GitHub; a mock userinfo endpoint may embed email directly.)
  let email = typeof user.email === 'string' ? user.email : null;
  let emailVerified = user.email_verified === true;
  if (eff.endpoints.userinfo === 'https://api.github.com/user') {
    try {
      const emailsRes = await fetch('https://api.github.com/user/emails', { headers });
      if (emailsRes.ok) {
        const emails = (await emailsRes.json()) as Array<{ email: string; primary: boolean; verified: boolean }>;
        const primary = emails.find((e) => e.primary && e.verified) ?? emails.find((e) => e.verified);
        if (primary) {
          email = primary.email;
          emailVerified = true;
        } else {
          email = null;
          emailVerified = false;
        }
      }
    } catch {
      // no verified email — profile still valid, email stays null
    }
  }

  const claims: Record<string, unknown> = {
    sub: `github:${user.id}`,
    email,
    email_verified: emailVerified,
    name: user.name ?? user.login ?? null,
    login: user.login,
    picture: user.avatar_url ?? null,
  };
  return applyClaimMapping(eff.claimMapping, claims);
}

export class LoginError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
