import 'dotenv/config';

export type ProviderType =
  | 'google'
  | 'microsoft'
  | 'apple'
  | 'github'
  | 'linkedin'
  | 'okta'
  | 'auth0'
  | 'oidc'
  | 'saml';

export const PROVIDER_TYPES: ProviderType[] = [
  'google',
  'microsoft',
  'apple',
  'github',
  'linkedin',
  'okta',
  'auth0',
  'oidc',
  'saml',
];

export interface ClaimMapping {
  sub?: string;
  email?: string;
  emailVerified?: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  avatar?: string;
}

export interface ProviderEnvConfig {
  type: ProviderType;
  enabled: boolean;
  clientId?: string;
  clientSecret?: string; // plaintext here; callers treat as sensitive
  issuer?: string;
  tenantId?: string;
  scopes: string[];
  allowEmailLink: boolean;
  /** Explicit endpoints (skip OIDC discovery). Used for offline/test setups. */
  endpoints?: {
    authorization?: string;
    token?: string;
    userinfo?: string;
    jwks?: string;
  };
  /** Apple-only: ES256 client-secret signing material. */
  apple?: { teamId: string; keyId: string; privateKeyPem: string };
  claimMapping?: ClaimMapping;
  /** Allow JIT org membership on first enterprise login (default false = fail closed). */
}

export interface AppConfig {
  port: number;
  appBaseUrl: string;
  redirectAllowlist: string[];
  databaseUrl: string;
  jwtSecret: string;
  configEncryptionKey: Buffer;
  providers: Record<ProviderType, ProviderEnvConfig>;
  firebaseServiceAccountJson?: string;
  googleApplicationCredentials?: string;
}

function req(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var ${name}`);
  return v;
}

function bool(name: string, def = false): boolean {
  const v = process.env[name];
  if (v === undefined) return def;
  return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}

function csv(name: string): string[] {
  return (process.env[name] ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function optionalClaimMapping(prefix: string): ClaimMapping | undefined {
  const raw = process.env[`${prefix}_CLAIM_MAPPING`];
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const out: ClaimMapping = {};
    for (const k of ['sub', 'email', 'emailVerified', 'name', 'givenName', 'familyName', 'avatar'] as const) {
      if (typeof parsed[k] === 'string') out[k] = parsed[k];
    }
    return out;
  } catch {
    throw new Error(`${prefix}_CLAIM_MAPPING is not valid JSON`);
  }
}

function base(prefix: string, type: ProviderType, scopes: string[]): ProviderEnvConfig {
  return {
    type,
    enabled: bool(`${prefix}_ENABLED`),
    clientId: process.env[`${prefix}_CLIENT_ID`] || undefined,
    clientSecret: process.env[`${prefix}_CLIENT_SECRET`] || undefined,
    scopes,
    allowEmailLink: bool(`${prefix}_ALLOW_EMAIL_LINK`),
    claimMapping: optionalClaimMapping(prefix),
  };
}

export function loadConfig(): AppConfig {
  const keyHex = process.env.CONFIG_ENCRYPTION_KEY ?? '';
  if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
    throw new Error('CONFIG_ENCRYPTION_KEY must be 64 hex chars (32 bytes)');
  }
  const providers: Record<ProviderType, ProviderEnvConfig> = {
    google: { ...base('GOOGLE', 'google', ['openid', 'profile', 'email']) },
    microsoft: {
      ...base('MICROSOFT', 'microsoft', ['openid', 'profile', 'email']),
      tenantId: process.env.MICROSOFT_TENANT_ID || undefined,
    },
    apple: {
      ...base('APPLE', 'apple', ['name', 'email']),
      apple:
        process.env.APPLE_TEAM_ID && process.env.APPLE_KEY_ID && process.env.APPLE_PRIVATE_KEY
          ? {
              teamId: process.env.APPLE_TEAM_ID,
              keyId: process.env.APPLE_KEY_ID,
              privateKeyPem: process.env.APPLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
            }
          : undefined,
    },
    github: { ...base('GITHUB', 'github', ['read:user', 'user:email']) },
    linkedin: { ...base('LINKEDIN', 'linkedin', ['openid', 'profile', 'email']) },
    okta: {
      ...base('OKTA', 'okta', ['openid', 'profile', 'email']),
      issuer: process.env.OKTA_ISSUER || undefined,
    },
    auth0: {
      ...base('AUTH0', 'auth0', ['openid', 'profile', 'email']),
      issuer: process.env.AUTH0_ISSUER || undefined,
    },
    oidc: {
      ...base('OIDC', 'oidc', ['openid', 'profile', 'email']),
      issuer: process.env.OIDC_ISSUER || undefined,
      endpoints: process.env.OIDC_AUTHORIZATION_ENDPOINT
        ? {
            authorization: process.env.OIDC_AUTHORIZATION_ENDPOINT,
            token: process.env.OIDC_TOKEN_ENDPOINT,
            userinfo: process.env.OIDC_USERINFO_ENDPOINT,
            jwks: process.env.OIDC_JWKS_URI,
          }
        : undefined,
    },
    saml: { ...base('SAML', 'saml', []) },
  };

  return {
    port: Number(process.env.PORT ?? 4000),
    appBaseUrl: (process.env.APP_BASE_URL ?? 'http://localhost:4000').replace(/\/$/, ''),
    redirectAllowlist: csv('APP_REDIRECT_ALLOWLIST'),
    databaseUrl: process.env.DATABASE_URL ?? './dev.sqlite3',
    jwtSecret: req('JWT_SECRET'),
    configEncryptionKey: Buffer.from(keyHex, 'hex'),
    providers,
    firebaseServiceAccountJson: process.env.FIREBASE_SERVICE_ACCOUNT_JSON || undefined,
    googleApplicationCredentials: process.env.GOOGLE_APPLICATION_CREDENTIALS || undefined,
  };
}
