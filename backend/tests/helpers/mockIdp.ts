import express from 'express';
import * as jose from 'jose';
import { randomToken } from '../../src/crypto.js';

/**
 * Minimal mock OIDC issuer for tests: discovery, JWKS, authorize (auto-approves),
 * token (PKCE-validating), userinfo. Scenarios let tests mint hostile tokens
 * (wrong issuer/audience/expiry/nonce) to prove the RP rejects them.
 */
export interface MockScenario {
  sub?: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  wrongIssuer?: boolean;
  badAudience?: boolean;
  expired?: boolean;
  nonceMismatch?: boolean;
  tokenError?: string;
}

interface CodeEntry {
  nonce: string;
  codeChallenge: string;
  redirectUri: string;
  scenario: MockScenario;
}

export interface MockIdp {
  issuer: string;
  clientId: string;
  clientSecret: string;
  authorizeUrl: (extra?: Record<string, string>) => string;
  setNextScenario(s: MockScenario): void;
  close(): Promise<void>;
}

export async function startMockIdp(): Promise<MockIdp> {
  const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
  const publicJwk = await jose.exportJWK(publicKey);
  publicJwk.kid = 'mock-key-1';
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';

  const app = express();
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());

  const clientId = 'test-client';
  const clientSecret = 'test-secret';
  let nextScenario: MockScenario = {};
  const codes = new Map<string, CodeEntry>();
  const accessTokens = new Map<string, MockScenario>();

  let issuer = '';
  app.get('/.well-known/openid-configuration', (_req, res) => {
    res.json({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      jwks_uri: `${issuer}/jwks`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'],
    });
  });
  app.get('/jwks', (_req, res) => res.json({ keys: [publicJwk] }));

  app.get('/authorize', (req, res) => {
    const q = req.query as Record<string, string>;
    if (q.client_id !== clientId) {
      res.status(400).send('bad client_id');
      return;
    }
    const code = randomToken(24);
    codes.set(code, {
      nonce: q.nonce ?? '',
      codeChallenge: q.code_challenge ?? '',
      redirectUri: q.redirect_uri ?? '',
      scenario: nextScenario,
    });
    nextScenario = {};
    const dest = new URL(q.redirect_uri);
    dest.searchParams.set('code', code);
    if (q.state) dest.searchParams.set('state', q.state);
    res.redirect(302, dest.toString());
  });

  app.post('/token', async (req, res) => {
    const b = req.body as Record<string, string>;
    const entry = codes.get(b.code);
    if (!entry) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'unknown code' });
      return;
    }
    codes.delete(b.code);
    if (entry.scenario.tokenError) {
      res.status(400).json({ error: entry.scenario.tokenError });
      return;
    }
    if (b.client_id !== clientId || b.client_secret !== clientSecret) {
      res.status(401).json({ error: 'invalid_client' });
      return;
    }
    if (b.redirect_uri !== entry.redirectUri) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
      return;
    }
    // PKCE S256 verification.
    const digest = jose.base64url.encode(
      new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(b.code_verifier ?? ''))),
    );
    if (digest !== entry.codeChallenge) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE failed' });
      return;
    }
    const s = entry.scenario;
    const now = Math.floor(Date.now() / 1000);
    const idToken = await new jose.SignJWT({
      email: s.email ?? 'alice@example.com',
      email_verified: s.emailVerified ?? true,
      name: s.name ?? 'Alice Example',
      // Nonce goes in the payload directly; mismatch scenario uses a wrong value.
      nonce: s.nonceMismatch ? 'wrong-nonce' : entry.nonce || undefined,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'mock-key-1' })
      .setIssuer(s.wrongIssuer ? 'https://evil.example.com' : issuer)
      .setSubject(s.sub ?? 'mock-sub-1')
      .setAudience(s.badAudience ? 'someone-else' : clientId)
      .setIssuedAt(s.expired ? now - 7200 : now)
      .setExpirationTime(s.expired ? now - 3600 : now + 300)
      .setJti(randomToken(12))
      .sign(privateKey);
    const accessToken = randomToken(24);
    accessTokens.set(accessToken, s);
    res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 300, id_token: idToken });
  });

  app.get('/userinfo', (req, res) => {
    const auth = req.headers.authorization ?? '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const s = accessTokens.get(token);
    if (!s) {
      res.status(401).json({ error: 'invalid_token' });
      return;
    }
    res.json({
      sub: s.sub ?? 'mock-sub-1',
      email: s.email ?? 'alice@example.com',
      email_verified: s.emailVerified ?? true,
      name: s.name ?? 'Alice Example',
    });
  });

  const server = await new Promise<import('node:http').Server>((resolve) => {
    const srv = app.listen(0, '127.0.0.1', () => resolve(srv));
  });
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('mock idp failed to bind');
  issuer = `http://127.0.0.1:${addr.port}`;

  return {
    issuer,
    clientId,
    clientSecret,
    authorizeUrl: (extra = {}) => {
      const u = new URL(`${issuer}/authorize`);
      for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v);
      return u.toString();
    },
    setNextScenario: (s) => {
      nextScenario = s;
    },
    close: () => new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  };
}
