import * as jose from 'jose';
import type { Knex } from 'knex';
import { newId, randomToken, sha256Hex } from '../crypto.js';
import { RefreshTokens, toBool, type UserRow } from '../db/models.js';

export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600;

export interface AccessClaims {
  sub: string;
  org_id: string | null;
  role: string | null;
  email: string | null;
  /** Refresh-token family id. Logout / reuse-detection revokes the family, and
   *  authenticate() verifies it is still active — so access tokens die with
   *  the session instead of lingering for their 15-minute TTL. */
  fid: string;
  jti: string;
}

export async function issueAccessToken(
  jwtSecret: string,
  user: UserRow,
  orgId: string | null,
  role: string | null,
  familyId: string,
): Promise<string> {
  const key = new TextEncoder().encode(jwtSecret);
  return new jose.SignJWT({ org_id: orgId, role, email: user.email, fid: familyId })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(user.id)
    .setJti(newId())
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TOKEN_TTL_SECONDS}s`)
    .sign(key);
}

export async function verifyAccessToken(jwtSecret: string, token: string): Promise<AccessClaims> {
  const key = new TextEncoder().encode(jwtSecret);
  const { payload } = await jose.jwtVerify(token, key, { algorithms: ['HS256'] });
  if (typeof payload.sub !== 'string' || !payload.sub) throw new Error('bad sub');
  if (typeof payload.fid !== 'string' || !payload.fid) throw new Error('missing family id');
  return {
    sub: payload.sub,
    org_id: typeof payload.org_id === 'string' ? payload.org_id : null,
    role: typeof payload.role === 'string' ? payload.role : null,
    email: typeof payload.email === 'string' ? payload.email : null,
    fid: payload.fid,
    jti: typeof payload.jti === 'string' ? payload.jti : '',
  };
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/** Create a fresh refresh-token family (session). Raw token returned once. */
export async function createSession(
  db: Knex,
  jwtSecret: string,
  user: UserRow,
  orgId: string | null,
  role: string | null,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<TokenPair> {
  const raw = randomToken();
  const familyId = newId();
  await RefreshTokens.create(db, {
    user_id: user.id,
    family_id: familyId,
    token_hash: sha256Hex(raw),
    expires_at: new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000).toISOString(),
    ip: meta.ip,
    user_agent: meta.userAgent,
  });
  return {
    accessToken: await issueAccessToken(jwtSecret, user, orgId, role, familyId),
    refreshToken: raw,
    expiresIn: ACCESS_TOKEN_TTL_SECONDS,
  };
}

export type RotateResult =
  | { ok: true; user: UserRow; refreshToken: string; familyId: string; previousOrgId?: string | null }
  | { ok: false; reason: 'not_found' | 'expired' | 'revoked' | 'reuse_detected' };

/**
 * Rotate a refresh token. Reuse of an already-rotated token revokes the whole
 * family (token-theft signal). Raw tokens are never stored — only SHA-256.
 * The caller issues the new access token after re-validating org membership.
 */
export async function rotateRefreshToken(
  db: Knex,
  rawToken: string,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<RotateResult> {
  const hash = sha256Hex(rawToken);
  // Whole rotation runs in one transaction. The claim below is a single
  // conditional UPDATE (WHERE id AND NOT revoked), so concurrent requests
  // presenting the same token cannot both rotate it — exactly one wins.
  return db.transaction(async (trx) => {
    const row = await RefreshTokens.byHash(trx, hash);
    if (!row) return { ok: false, reason: 'not_found' };
    if (new Date(row.expires_at).getTime() < Date.now()) return { ok: false, reason: 'expired' };

    if (toBool(row.revoked)) {
      if (row.successor_hash) {
        // This token was already rotated and is being presented again: theft.
        await RefreshTokens.revokeFamily(trx, row.family_id);
        return { ok: false, reason: 'reuse_detected' };
      }
      return { ok: false, reason: 'revoked' };
    }

    const { Users } = await import('../db/models.js');
    const user = await Users.byId(trx, row.user_id);
    if (!user || toBool(user.disabled)) {
      await RefreshTokens.revokeFamily(trx, row.family_id);
      return { ok: false, reason: 'revoked' };
    }

    const nextRaw = randomToken();
    const nextHash = sha256Hex(nextRaw);
    // Atomic claim: flip revoked false->true only if still unrevoked.
    // Knex renders `false` per-dialect (0 on SQLite, FALSE on Postgres).
    const claimed = await trx('refresh_tokens')
      .where({ id: row.id, revoked: false })
      .update({ revoked: true, successor_hash: nextHash });
    if (!claimed) {
      // Lost the race — another request rotated this token first. Treat the
      // replay exactly like reuse: the family dies.
      const fresh = await RefreshTokens.byHash(trx, hash);
      if (fresh && toBool(fresh.revoked) && fresh.successor_hash) {
        await RefreshTokens.revokeFamily(trx, fresh.family_id);
        return { ok: false, reason: 'reuse_detected' };
      }
      return { ok: false, reason: 'revoked' };
    }

    await RefreshTokens.create(trx, {
      user_id: row.user_id,
      family_id: row.family_id,
      token_hash: nextHash,
      expires_at: new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000).toISOString(),
      ip: meta.ip,
      user_agent: meta.userAgent,
    });

    return { ok: true, user, refreshToken: nextRaw, familyId: row.family_id };
  });
}

export async function revokeFamilyByToken(db: Knex, rawToken: string): Promise<boolean> {
  const row = await RefreshTokens.byHash(db, sha256Hex(rawToken));
  if (!row) return false;
  await RefreshTokens.revokeFamily(db, row.family_id);
  return true;
}
