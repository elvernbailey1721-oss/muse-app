import type { NextFunction, Request, Response } from 'express';
import type { Knex } from 'knex';
import type { AppConfig } from '../config.js';
import { Memberships, RefreshTokens, type MembershipRow } from '../db/models.js';
import { verifyAccessToken, type AccessClaims } from './tokens.js';
import { roleAtLeast, isValidRole } from './roles.js';
import { audit } from '../services/audit.js';
import type { Role } from '../db/models.js';

export interface RequestContext {
  db: Knex;
  config: AppConfig;
}

declare module 'express-serve-static-core' {
  interface Request {
    auth?: AccessClaims & { userId: string };
    orgMembership?: MembershipRow;
  }
}

export function getClientIp(req: Request): string | null {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd) return fwd.split(',')[0].trim();
  return req.ip ?? null;
}

/** Single-value route param (Express 5 types params as string|string[]). */
export function param(req: Request, name: string): string {
  const v = req.params[name];
  if (typeof v !== 'string' || !v) throw new Error(`missing route param: ${name}`);
  return v;
}

/** Default-deny authentication: Bearer access token required. */
export function authenticate(rc: RequestContext) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const header = req.headers.authorization ?? '';
      const [scheme, token] = header.split(' ');
      if (scheme?.toLowerCase() !== 'bearer' || !token) {
        res.status(401).json({ error: 'unauthorized', message: 'Missing bearer token' });
        return;
      }
      const claims = await verifyAccessToken(rc.config.jwtSecret, token);
      // Immediate session invalidation: the access token is bound to its
      // refresh family; logout / reuse-detection revokes the family, which
      // kills outstanding access tokens before their 15-minute TTL.
      const active = await RefreshTokens.familyActive(rc.db, claims.fid);
      if (!active) {
        await audit(rc.db, 'authz_denied', {
          actorUserId: claims.sub,
          ip: getClientIp(req),
          userAgent: req.headers['user-agent'] ?? null,
          meta: { reason: 'session_revoked', detail: 'access token family no longer active' },
        });
        res.status(401).json({ error: 'unauthorized', message: 'Session revoked' });
        return;
      }
      req.auth = { ...claims, userId: claims.sub };
      next();
    } catch {
      res.status(401).json({ error: 'unauthorized', message: 'Invalid or expired token' });
    }
  };
}

/** Require an org-bound session (org_id came from the login's membership, never the client). */
export function requireOrg(rc: RequestContext) {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth?.org_id) {
      await audit(rc.db, 'authz_denied', {
        actorUserId: req.auth?.userId,
        ip: getClientIp(req),
        userAgent: req.headers['user-agent'] ?? null,
        meta: { reason: 'no_org_context', detail: 'endpoint requires org-bound session' },
      });
      res.status(403).json({ error: 'forbidden', message: 'No organization context' });
      return;
    }
    next();
  };
}

/** Require the session's role (from the token's membership binding) to suffice. */
export function requireSessionRole(rc: RequestContext, min: Role) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const role = req.auth?.role;
    if (!req.auth?.org_id || !isValidRole(role) || !roleAtLeast(role, min)) {
      await audit(rc.db, 'authz_denied', {
        actorUserId: req.auth?.userId,
        orgId: req.auth?.org_id,
        ip: getClientIp(req),
        userAgent: req.headers['user-agent'] ?? null,
        meta: { reason: 'insufficient_role', role: role ?? null, detail: `requires ${min}` },
      });
      res.status(403).json({ error: 'forbidden', message: 'Insufficient role' });
      return;
    }
    next();
  };
}

/**
 * For /orgs/:orgId admin routes: verify the caller is a member of the PATH org
 * with sufficient role. The path org is never trusted on its own — the
 * membership row is the authority.
 */
export function requireOrgRole(rc: RequestContext, min: Role) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const orgId = param(req, 'orgId');
    const membership = orgId ? await Memberships.byUserAndOrg(rc.db, req.auth!.userId, orgId) : undefined;
    if (!membership || !roleAtLeast(membership.role, min)) {
      await audit(rc.db, 'authz_denied', {
        actorUserId: req.auth?.userId,
        orgId: orgId ?? null,
        ip: getClientIp(req),
        userAgent: req.headers['user-agent'] ?? null,
        meta: { reason: 'insufficient_role', detail: `requires ${min} in org` },
      });
      res.status(403).json({ error: 'forbidden', message: 'Insufficient role in organization' });
      return;
    }
    req.orgMembership = membership;
    next();
  };
}
