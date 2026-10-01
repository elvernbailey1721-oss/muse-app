import type { Knex } from 'knex';
import { AuditEvents } from '../db/models.js';

export const AUDIT_ACTIONS = [
  'login',
  'login_failure',
  'identity_linked',
  'authz_denied',
  'logout',
  'provider_config_changed',
  'email_collision_deferred',
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];

/**
 * Allowlisted audit meta fields. Anything not on this list is dropped —
 * passwords, secrets, tokens, auth codes, nonces, and verifiers can never
 * reach the audit log.
 */
const META_ALLOWLIST = new Set([
  'email',
  'provider_type',
  'provider_name',
  'org_id',
  'org_name',
  'role',
  'previous_role',
  'reason',
  'detail',
  'user_id',
  'device_platform',
  'scan_id',
  'scan_name',
  'redirect_host',
]);

function sanitizeMeta(meta: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!meta) return undefined;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(meta)) {
    if (META_ALLOWLIST.has(k) && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' || v === null)) {
      out[k] = v;
    }
  }
  return out;
}

export async function audit(
  db: Knex,
  action: AuditAction,
  opts: {
    actorUserId?: string | null;
    orgId?: string | null;
    ip?: string | null;
    userAgent?: string | null;
    meta?: Record<string, unknown>;
  } = {},
): Promise<void> {
  try {
    await AuditEvents.append(db, {
      actor_user_id: opts.actorUserId ?? null,
      action,
      org_id: opts.orgId ?? null,
      ip: opts.ip ?? null,
      user_agent: opts.userAgent ?? null,
      meta_json: JSON.stringify(sanitizeMeta(opts.meta) ?? {}),
    });
  } catch (err) {
    // Audit must never break the request path; log to stderr.
    console.error('audit append failed:', err);
  }
}
