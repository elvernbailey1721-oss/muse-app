import type { ProviderContext } from './providers.js';
import { ensureProviderRow } from './providers.js';
import { Identities, Users, toBool, type IdentityRow, type UserRow } from '../db/models.js';
import { audit } from '../services/audit.js';
import type { VerifiedProfile } from './oidc.js';

export class LinkError extends Error {
  code: string;
  status: number;
  constructor(code: string, message: string, status = 403) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export interface LinkOutcome {
  user: UserRow;
  identity: IdentityRow;
  /** True when a brand-new user row was created. */
  createdUser: boolean;
  /** True when the identity was attached to a pre-existing user via email linking. */
  linkedToExisting: boolean;
}

/**
 * Resolve-or-create the user for a verified SSO profile.
 *
 * Security rules (fail closed):
 * 1. The join key is ALWAYS (provider_id, provider_sub) — a stable provider
 *    subject. Email is NEVER a join key.
 * 2. Email linking happens ONLY when the provider asserted email_verified AND
 *    the provider's allowEmailLink flag is on. Otherwise a fresh unlinked user
 *    is created — never an automatic merge.
 * 3. Unverified emails are never written to users.email (unique column); they
 *    live on the identity row only.
 * 4. Revoked or disabled identities/users fail closed.
 */
export async function resolveUserForIdentity(
  ctx: ProviderContext,
  providerId: string,
  allowEmailLink: boolean,
  profile: VerifiedProfile,
  reqMeta: { ip?: string | null; userAgent?: string | null },
): Promise<LinkOutcome> {
  const { db } = ctx;

  const identity = await Identities.byProviderSub(db, providerId, profile.sub);
  if (identity) {
    if (toBool(identity.revoked)) {
      throw new LinkError('identity_revoked', 'This identity has been revoked');
    }
    const user = await Users.byId(db, identity.user_id);
    if (!user || toBool(user.disabled)) {
      throw new LinkError('user_disabled', 'User account is disabled', 403);
    }
    await Identities.touch(db, identity.id, profile.email, profile.emailVerified);
    // Fill in display name on first sight.
    if (!user.name && profile.name) await Users.update(db, user.id, { name: profile.name });
    if (!user.avatar_url && profile.avatarUrl) await Users.update(db, user.id, { avatar_url: profile.avatarUrl });
    const fresh = await Users.byId(db, user.id);
    return { user: fresh!, identity, createdUser: false, linkedToExisting: false };
  }

  // No identity yet: email linking ONLY on verified email + explicit allow rule.
  // Wrapped in a transaction so concurrent logins for the same sub/email
  // cannot double-create users or identities.
  return db.transaction(async (trx) => {
    if (profile.email && profile.emailVerified && allowEmailLink) {
      const existing = await Users.byEmail(trx, profile.email);
      if (existing && !toBool(existing.disabled)) {
        const linked = await Identities.create(trx, {
          user_id: existing.id,
          provider_id: providerId,
          provider_sub: profile.sub,
          email: profile.email,
          email_verified: true,
        });
        await audit(trx, 'identity_linked', {
          actorUserId: existing.id,
          ip: reqMeta.ip,
          userAgent: reqMeta.userAgent,
          meta: { email: profile.email },
        });
        return { user: existing, identity: linked, createdUser: false, linkedToExisting: true };
      }
    }

    // Fail closed: brand-new unlinked user. Verified email may occupy users.email;
    // unverified email stays on the identity row only (prevents unique collisions
    // and unverified-email takeover). If the verified email is already owned by
    // another user (e.g. linking disabled), create the account with email NULL
    // rather than hitting the unique constraint or hijacking the address.
    let userEmail: string | null = profile.emailVerified && profile.email ? profile.email : null;
    if (userEmail && (await Users.byEmail(trx, userEmail))) {
      await audit(trx, 'email_collision_deferred', {
        ip: reqMeta.ip,
        userAgent: reqMeta.userAgent,
      });
      userEmail = null;
    }
    const user = await Users.create(trx, {
      email: userEmail,
      name: profile.name,
      avatar_url: profile.avatarUrl,
    });
    const created = await Identities.create(trx, {
      user_id: user.id,
      provider_id: providerId,
      provider_sub: profile.sub,
      email: profile.email,
      email_verified: profile.emailVerified,
    });
    return { user, identity: created, createdUser: true, linkedToExisting: false };
  });
}

/** Ensure a providers row exists for an env-configured provider (FK target). */
export async function providerRowForLogin(ctx: ProviderContext, orgId: string | null, type: string, name: string) {
  return ensureProviderRow(ctx, orgId, type, name);
}
