import type { Role } from '../db/models.js';

const RANK: Record<Role, number> = { member: 1, admin: 2, owner: 3 };

export function isValidRole(role: unknown): role is Role {
  return role === 'owner' || role === 'admin' || role === 'member';
}

export function assertValidRole(role: unknown): asserts role is Role {
  if (!isValidRole(role)) throw new Error(`Invalid role: ${String(role)}`);
}

/** True when `actor` may act with at least `required` privilege. */
export function roleAtLeast(actor: Role, required: Role): boolean {
  return RANK[actor] >= RANK[required];
}
