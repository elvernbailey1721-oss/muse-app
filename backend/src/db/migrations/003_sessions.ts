import type { Knex } from 'knex';

export async function up(db: Knex): Promise<void> {
  await db.schema.createTable('refresh_tokens', (t) => {
    t.text('id').primary();
    t.text('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.text('family_id').notNullable();
    // SHA-256 hex of the token; raw token is never stored.
    t.text('token_hash').notNullable().unique();
    t.boolean('revoked').notNullable().defaultTo(false);
    t.text('successor_hash').nullable();
    t.timestamp('expires_at').notNullable();
    t.text('ip').nullable();
    t.text('user_agent').nullable();
    t.timestamp('created_at').notNullable().defaultTo(db.fn.now());
    t.index(['family_id']);
    t.index(['user_id']);
  });

  await db.schema.createTable('devices', (t) => {
    t.text('id').primary();
    t.text('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.text('platform').notNullable();
    t.text('token').notNullable();
    t.text('app_version').nullable();
    t.timestamp('last_seen_at').notNullable().defaultTo(db.fn.now());
    t.timestamp('created_at').notNullable().defaultTo(db.fn.now());
    t.timestamp('updated_at').notNullable().defaultTo(db.fn.now());
    t.unique(['user_id', 'token']);
    t.index(['user_id']);
  });
  // NOTE: platform restricted to ios|android by application validation
  // (see src/routes/devices.ts). Postgres deployments should add a CHECK constraint.

  await db.schema.createTable('scans', (t) => {
    t.text('id').primary();
    t.text('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    // Tenant isolation: every scan belongs to exactly one org; org_id always
    // comes from the authenticated session, never from the client.
    t.text('org_id').notNullable().references('id').inTable('organizations').onDelete('CASCADE');
    t.text('name').notNullable();
    t.text('colors_json').notNullable(); // JSON array of hex strings
    t.text('detected_color').nullable();
    t.text('thumbnail').nullable(); // optional base64 thumbnail
    t.timestamp('captured_at').nullable();
    t.timestamp('created_at').notNullable().defaultTo(db.fn.now());
    t.timestamp('updated_at').notNullable().defaultTo(db.fn.now());
    t.index(['org_id', 'created_at']);
    t.index(['user_id']);
  });

  // Append-only audit log. No UPDATE/DELETE paths exist in the codebase.
  await db.schema.createTable('audit_events', (t) => {
    t.text('id').primary();
    t.text('actor_user_id').nullable();
    t.text('action').notNullable();
    t.text('org_id').nullable();
    t.text('ip').nullable();
    t.text('user_agent').nullable();
    t.text('meta_json').nullable(); // allowlisted fields only (see services/audit.ts)
    t.timestamp('created_at').notNullable().defaultTo(db.fn.now());
    t.index(['action', 'created_at']);
    t.index(['actor_user_id']);
  });

  // Single-use OIDC/OAuth2 authorization state: state hash -> PKCE verifier + nonce.
  await db.schema.createTable('auth_states', (t) => {
    t.text('id').primary();
    t.text('state_hash').notNullable().unique();
    t.text('provider_key').notNullable(); // "<type>:<org_id|global>"
    t.text('code_verifier').nullable();
    t.text('nonce').nullable();
    t.text('redirect_uri').nullable();
    t.text('org_id').nullable(); // requested org context (validated post-login)
    t.text('post_login_redirect').nullable(); // validated against allowlist
    t.boolean('used').notNullable().defaultTo(false);
    t.timestamp('expires_at').notNullable();
    t.timestamp('created_at').notNullable().defaultTo(db.fn.now());
    t.index(['expires_at']);
  });

  // Replay protection for SSO assertions (SAML Response IDs / token JTIs).
  await db.schema.createTable('used_assertions', (t) => {
    t.text('id').primary();
    t.text('assertion_id').notNullable().unique();
    t.text('provider_key').notNullable();
    t.timestamp('expires_at').notNullable();
    t.timestamp('created_at').notNullable().defaultTo(db.fn.now());
    t.index(['expires_at']);
  });
}

export async function down(db: Knex): Promise<void> {
  await db.schema.dropTableIfExists('used_assertions');
  await db.schema.dropTableIfExists('auth_states');
  await db.schema.dropTableIfExists('audit_events');
  await db.schema.dropTableIfExists('scans');
  await db.schema.dropTableIfExists('devices');
  await db.schema.dropTableIfExists('refresh_tokens');
}
