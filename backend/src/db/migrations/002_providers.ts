import type { Knex } from 'knex';

export async function up(db: Knex): Promise<void> {
  await db.schema.createTable('providers', (t) => {
    t.text('id').primary();
    // google|microsoft|apple|github|linkedin|okta|auth0|oidc|saml
    t.text('type').notNullable();
    t.text('name').notNullable();
    // NULL = global provider; set = per-organization provider
    t.text('org_id').nullable().references('id').inTable('organizations').onDelete('CASCADE');
    // AES-256-GCM encrypted JSON (base64). Secrets never stored plaintext.
    t.text('config_encrypted').notNullable();
    t.boolean('enabled').notNullable().defaultTo(true);
    t.timestamp('created_at').notNullable().defaultTo(db.fn.now());
    t.timestamp('updated_at').notNullable().defaultTo(db.fn.now());
    t.index(['org_id']);
  });
  // One global row per type; one row per (type, org) for org overrides.
  await db.raw(
    `CREATE UNIQUE INDEX IF NOT EXISTS providers_global_type_unique ON providers(type) WHERE org_id IS NULL`,
  );
  await db.raw(
    `CREATE UNIQUE INDEX IF NOT EXISTS providers_org_type_unique ON providers(type, org_id) WHERE org_id IS NOT NULL`,
  );

  await db.schema.createTable('identities', (t) => {
    t.text('id').primary();
    t.text('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.text('provider_id').notNullable().references('id').inTable('providers').onDelete('CASCADE');
    // Stable provider-issued subject. NEVER email — email is not a join key.
    t.text('provider_sub').notNullable();
    t.text('email').nullable();
    t.boolean('email_verified').notNullable().defaultTo(false);
    t.boolean('revoked').notNullable().defaultTo(false);
    t.timestamp('linked_at').notNullable().defaultTo(db.fn.now());
    t.timestamp('created_at').notNullable().defaultTo(db.fn.now());
    t.timestamp('updated_at').notNullable().defaultTo(db.fn.now());
    t.unique(['provider_id', 'provider_sub']);
    t.index(['user_id']);
  });
}

export async function down(db: Knex): Promise<void> {
  await db.schema.dropTableIfExists('identities');
  await db.schema.dropTableIfExists('providers');
}
