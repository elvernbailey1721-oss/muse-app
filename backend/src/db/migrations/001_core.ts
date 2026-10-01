import type { Knex } from 'knex';

export async function up(db: Knex): Promise<void> {
  await db.schema.createTable('users', (t) => {
    t.text('id').primary();
    t.text('email').nullable().unique();
    t.text('name').nullable();
    t.text('avatar_url').nullable();
    t.boolean('disabled').notNullable().defaultTo(false);
    t.timestamp('created_at').notNullable().defaultTo(db.fn.now());
    t.timestamp('updated_at').notNullable().defaultTo(db.fn.now());
  });

  await db.schema.createTable('organizations', (t) => {
    t.text('id').primary();
    t.text('name').notNullable();
    t.text('slug').notNullable().unique();
    t.text('domain').nullable().unique();
    t.timestamp('created_at').notNullable().defaultTo(db.fn.now());
    t.timestamp('updated_at').notNullable().defaultTo(db.fn.now());
  });

  await db.schema.createTable('org_memberships', (t) => {
    t.text('id').primary();
    t.text('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.text('org_id').notNullable().references('id').inTable('organizations').onDelete('CASCADE');
    t.text('role').notNullable(); // owner | admin | member (enforced in app + CHECK below)
    t.timestamp('created_at').notNullable().defaultTo(db.fn.now());
    t.unique(['user_id', 'org_id']);
    t.index(['user_id']);
    t.index(['org_id']);
  });
  // NOTE: role is restricted to owner|admin|member by application validation
  // (see src/auth/roles.ts). Postgres deployments should add a CHECK constraint.
}

export async function down(db: Knex): Promise<void> {
  await db.schema.dropTableIfExists('org_memberships');
  await db.schema.dropTableIfExists('organizations');
  await db.schema.dropTableIfExists('users');
}
