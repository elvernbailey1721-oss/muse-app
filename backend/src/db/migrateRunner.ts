import type { Knex } from 'knex';
import * as m001 from './migrations/001_core.js';
import * as m002 from './migrations/002_providers.js';
import * as m003 from './migrations/003_sessions.js';

const MIGRATIONS: Array<{ name: string; up: (db: Knex) => Promise<void> }> = [
  { name: '001_core', up: m001.up },
  { name: '002_providers', up: m002.up },
  { name: '003_sessions', up: m003.up },
];

export async function runMigrations(db: Knex): Promise<string[]> {
  const hasTable = await db.schema.hasTable('schema_migrations');
  if (!hasTable) {
    await db.schema.createTable('schema_migrations', (t) => {
      t.text('name').primary();
      t.timestamp('applied_at').notNullable().defaultTo(db.fn.now());
    });
  }
  const rows = await db('schema_migrations').select('name');
  const appliedSet = new Set(rows.map((r) => String(r.name)));
  const applied: string[] = [];
  for (const m of MIGRATIONS) {
    if (appliedSet.has(m.name)) continue;
    await m.up(db);
    await db('schema_migrations').insert({ name: m.name });
    applied.push(m.name);
  }
  return applied;
}
