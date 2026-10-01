import path from 'node:path';
import type { Knex } from 'knex';
import knexFactory from 'knex';

let instance: Knex | null = null;

export interface DbOptions {
  filename?: string;
}

export function createKnex(opts: DbOptions = {}): Knex {
  const filename = opts.filename ?? process.env.DATABASE_URL ?? './dev.sqlite3';
  const db = knexFactory({
    client: 'better-sqlite3',
    connection: { filename },
    useNullAsDefault: true,
    // :memory: databases are per-connection — keep a single connection.
    pool: filename === ':memory:' ? { min: 1, max: 1 } : { min: 1, max: 4 },
    migrations: {
      directory: path.resolve(process.cwd(), 'src/db/migrations'),
      extension: 'ts',
    },
  });
  return db;
}

export function getDb(): Knex {
  if (!instance) instance = createKnex();
  return instance;
}

export async function closeDb(): Promise<void> {
  if (instance) {
    await instance.destroy();
    instance = null;
  }
}
