import { createKnex } from './knex.js';
import { runMigrations } from './migrateRunner.js';

async function main() {
  const db = createKnex();
  try {
    const applied = await runMigrations(db);
    console.log('Migrations applied:', applied.length ? applied : '(none — already up to date)');
  } finally {
    await db.destroy();
  }
}

main().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
