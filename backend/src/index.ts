import { loadConfig } from './config.js';
import { createKnex } from './db/knex.js';
import { runMigrations } from './db/migrateRunner.js';
import { createApp } from './app.js';

async function main() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    console.error('Configuration error:', err instanceof Error ? err.message : err);
    console.error('Copy .env.example to .env and fill in the required values.');
    process.exit(1);
  }
  const db = createKnex();
  const applied = await runMigrations(db);
  if (applied.length) console.log('Migrations applied:', applied.join(', '));

  const app = createApp({ db, config });
  const server = app.listen(config.port, () => {
    console.log(`paintscope-mobile-backend listening on :${config.port}`);
  });

  const shutdown = async () => {
    server.close();
    await db.destroy();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  console.error('Startup failed:', err);
  process.exit(1);
});
