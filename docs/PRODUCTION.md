# Production setup — Replit + custom domain

## 1. Create the Replit

1. New Repl → import from this repo (`backend/`), or upload `backend/` as a Node.js Repl.
2. Set the run command: `npm run build && npm start` (build once; `npm start` serves `dist/`).
3. Replit provides `PORT` automatically — the server reads it from env. No code change needed.

## 2. Secrets (Replit Secrets tab — never in code)

Set every variable from `docs/ENV.md`: `APP_BASE_URL`, `APP_REDIRECT_ALLOWLIST`, `JWT_SECRET`,
`CONFIG_ENCRYPTION_KEY`, provider credentials, and the Firebase credential (paste the service-account
JSON into `FIREBASE_SERVICE_ACCOUNT_JSON`).

## 3. Database

- **Start:** SQLite file (default `DATABASE_URL`, persists in the Repl).
- **Grow:** switch `DATABASE_URL` to `postgres://…` (Neon/Supabase/etc.) and `npm install pg`.
  SQL is written Postgres-compatible; migrations are knex schema-builder based. Run `npm run migrate` once
  against the new DB.

## 4. Custom domain (optional)

1. Replit → Deployments → custom domain, point your DNS at Replit.
2. Set `APP_BASE_URL=https://api.yourdomain.com` and add it to `APP_REDIRECT_ALLOWLIST`.
3. Re-register the OAuth redirect URIs at each IdP:
   `<APP_BASE_URL>/auth/callback/<provider>` (e.g. `…/auth/callback/google`).
4. SAML: per-org SP metadata at `GET /auth/saml/:orgId/metadata` — hand that XML to each org's IdP admin.

## 5. Point the app at it

```sh
cd app
PAINTSCOPE_API_URL=https://api.yourdomain.com npm run build:bundle
npx cap sync
```

Production API **must be https://** — iOS WebKit does not honor the `upgrade-insecure-requests`
exception for `http://localhost` that Android Chromium allows.

## 6. Smoke test

```sh
curl https://api.yourdomain.com/healthz
curl "https://api.yourdomain.com/auth/providers"   # only enabled providers listed
```
