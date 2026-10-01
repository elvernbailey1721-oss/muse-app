# Environment variables

Full annotated list lives in `backend/.env.example` — copy it to `.env` and fill in. **Never commit real values.**

## Core

| Var | Required | Purpose |
|---|---|---|
| `PORT` | no (default 4000) | Replit sets this itself — the server reads it from env |
| `APP_BASE_URL` | yes | Public base URL, e.g. `https://paintscope-api.<replit>.repl.co`. Callbacks are built from this |
| `APP_REDIRECT_ALLOWLIST` | yes | Comma-separated FULL URLs allowed as post-login `?redirect=` targets, matched **exactly** (byte-for-byte incl. path+query). Mobile deep link example: `paintscope://auth/done` |
| `DATABASE_URL` | no | SQLite file path for dev; `postgres://…` for Postgres (requires installing `pg`) |
| `JWT_SECRET` | yes | 64 hex chars (`openssl rand -hex 32`) — signs access tokens |
| `CONFIG_ENCRYPTION_KEY` | yes | 64 hex chars — AES-256-GCM for provider secrets at rest |

## Per-provider (`<PROVIDER>` = GOOGLE, MICROSOFT, APPLE, GITHUB, LINKEDIN, OKTA, AUTH0, OIDC)

| Var | Purpose |
|---|---|
| `<PROVIDER>_ENABLED` | `true` to enable; anything else = disabled (fail closed) |
| `<PROVIDER>_CLIENT_ID` / `<PROVIDER>_CLIENT_SECRET` | IdP app credentials |
| `<PROVIDER>_ALLOW_EMAIL_LINK` | `true` permits linking to an existing user on **verified** email only; default false |
| `<PROVIDER>_ISSUER` | Override issuer (Okta/Auth0/generic OIDC) |
| `<PROVIDER>_SCOPES` | Override scopes |
| `<PROVIDER>_CLAIM_MAPPING` | JSON claim → profile field map |
| `<PROVIDER>_SKIP_DISCOVERY`, `<PROVIDER>_AUTHORIZATION_ENDPOINT`, `<PROVIDER>_TOKEN_ENDPOINT`, `<PROVIDER>_USERINFO_ENDPOINT`, `<PROVIDER>_JWKS_URI` | Endpoint overrides |

Provider-specific extras: `MICROSOFT_TENANT_ID` (**required** — Entra ID fails closed without it),
`APPLE_TEAM_ID` / `APPLE_KEY_ID` / `APPLE_PRIVATE_KEY` (client-secret JWT signing).

## SAML (per-org, DB-configured; env defaults optional)

`SAML_DEFAULT_*` vars provide org defaults; each org's provider row holds its IdP metadata URL / certificate,
`nameIdClaim`, and attribute mapping. Rotation: store old + new certs in the row during rollover.

## Push

`FIREBASE_SERVICE_ACCOUNT_JSON` **or** `GOOGLE_APPLICATION_CREDENTIALS` — one of the two, env-only, never in the repo.
Without them, push sends are skipped with a logged warning (`push.ts`).

## Test-only (NEVER in production)

`OIDC_TEST_ALLOW_HTTP=1` — allows http issuers for the mocked IdP in tests. Production refuses non-https issuers.
