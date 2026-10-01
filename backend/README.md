# PaintScope Mobile backend

REST API backend for the PaintScope mobile app. TypeScript + Express + Knex.
Local dev runs on SQLite; SQL is written to stay portable to Postgres.

## Quick start (Replit-friendly)

```bash
cp .env.example .env        # fill in real values; NEVER commit .env
npm install                 # once
npm run migrate             # create/upgrade the database
npm run dev                 # tsx watch, PORT from .env (default 4000)
# or: npm run build && npm start
```

- `PORT` — listen port.
- `npm run migrate` — apply pending migrations (idempotent, journaled).
- `npm test` — vitest (SQLite `:memory:`).

## Auth routes

| Method | Path | Notes |
|---|---|---|
| GET | `/healthz` | liveness |
| GET | `/auth/providers` | enabled providers (public, non-secret metadata) |
| GET | `/auth/discover` | server discovery (callback URL, provider list) |
| GET/POST | `/auth/login/:type` | start OIDC/OAuth2 flow (`type`: google, microsoft, apple, github, linkedin, okta, auth0, oidc) |
| GET/POST | `/auth/callback/:type` | authorization-code callback (Apple uses `form_post`) |
| GET | `/auth/saml/:orgId/login` | SAML AuthnRequest |
| POST | `/auth/saml/:orgId/acs` | SAML assertion consumer |
| GET | `/auth/saml/:orgId/metadata` | SP metadata |
| POST | `/auth/refresh` | rotate refresh token (atomic, reuse-detecting) |
| POST | `/auth/logout` | revoke refresh family (auth required) |
| POST | `/auth/org` | switch active organization (auth required) |

## API routes (Bearer access token required)

| Method | Path | Notes |
|---|---|---|
| GET/PATCH | `/me` | current user profile |
| GET/POST | `/devices` | register / list own devices |
| DELETE | `/devices/:id` | remove own device |
| GET/POST | `/scans` | tenant-scoped scan records |
| GET/DELETE | `/scans/:id` | tenant-scoped |

## Admin routes (org role `owner`/`admin` required)

`/orgs` CRUD, `/orgs/:orgId/members` (add/update/remove roles), `/orgs/:orgId/providers`
(add/update/remove provider configs — SAML is configured here; secrets encrypted at rest).

## Provider matrix (verified 2026-09-29)

| Provider | Protocol | Discovery / endpoints | Identity key | Notes |
|---|---|---|---|---|
| Google | OIDC | `https://accounts.google.com/.well-known/openid-configuration` | `sub` | id_token carries verified email |
| Microsoft Entra | OIDC | `https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration` | `sub` | **tenant ID required** — the `common` endpoint publishes a templated issuer that cannot validate tokens; provider fails closed without it |
| Apple | OIDC (no discovery doc) | fixed `https://appleid.apple.com/auth/*`, JWKS `/auth/keys` | `sub` | client secret is a generated ES256 JWT (team ID/key ID/private key); `form_post` response mode |
| GitHub | OAuth2 (not OIDC) | `https://github.com/login/oauth/{authorize,access_token}`, profile `GET https://api.github.com/user` | `github:<numeric id>` | verified email via `GET /user/emails` (primary+verified); PKCE S256 |
| LinkedIn | OIDC | `https://www.linkedin.com/oauth/.well-known/openid-configuration` | `sub` | issuer `https://www.linkedin.com` |
| Okta | OIDC | `<issuer>/.well-known/openid-configuration` (`https://<org>.okta.com[/oauth2/default]`) | `sub` | issuer must exactly match `iss` |
| Auth0 | OIDC | `<issuer>/.well-known/openid-configuration` (`https://<tenant>.<region>.auth0.com`) | `sub` | standard OIDC |
| Generic OIDC | OIDC | operator issuer or explicit endpoints + `*_SKIP_DISCOVERY` | `sub` | claim mapping via `*_CLAIM_MAPPING` JSON |
| SAML 2.0 | SAML | per-org IdP config (entry point, IdP cert(s), SP entity ID) | configured `nameIdClaim` or NameID | strict `InResponseTo`, signed-assertion + audience checks, assertion replay cache; transient NameIDs rejected without a configured stable attribute |

## Security model

- **Stable identity key is `(provider_id, provider_sub)`** — email is never an identity key.
- **Unverified email never populates `users.email`.** Verified-email linking requires the explicit
  provider flag `*_ALLOW_EMAIL_LINK`; if linking is off and another account owns the verified
  email, the new user gets `users.email = NULL` and the event is audited (`email_collision_deferred`).
- **SSO authenticates only.** It never creates org memberships or grants roles — those are explicit
  admin actions. Org scope on every request comes from the authenticated session/membership.
- Tokens: short-lived JWT access tokens **bound to a refresh family** (`fid`), so logout and
  refresh-token reuse detection invalidate already-issued access tokens immediately.
- Refresh rotation is atomic (single `UPDATE … WHERE token_hash AND NOT revoked`) with
  **reuse detection**: a replayed refresh token revokes the whole family and is audited.
- OIDC/OAuth2: state (single-use, DB), nonce, PKCE S256, issuer/audience/signature/expiry validation,
  id_token `jti` replay cache.
- Post-login redirects are matched **exactly** against `APP_REDIRECT_ALLOWLIST` (full URL, not origin).
- Provider secrets encrypted at rest (AES-256-GCM, `CONFIG_ENCRYPTION_KEY`).
- Audit metadata is allowlisted — tokens, secrets, passwords, codes, nonces, verifiers never logged.
- Push uses FCM HTTP v1 via `firebase-admin` with service-account credentials from env only.

## Environment variables

See `.env.example` for the full annotated list. Key groups:

- `PORT`, `APP_BASE_URL`, `APP_REDIRECT_ALLOWLIST` (exact full URLs), `DATABASE_URL`
- `JWT_SECRET`, `CONFIG_ENCRYPTION_KEY` (64 hex chars each)
- `<PROVIDER>_{ENABLED,CLIENT_ID,CLIENT_SECRET,ALLOW_EMAIL_LINK}` for each provider
- `<PROVIDER>_ISSUER`, `*_SKIP_DISCOVERY`, endpoint overrides (`*_AUTHORIZATION_ENDPOINT`, etc.),
  `*_SCOPES`, `*_CLAIM_MAPPING` (JSON)
- `MICROSOFT_TENANT_ID` (required), `APPLE_{TEAM_ID,KEY_ID,PRIVATE_KEY}`
- `FIREBASE_SERVICE_ACCOUNT_JSON` or `GOOGLE_APPLICATION_CREDENTIALS` for push
- `OIDC_TEST_ALLOW_HTTP=1` — **test-only**, allows plain-HTTP issuers in `openid-client`;
  the test harness sets it for its local mock IdP. Never set in production.

## Database

Three migrations (`001_core`, `002_providers`, `003_sessions`) create 12 tables:
`users`, `organizations`, `org_memberships`, `providers`, `identities`, `devices`,
`scans`, `audit_events`, `auth_states`, `refresh_tokens`, `used_assertions`, `schema_migrations`.

For production Postgres: set `DATABASE_URL` to a `postgres://` URL and install the `pg`
driver (`npm i pg`). Migration SQL and queries avoid SQLite-only constructs.

## Limitations (honest)

- Microsoft Entra requires a tenant ID; multi-tenant `common` is deliberately unsupported.
- Apple name/email arrive only on first consent; later sign-ins carry `sub` + email in the id_token.
- GitHub users with no verified email get `users.email = NULL` (no linking fallback).
- SAML needs an explicit `nameIdClaim` when the IdP issues transient NameIDs.
- Push requires a real Firebase service account; otherwise device registration is stored
  without attempting delivery.
- Access-token revocation is checked against the refresh family on each request (one DB lookup).
