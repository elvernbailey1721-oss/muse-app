# PaintScope Mobile — Architecture

**Built 2026-09-29.** Repo root: `~/workspace/paintscope-mobile/`

```
paintscope-mobile/
├── backend/          # TypeScript + Express + Knex REST API (Node 24)
│   ├── src/
│   │   ├── index.ts            # entrypoint, PORT from env
│   │   ├── app.ts              # Express app, route mounting, /healthz
│   │   ├── config.ts           # env parsing + per-provider config
│   │   ├── crypto.ts           # AES-256-GCM config encryption, hashing
│   │   ├── db/                 # knex.ts, migrate.ts, migrateRunner.ts, migrations/, models.ts
│   │   ├── auth/               # oidc.ts, samlSp.ts, providers.ts, tokens.ts,
│   │   │                       #   linking.ts, middleware.ts, roles.ts
│   │   ├── routes/             # auth.ts, me.ts, devices.ts, scans.ts, admin.ts
│   │   └── services/           # audit.ts, push.ts
│   └── tests/                  # auth.test.ts, rbac.test.ts (+ helpers)
├── app/              # Capacitor.js mobile shell
│   ├── www/          # web bundle (index.html + js/ + media/)
│   ├── src/          # api.ts, config.ts, main.ts, native.ts, secure-storage.ts
│   ├── android/ ios/ # generated native scaffolds (synced)
│   ├── capacitor.config.ts     # appId com.paintscope.app
│   ├── NATIVE_BUILD.md         # human steps for signed builds
│   └── BUILD_NOTES.md          # commands run + outcomes
└── docs/             # this package
```

## Backend design

**Identity model** (migrations `001_core`, `002_providers`, `003_sessions`):

- `users` → `identities` → `providers` → `organizations`
- `org_memberships(user_id, org_id, role ∈ owner|admin|member)`
- `identities` has `UNIQUE(provider_id, provider_sub)` — stable provider subject IDs are the join key, never email.
- `devices` (push tokens per user), `scans` (saved paint scans, org-scoped), `audit_events` (append-only),
  `auth_states` (OAuth state/nonce/PKCE single-use), `refresh_tokens` (hashed, family-bound), `used_assertions` (SAML replay cache).

**Auth flow (OIDC/OAuth2):**
`GET /auth/providers` → `GET /auth/discover?email=` (domain → org → providers) →
`GET /auth/login/:type?redirect=` (exact-allowlisted) → provider → `GET|POST /auth/callback/:type`
(state + nonce + PKCE verification, issuer/audience/signature/JWKS/expiry validation) →
identity lookup by `(provider_id, provider_sub)` → link-or-create via `auth/linking.ts` (verified-email rule) →
JWT access (15 min) + rotating refresh token (hashed, reuse detection revokes family).

**SAML 2.0 (per-org):** `GET /auth/saml/:orgId/login` → IdP → `POST /auth/saml/:orgId/acs`
(strict `InResponseTo`, `used_assertions` replay cache, configurable `nameIdClaim`). SP metadata at
`GET /auth/saml/:orgId/metadata`.

**Key invariants:**
- SSO authenticates only — it never creates `org_memberships`. Roles are granted by explicit owner/admin action (`routes/admin.ts`).
- Tenant isolation is enforced at the query layer (`models.ts`): every org-scoped query filters by the membership's `org_id`. Client-supplied `org_id` is never trusted.
- Secrets never reach logs: `services/audit.ts` allowlists meta fields; no passwords/tokens/codes are logged anywhere.
- Provider secrets in DB are AES-256-GCM encrypted (`CONFIG_ENCRYPTION_KEY`).

## App design

- `www/` is the extracted PaintScope web bundle (the 35.6 MB single-file export split into `index.html` 1.6 MB + `media/` files; behavior untouched).
- Additive bridge `www/js/*.js` (from `src/*.ts`): `main.ts` runs at startup — camera permission → silent session restore (refresh token in secure storage) → push init. Each step failure-isolated; the web app works standalone without the backend.
- `api.ts`: typed REST client, single-flight refresh rotation, one silent retry on 401, `AuthError` → logged-out state.
- Token storage: `@aparajita/capacitor-secure-storage` (iOS Keychain / Android EncryptedSharedPreferences). Web fallback is memory-only, never localStorage.
- `capacitor.config.ts`: `appId com.paintscope.app`, `webDir www`, Android served over `https` scheme.

## Request map (backend)

| Area | Routes |
|---|---|
| Health | `GET /healthz` |
| SSO | `GET /auth/providers`, `GET /auth/discover`, `GET /auth/login/:type`, `GET\|POST /auth/callback/:type`, `POST /auth/refresh`, `POST /auth/logout` |
| SAML | `GET /auth/saml/:orgId/login`, `POST /auth/saml/:orgId/acs`, `GET /auth/saml/:orgId/metadata` |
| Orgs | `POST /orgs`, `POST /auth/org`, admin CRUD under `/orgs/:orgId` |
| Profile | `GET /me`, `PATCH /me` |
| Devices | `GET /devices`, `POST /devices`, `DELETE /devices/:id` |
| Scans | `GET /scans`, `POST /scans`, `GET /scans/:id`, `DELETE /scans/:id` |
