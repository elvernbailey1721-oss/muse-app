# Providers implemented

All nine providers from the spec are implemented in `backend/src/auth/` and are **independently
configurable** — each can be enabled/disabled without touching the others (`*_ENABLED=false` = fail closed).
Provider configs live in `providers` table rows and/or `<PROVIDER>_*` env vars; secrets are AES-256-GCM
encrypted at rest. Org-specific OIDC/SAML rows can be added per organization without redesign
(`providers.org_id`, plus `routes/admin.ts` endpoints).

RESEARCH RULE was applied: every issuer/discovery endpoint below was verified against current official
provider docs and the installed dependency's actual API. Two findings forced real fixes (see SECURITY.md).

| Provider | Type | Key files | Notes |
|---|---|---|---|
| Google | OIDC | `auth/oidc.ts`, `auth/providers.ts` | Discovery `https://accounts.google.com/.well-known/openid-configuration`; issuer `https://accounts.google.com`; `email` + `email_verified` from id_token |
| Microsoft Entra ID | OIDC | `auth/oidc.ts` | **Requires `MICROSOFT_TENANT_ID`.** The `common` endpoint publishes a templated issuer (`…/{tenantid}/v2.0`) that cannot validate id_tokens, so multi-tenant `common` is deliberately unsupported — fail closed |
| Apple | OIDC (fixed endpoints) | `auth/oidc.ts` | Apple publishes no discovery doc: uses documented fixed `/auth/authorize`, `/auth/token`, `/auth/keys`; `skipDiscovery` default true; claims come from id_token; name/email only on first consent |
| GitHub | OAuth2 | `auth/oidc.ts`, `auth/providers.ts` | Authorization Code + PKCE; profile from user API; users with no verified email get `users.email = NULL` |
| LinkedIn | OIDC | `auth/oidc.ts` | OIDC discovery; `email` + `email_verified` claims |
| Okta | OIDC | `auth/oidc.ts` | Issuer URL from config (org subdomain) |
| Auth0 | OIDC | `auth/oidc.ts` | Issuer URL from config (tenant domain) |
| Generic OIDC | OIDC | `auth/oidc.ts` | Issuer URL from config; endpoint overrides supported (`*_SKIP_DISCOVERY`, `*_AUTHORIZATION_ENDPOINT`, etc.) |
| Enterprise SAML 2.0 | SAML | `auth/samlSp.ts` | Per-organization via node-saml (maintained lib); strict `InResponseTo`; `used_assertions` replay cache; `nameIdClaim` configurable for transient NameIDs; SP metadata endpoint per org |

## Changed/new files (backend)

- `src/auth/oidc.ts` — generic Authorization Code + PKCE client, JWKS validation, claim mapping
- `src/auth/samlSp.ts` — per-org SAML service provider
- `src/auth/providers.ts` — provider registry, enable/disable, discovery
- `src/auth/linking.ts` — identity link/create rules (verified-email gate, no unsafe merge)
- `src/auth/tokens.ts` — JWT access + rotating hashed refresh tokens (atomic rotation)
- `src/auth/middleware.ts`, `src/auth/roles.ts` — auth, default-deny RBAC, tenant scoping
- `src/routes/auth.ts` — login/discover/callback/refresh/logout/SAML routes
- `src/routes/admin.ts` — org + membership + provider admin
- `src/routes/me.ts`, `src/routes/devices.ts`, `src/routes/scans.ts` — app API
- `src/services/audit.ts`, `src/services/push.ts` — audit allowlist, FCM send path
- `src/db/migrations/{001_core,002_providers,003_sessions}.ts` — full schema
- `src/config.ts`, `src/crypto.ts` — env parsing, encryption

## Claim mapping

Per-provider `*_CLAIM_MAPPING` JSON maps IdP claims → profile fields (e.g. `{"name":"name","picture":"avatar_url"}`).
SAML attribute → claim mapping uses `nameIdClaim` plus configurable attribute map.

## Certificate/key rotation

Providers accept multiple active JWKS keys (standard `kid` selection). For SAML, org provider configs
support storing a rotation window with old + new certificates; SP metadata endpoint reflects the current set.
