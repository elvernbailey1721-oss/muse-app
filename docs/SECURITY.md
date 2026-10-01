# Security findings + adversarial review

Threat model from the spec was implemented and then adversarially reviewed. Findings below are
**fixed and tested**, not just noted.

## Findings fixed during the build

1. **Microsoft `common` endpoint = issuer confusion.** The `common` discovery document publishes a templated
   issuer (`https://login.microsoftonline.com/{tenantid}/v2.0`) that can never match a real id_token `iss`.
   Accepting it would have meant skipping issuer validation. **Fix:** provider fails closed without an explicit
   `MICROSOFT_TENANT_ID`; multi-tenant `common` deliberately unsupported. (Found via research rule — official docs.)
2. **Apple discovery URL was fictional.** Apple publishes no OIDC discovery document; a default
   `/.well-known/openid-configuration` URL would 404 and block Apple login entirely. **Fix:** documented fixed
   endpoints (`/auth/authorize`, `/auth/token`, `/auth/keys`), `skipDiscovery` default true, claims from id_token.
3. **Non-atomic refresh rotation = token race.** Read-then-write rotation let two concurrent requests both succeed.
   **Fix:** single-transaction conditional claim (`UPDATE … WHERE id AND revoked=false`); losers are treated as
   reuse → whole family revoked. Tested with a 5-way concurrent race.
4. **SQLite-only boolean predicate broke Postgres portability.** `whereRaw('revoked = 0')` errors on Postgres
   booleans. **Fix:** dialect-portable knex predicates; app-generated UUIDs; knex schema builder everywhere.

## Standing mitigations (implemented, tested where marked)

- **Account takeover:** identity key is `(provider_id, provider_sub)` UNIQUE; email is never the join key.
- **Malicious linking:** email linking only with verified email **and** explicit per-provider allow flag; otherwise
  fail closed. (tested: unsafe-merge rejection)
- **Token/code substitution:** auth codes single-use (`auth_states`); access tokens family-bound to refresh tokens.
- **Issuer confusion:** `iss` validated against expected per-provider value; discovery over https only (test-only http flag).
- **Replay:** nonce single-use; SAML assertions cached in `used_assertions`; strict SAML `InResponseTo`.
- **CSRF:** `state` bound to the login attempt; SameSite=strict where cookies are used.
- **Open redirects:** post-login `?redirect=` matched **exactly** (byte-for-byte) against `APP_REDIRECT_ALLOWLIST`; server never redirects itself.
- **Privilege escalation:** SSO creates zero memberships (tested); role changes require owner via `routes/admin.ts`.
- **Tenant escape:** `org_id` always from session membership, never client input (tested).
- **Stale/disabled identities:** provider `enabled` + identity revocation checked on each login; disabled provider rejected pre-redirect (tested).
- **Session fixation:** tokens minted fresh on login; logout revokes the whole refresh family server-side (tested).
- **Logout failures:** revocation is server-side; a failed client clear still leaves the family dead.
- **Audit hygiene:** `services/audit.ts` allowlists meta fields — no passwords, secrets, tokens, or codes can be logged.
- **Config encryption:** provider secrets AES-256-GCM at rest (`CONFIG_ENCRYPTION_KEY`).

## Adversarial review notes (residual risks — see also LIMITATIONS.md)

- Access-token revocation is checked per request = one DB lookup per request; acceptable at this scale, revisit with a denylist cache if traffic grows.
- `used_assertions` and `auth_states` need TTL pruning in production (add a scheduled cleanup before long-term use).
- Client secrets for providers live in env/DB — rotation is manual (documented rotation path exists for certs/keys; client-secret rotation is an ops procedure).
- The mobile app's OAuth flow must use the system browser / ASWebAuthenticationSession (not the WebView) at integration time — the current `api.ts` returns the login URL; the native handoff is a documented human step.
