# Tests & results

**Independently re-verified 2026-09-29** by re-running the gates (not just the builder's report).

## Backend (`backend/`)

| Gate | Result |
|---|---|
| `npm run migrate` (fresh SQLite DB) | 3 migrations applied: `001_core`, `002_providers`, `003_sessions`; 12 tables created (verified with independent `.tables` recount) |
| `npx tsc --noEmit` | clean, 0 errors |
| `npm run lint` (ESLint) | clean, 0 errors, 0 warnings |
| `npx vitest run` | **32 passed, 0 failed** (2 files: `tests/auth.test.ts` 22, `tests/rbac.test.ts` 10) |
| `npm run build` | success (`dist/` emitted) |

### What the 32 tests cover

- **Provider success/failure** — mocked OIDC IdP (local HTTP issuer + fake JWKS in `tests/helpers/mockIdp.ts`):
  full login creates user + identity; bad auth code rejected; wrong issuer rejected; bad signature rejected.
- **Linking rules** — verified-email link allowed when provider flag on; **unsafe merge on unverified email rejected**;
  same `(provider, sub)` re-login returns the same user; different sub never merges.
- **Invalid state/nonce** — tampered state rejected (CSRF), replayed nonce rejected, single-use auth states enforced.
- **Tenant isolation** — user in org A gets 403/404 on org B's scans; `org_id` from client input ignored.
- **RBAC** — member cannot manage members/providers; admin cannot delete owner; default-deny on unknown routes.
- **Disabled provider** — login attempt on disabled provider rejected before redirect.
- **Logout** — refresh-token family revoked; reused refresh token triggers family-wide revocation.
- **New edge tests** — exact redirect-URL matching (query/path mismatches rejected); Microsoft fails closed without tenant id;
  Apple fixed endpoints (no discovery); SSO creates **zero** org memberships; 5-way concurrent refresh race → exactly one winner.

## App (`app/`)

| Gate | Result |
|---|---|
| Media extraction (`tools/extract-media.mjs`) | 34/34 blobs extracted → 32 unique files (2 deduped); **32/32 SHA-256 re-verified**; 0 leftover `data:application/octet-stream` URIs; manifest `www/media/MANIFEST.json` |
| Byte-integrity spot check (independent) | `www/media/origin-story.mp4` SHA-256 matches a blob in the original export |
| `npx tsc --noEmit` | clean |
| `npx cap sync` | exit 0 — android + ios updated, 3/3 plugins (camera, push-notifications, secure-storage) on both; synced `index.html` byte-identical |
| Bundle size | `index.html` 35.6 MB → **1.6 MB**; media as files under `www/media/` (30 radio mp3 + origin video + speaker primer) |

### Not covered (honest gaps)

- No headless-browser smoke test of the bundle — no Chromium on this VM; verification was static (hash + reference + structural).
- No on-device test of camera/push/secure-storage — needs a real phone + native build.
- No Postgres integration run — SQL is written portable and migrations use the knex schema builder, but only SQLite was exercised.
