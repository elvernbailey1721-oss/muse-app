# Remaining limitations + exact human steps

## What I could NOT do here (needs Elvern)

1. **Signed native builds.** Needs Android Studio + Xcode on his machine (or CI).
   Exact commands are in `app/NATIVE_BUILD.md`:
   `npx cap add android` / `npx cap add ios` (already synced once), `npx cap sync`,
   `npx cap open android|ios`, then Android Studio → Generate Signed Bundle/APK,
   Xcode → Archive → TestFlight. Everyday web change: `PAINTSCOPE_API_URL=https://… npm run build:bundle && npx cap sync`.
2. **Store submission.** App Store / TestFlight requires his **Apple Developer account ($99/yr)**;
   Play Store needs his Google Play developer account. Nothing published, submitted, or purchased.
3. **Push credentials.** FCM service-account JSON + APNs `.p8` key — his to supply (checklist in `docs/PUSH_SETUP.md`).
4. **IdP app registrations.** For each provider he wants live: create the OAuth/OIDC app at the provider,
   set redirect URI `<APP_BASE_URL>/auth/callback/<provider>`, put client id/secret in env or DB.
5. **User-facing permission copy.** Paste the exact `Info.plist` / `AndroidManifest.xml` snippets from
   `app/docs/ios-setup.md` and `app/docs/android-setup.md` (left for him deliberately — it's user-facing text).
6. **Native OAuth handoff.** The app must open login in the system browser / ASWebAuthenticationSession, not the
   WebView — wire `api.ts`'s login URL to that at native-integration time.

## Known product limitations

- Microsoft multi-tenant `common` deliberately unsupported (issuer can't validate) — use explicit tenant id.
- Apple returns name/email only on first consent; later logins carry just the `sub`.
- GitHub users with no verified email get `users.email = NULL` (linking then impossible — by design).
- SAML needs `nameIdClaim` configured for transient NameIDs.
- Access-token revocation costs one DB lookup per request (fine at this scale).
- `used_assertions` / `auth_states` need TTL pruning before long-term production use.
- Postgres requires installing the `pg` driver (SQLite ships in deps); only SQLite was exercised in tests.
- No on-device verification yet: camera, push, and secure-storage behavior on a real phone are unproven
  until he builds and installs the native app.
- iOS dev caveat: WebKit ignores `upgrade-insecure-requests` for `http://localhost`, so dev API calls must be
  `https://` on real iPhones (documented in `app/NATIVE_BUILD.md`).

## Suggested next order

1. Deploy backend to Replit (`docs/PRODUCTION.md`) with at least Google SSO enabled.
2. Register IdP apps, set redirect URIs.
3. Supply FCM + APNs credentials.
4. `npx cap open ios/android` → paste permission snippets → build signed → install on his phone.
5. Ear/eye test on the real phone, then TestFlight/Play internal track.
