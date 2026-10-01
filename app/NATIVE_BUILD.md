# NATIVE_BUILD — what I could not do here, and your exact steps

This Linux VM cannot produce signed native binaries and has no Apple/Google
developer identities. Everything below is yours (or CI's) to run. Nothing has
been published, submitted, or purchased.

## What requires your machine / accounts

| Need | Why I couldn't do it |
|---|---|
| Signed `.apk` / `.aab` | Needs Android Studio + Android SDK + your keystore |
| Signed `.ipa` / TestFlight / App Store | Needs Xcode on a Mac + Apple Developer Program ($99/yr) |
| Push notifications end-to-end | Needs your FCM service account (Android) and APNs key (iOS); the backend must be configured with them (coordinates with the sibling `backend/` docs) |
| `Info.plist` usage strings, `AndroidManifest` permissions | Deliberately left for you — exact copy-paste snippets are in `docs/ios-setup.md` and `docs/android-setup.md` |

## One-time native config (do this first)

1. `docs/ios-setup.md` — paste the 3 `Info.plist` usage-description keys;
   add the Push Notifications capability in Xcode; create the APNs key.
2. `docs/android-setup.md` — add `CAMERA` + `POST_NOTIFICATIONS` to
   `AndroidManifest.xml`; drop `google-services.json` into `android/app/`.

## Everyday commands (from `~/workspace/paintscope-mobile/app/`)

```bash
# Rebuild the web bundle from the latest exported paintscope.html,
# compile the TS bridge, inject it, then push everything to both platforms:
npm run build:bundle        # = extract-media + build-web
npx cap sync

# Point the API client at a non-default backend (dev LAN IP, staging, prod):
PAINTSCOPE_API_URL=https://api.paintscope.example.com npm run build:bundle
npx cap sync
# (Production MUST be https:// — see the CSP notes in docs/*-setup.md.)

# Typecheck only:
npm run typecheck            # tsc --noEmit

# Add a platform later (already added here for android + ios):
npx cap add android
npx cap add ios
```

## Opening the native projects

```bash
npx cap open android   # opens Android Studio
npx cap open ios       # opens ios/App/App.xcworkspace in Xcode (use the .xcworkspace, not .xcodeproj)
```

## Release builds

**Android** (Android Studio): Build → Generate Signed Bundle/APK → create or
choose your keystore → build the `.aab` → upload to Play Console. Or via CLI:

```bash
cd android && ./gradlew bundleRelease
# signs with the keystore configured in android/key.properties (you create this)
```

**iOS** (Xcode, Mac required): select the `App` scheme → Product → Archive →
Distribute App → App Store Connect / TestFlight. Requires the Apple Developer
Program membership ($99/yr) and the bundle id `com.paintscope.app` registered
under your Team.

## Push notification checklist (both platforms)

- [ ] Android: `android/app/google-services.json` from Firebase (package
      `com.paintscope.app`); backend holds the FCM service account key.
- [ ] iOS: Push Notifications capability enabled; APNs `.p8` key created;
      backend (or Firebase) configured with Key ID + Team ID + bundle id.
- [ ] Backend implements `POST /devices` (the app registers `{ platform,
      pushToken, appVersion }` on login when a push token exists).
- [ ] Test: send a test push from Firebase Console / backend to the registered
      `pushToken`; confirm foreground presentation + tap handling.

## Secure storage fallback plan

Primary: `@aparajita/capacitor-secure-storage@8.0.1` (verified maintained —
published 2026-09-23; iOS Keychain `whenUnlocked`, Android
EncryptedSharedPreferences via Keystore). If it ever goes unmaintained, the
fallback is a minimal first-party plugin: Swift Keychain wrapper (~120 lines)
+ Kotlin EncryptedSharedPreferences wrapper (~80 lines), registered as
`SecureStorage` with the same `getItem/setItem/removeItem/clear` string API —
`src/secure-storage.ts` needs no changes. `@capacitor/preferences` is
**never** an option for tokens (unencrypted).

## Known limitations

- `www/index.html` is 1.6 MB (JS+CSS from the export); the 22.9 MB of media
  now loads as separate `media/` files instead of one 35.6 MB parse.
- The sibling `backend/` is empty — `src/api.ts` is written against the
  documented contract in its header comment; login/devices/scans calls will
  fail until the backend exists. The web app itself needs no backend.
- On a desktop browser (no Capacitor), `js/main.js` detects the missing native
  runtime and the PaintScope web app runs standalone; the refresh token falls
  back to session memory (warning in console).
- The app id is `com.paintscope.app` — if you already own a different bundle
  id / Play listing, change `appId` in `capacitor.config.ts` **before** first
  store submission (it cannot change afterwards).
