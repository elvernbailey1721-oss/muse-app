# Push setup checklist

The backend sends via **firebase-admin FCM HTTP v1** (`src/services/push.ts`). Credentials are env-only
and were **not** included — Elvern must supply all of these.

## Elvern must supply

- [ ] **FCM service account JSON** — Firebase Console → Project settings → Service accounts → Generate new private key.
      Deploy as `FIREBASE_SERVICE_ACCOUNT_JSON` (paste full JSON) **or** `GOOGLE_APPLICATION_CREDENTIALS` (path).
- [ ] **APNs key (.p8)** — Apple Developer → Certificates, Identifiers & Profiles → Keys → create APNs key.
      Upload the `.p8` + Key ID + Team ID into **Firebase Console → Project settings → Cloud Messaging → Apple app**,
      or configure APNs directly if bypassing FCM for iOS. (Requires the $99/yr Apple Developer account.)
- [ ] **Android:** download `google-services.json` from Firebase Console → place at `app/android/app/google-services.json`,
      then rebuild (`npx cap sync` + Android Studio build).
- [ ] **iOS:** enable Push Notifications capability in Xcode for the `com.paintscope.app` target; upload APNs key to Firebase as above.
- [ ] **User-facing permission copy:** paste the `Info.plist` usage-description strings from `app/docs/ios-setup.md`
      and the `AndroidManifest.xml` permissions from `app/docs/android-setup.md` (exact snippets provided there).

## How it works

1. App registers its FCM/APNs token: `POST /devices {platform: ios|android, token, app_version}` (token in secure storage path, never logged).
2. Backend stores one row per (user, token) in `devices`.
3. `push.ts` sends via FCM HTTP v1 to all of a user's tokens. No credentials configured → send is skipped with a warning (never crashes).
4. Logout / `DELETE /devices/:id` removes the token server-side.

## Test it

1. Deploy backend with the Firebase credential set.
2. Install a dev build on a real phone, sign in (creates a device row).
3. Trigger a send (admin route or direct service call) → notification appears.
   (FCM does not deliver to emulators/simulators reliably — use a real device.)
