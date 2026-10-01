# Android native setup — manual steps (Android Studio required)

These edits live in the generated `android/` project. They survive
`npx cap sync`, so this is a one-time setup.

## 1. Permissions — `android/app/src/main/AndroidManifest.xml`

Add inside the `<manifest>` element, next to the existing `<!-- Permissions -->`
comment (the file currently declares only `INTERNET`):

```xml
<uses-permission android:name="android.permission.CAMERA" />
<!-- Required on Android 13+ (API 33) for push notifications to display -->
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
```

Optional but recommended — declare the camera hardware feature so the Play
Store filters correctly:

```xml
<uses-feature android:name="android.hardware.camera" android:required="true" />
```

Notes:
- `CAMERA` is a runtime permission: `js/main.js` requests it once at startup
  via the Capacitor Camera plugin (check first, prompt only if undecided).
- `POST_NOTIFICATIONS` is requested by the PushNotifications plugin when
  `initPushNotifications()` runs.

## 2. Firebase / FCM — `google-services.json` (push prerequisite)

1. In the Firebase console create a project, add an Android app with package
   name **`com.paintscope.app`**, and download **`google-services.json`**.
2. Place it at **`android/app/google-services.json`** (next to `build.gradle`).
3. The backend needs the Firebase **service account** (Project settings →
   Service accounts → Generate new private key) to send pushes — hand it to
   the backend operator, never commit it to git.

Without `google-services.json`, `PushNotifications.register()` fails and the
app logs `[paintscope-mobile] Push registration failed: ...` — everything
else keeps working.

## 3. Dev-loop notes

- The dev backend default is `http://localhost:3000`.
  - **Emulator:** `localhost` is the emulator itself — point the build at
    `http://10.0.2.2:3000` instead:
    `PAINTSCOPE_API_URL=http://10.0.2.2:3000 node tools/build-web.mjs && npx cap sync`
  - **Physical device:** use your machine's LAN IP (`http://192.168.x.x:3000`).
- Cleartext `http://` to non-loopback hosts is blocked by Android's default
  network security policy. For local dev only, you may add
  `android:usesCleartextTraffic="true"` to the `<application>` tag in the
  manifest — **remove it for release builds**. Release builds must use an
  `https://` API URL (set `$PAINTSCOPE_API_URL` at build time).
- The CSP meta tag in `www/index.html` carries `upgrade-insecure-requests`;
  Chromium (Android WebView) honors the loopback exemption for
  `http://localhost`, so emulator-localhost dev calls are not rewritten.
- After editing the web bundle: `npx cap sync`, then Run in Android Studio.
