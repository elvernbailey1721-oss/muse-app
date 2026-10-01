# iOS native setup — manual steps (Xcode required)

These edits live in the generated `ios/` project. They survive `npx cap sync`
(Capacitor never overwrites `Info.plist`), so this is a one-time setup.

## 1. Camera / photo usage descriptions — `ios/App/App/Info.plist`

The Camera plugin **will crash / be rejected** without these. Add inside the
top-level `<dict>`, e.g. right after the `LSRequiresIPhoneOS` entry:

```xml
<key>NSCameraUsageDescription</key>
<string>PaintScope needs camera access to scan your wall colors.</string>
<key>NSPhotoLibraryUsageDescription</key>
<string>PaintScope needs photo library access to open and save scan photos.</string>
<key>NSPhotoLibraryAddUsageDescription</key>
<string>PaintScope needs permission to save scan photos to your library.</string>
```

Notes:
- `NSMicrophoneUsageDescription` is **not** needed — the scanner captures
  stills/previews, never video with audio.
- The strings above are user-facing App Store review copy — reword freely,
  but keep them specific about *why* the camera is used.
- `js/main.js` calls `ensureCameraPermission()` once at startup (check first,
  prompt only if undecided), so the prompt appears on first launch.

## 2. Push Notifications capability — Xcode

1. Open `ios/App/App.xcworkspace` in Xcode (NOT the `.xcodeproj`).
2. Select the `App` target → **Signing & Capabilities** → **+ Capability** →
   **Push Notifications**.
3. Add **Background Modes** → check **Remote notifications** (only needed if
   you want background push handling; foreground presentation is configured
   in `capacitor.config.ts` under `plugins.PushNotifications`).

## 3. APNs — Apple Developer account required ($99/yr)

1. At https://developer.apple.com/account/resources/authkeys/list create an
   **Apple Push Notifications service (APNs)** key (`.p8`). Download it once —
   Apple shows it only once. Note the **Key ID** and **Team ID**.
2. Give the `.p8` + Key ID + Team ID + bundle id `com.paintscope.app` to the
   backend operator (see `../backend` docs when they exist): the server needs
   them to send pushes. Alternatively register the key in Firebase and let the
   backend use FCM for both platforms.

## 4. Dev-loop notes

- Local HTTP backend (`http://localhost:3000`): iOS App Transport Security
  exempts loopback, so plain `http://localhost` works from the Simulator.
  A LAN IP (`http://192.168.x.x:3000`, i.e. a physical phone talking to your
  dev machine) needs an `NSAppTransportSecurity` → `NSExceptionDomains`
  entry or, simpler, an `https://` dev URL.
- The CSP meta tag in `www/index.html` carries `upgrade-insecure-requests`.
  Chromium honors the loopback exemption for `http://localhost`; **WebKit
  (iOS) does not** — on a real iPhone, dev API calls to `http://localhost`
  would be rewritten to `https://` and fail. Production API URLs must be
  `https://` regardless (set `$PAINTSCOPE_API_URL` at build time).
- After editing the web bundle: `npx cap sync` (or `npx cap copy`) then
  re-run from Xcode.
