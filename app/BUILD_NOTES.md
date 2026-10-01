# BUILD_NOTES — PaintScope Mobile shell

Exact commands run on the Linux build VM (Node v24.20.0, npm 10.9.4),
2026-09-29. Outcomes recorded verbatim.

## 1. Web bundle extraction

Source: `~/workspace/your_files/paintscope/paintscope.html`
(35,607,899 bytes, exported 2026-09-29 — the verified current build).

Inspection found 34 `data:application/octet-stream;base64` URIs:
- 30 radio tracks in the `radioLibrary` JS literal (6 stations × 5)
- 1 origin-story video (`<video>` source) + 1 duplicate of it (`videoFallback` href)
- 1 `speakerPrimer` audio element src (4.4 KB silent MP3)
- 1 `radioAudio` element initial src (byte-identical to the "Midnight Gallery" track)

Plus 5 small `data:image/*` URIs (webp thumbnails, jpeg poster) — intentionally
left inline (a few KB each).

```
node tools/extract-media.mjs
# -> { matches: 34, uniqueFiles: 32, duplicatesDeduped: 2,
#      totalMediaBytes: 22869371, indexHtmlBytes: 1632687 }
# -> OK: all hashes verified, all references resolve.
```

Notes:
- First run named the deduped radio blob `media/radio-initial.mp3`; fixed the
  script to write track entries first so duplicates reuse the meaningful track
  filename (`media/radio/jazz/midnight-gallery.mp3`), then re-ran clean.
- Every blob: magic-byte sniffed (ID3→`.mp3`, `ftyp`→`.mp4`), SHA-256 hashed,
  written to `www/media/`, re-read and hash-compared. `www/media/MANIFEST.json`
  records file/bytes/sha256 for all 32 files.
- Result: `www/index.html` 1.63 MB (was 35.6 MB), zero remaining
  `data:application/octet-stream` URIs, all 32 media references resolve on disk.
- No JS logic inspects `data:` URIs (`startsWith('data`/`indexOf('data:`/`atob`
  all absent); tracks are consumed via plain `radioAudio.src = track[1]`, so
  relative paths are behavior-preserving.

## 2. Scaffold

```
npm init -y
npm pkg set name="@paintscope/mobile" version="1.0.0" private=true
npm install @capacitor/core @capacitor/cli @capacitor/camera \
  @capacitor/push-notifications @aparajita/capacitor-secure-storage
npm install -D typescript
```

Installed: `@capacitor/core@8.5.2`, `@capacitor/cli@8.5.2`,
`@capacitor/camera@8.2.4`, `@capacitor/push-notifications@8.1.2`,
`@aparajita/capacitor-secure-storage@8.0.1`, `typescript@7.0.2`.

## 3. Web bridge build

```
node tools/build-web.mjs
# first run: FAILED — tsc error TS2367 in src/native.ts
#   (PermissionState has no 'limited'; the Camera plugin defines
#   CameraPermissionState = PermissionState | 'limited')
# fix: import CameraPermissionState from '@capacitor/camera' (type-only)
# second run: OK
# -> { apiUrl: "http://localhost:3000", apiOrigin: "http://localhost:3000",
#      tokenReplacedInFiles: 1, bridgeInjected: true, cspExtended: true }
```

What `build-web.mjs` does (after `extract-media.mjs`, which regenerates
`www/index.html`):
1. `npx tsc` → `www/js/` (api, config, main, native, secure-storage).
2. Replaces the `__PAINTSCOPE_API_URL__` token with `$PAINTSCOPE_API_URL`
   (default `http://localhost:3000`).
3. Injects `<script type="module" src="js/main.js"></script>` before `</body>`.
4. Extends the CSP meta tag **minimally**: `script-src` gains `'self'`
   (the existing inline-script sha256 hash is untouched), `connect-src` gains
   the API origin. All other directives byte-identical.

## 4. Native platforms + sync

```
npx cap add android   # ✔ success — 3 plugins found for android
npx cap add ios       # ✔ success — 3 plugins found for ios (Package.swift)
npx cap sync          # ✔ exit 0 — android + ios updated, web assets copied
```

`cap sync` copies 41 files to `android/app/src/main/assets/public` and
`ios/App/App/public` (index.html, 5 js, 32 media, MANIFEST.json, cordova shims).

## 5. Verification

- `npx tsc --noEmit` → clean (no output).
- `npx cap sync` → exit 0, both platforms, 3/3 plugins each.
- Bundle: 34/34 data URIs extracted; 32/32 written files hash-verified on
  re-read against source base64; 0 leftover `data:application/octet-stream`;
  all `media/…` references in `www/index.html` resolve on disk.
- Full pipeline re-run (`extract-media` → `build-web`) is idempotent.

## 6. Build-script fixes found during verification

Two real bugs were caught and fixed before delivery:
1. **Token collision** — the first `build-web.mjs` did a blind string replace
   of `__PAINTSCOPE_API_URL__`, which also rewrote the runtime property access
   `globalThis.__PAINTSCOPE_API_URL__` into `globalThis."http://…"` (syntax
   error). Fixed: the build token is now the distinct identifier
   `__PAINTSCOPE_API_URL_BUILD__`, the runtime key is read via bracket
   notation, and `build-web.mjs` runs `node --check` over every emitted file.
2. **CSP origin accumulation** — rebuilding with a different
   `$PAINTSCOPE_API_URL` appended the new origin to `connect-src` without
   removing the old one. Fixed: `connect-src` is normalized to exactly
   `'self'` + the current API origin on every build.

## 7. Not done here (human steps)

- No signed `.apk`/`.aab`/`.ipa` — needs Android Studio + Xcode (see NATIVE_BUILD.md).
- No headless browser smoke test — no Chromium on this VM; verification was
  static (hash + reference + structural checks). The bundle is byte-identical
  web behavior to the published artifact plus the additive `js/main.js` bridge.
- `Info.plist` usage descriptions and `AndroidManifest.xml` permissions were
  deliberately left for the human (exact snippets in `docs/`).
