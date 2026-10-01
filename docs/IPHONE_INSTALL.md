# Install PaintScope on your iPhone from your Chromebook (free, no Mac)

You already have: the unsigned `.ipa` from Codemagic's build Artifacts tab
(see `codemagic.yaml` for the build setup), downloaded into your Chromebook's
Linux files.

## One-time Chromebook setup (~15 minutes)

1. **Turn on Linux.** Settings → About ChromeOS → Developers → Linux
   development environment → Turn on.
2. **Share your iPhone's USB with Linux.** With the iPhone plugged in, go to
   Settings → About ChromeOS → Developers → Linux development environment →
   **Manage USB devices** → select your iPhone and enable it. You may need to
   do this quickly before ChromeOS claims the device (a known timing quirk).
3. **Get the signing tool.** In the Linux terminal, use SideStore's `iloader`
   AppImage (their official docs include a Chromebook-specific guide) or
   AltServer-Linux. Both are free.
4. **Install it on the phone:** `chmod +x iloader*.AppImage` then run it,
   point it at your `PaintScope-unsigned.ipa`, and sign in with a **free**
   Apple ID when prompted. This uses Apple's own personal-team provisioning —
   the same mechanism Xcode uses — so it is legitimate, not a hack.

## On your iPhone

- When install finishes: Settings → General → VPN & Device Management →
  trust the developer certificate with your Apple ID.
- Open PaintScope. The app works fully except **push notifications** and
  iCloud — those require the $99/yr paid Apple Developer account.

## The two catches, plainly

1. **Free signing expires every 7 days.** The app stops opening until you
   re-sign it. Run the tool again on your Chromebook — takes about 2 minutes.
2. **3 apps per device** on a free Apple ID, and no TestFlight/App Store.
   When you want push notifications or store distribution, that is when the
   $99/yr Apple Developer Program becomes necessary — nothing in the app code
   needs to change for it.

## If the USB step fails

USB pass-through reliability varies by Chromebook model and ChromeOS version.
If Linux cannot see the iPhone, try a different cable/port, reboot, and
re-enable the USB device. This is a ChromeOS limitation, not the app.
