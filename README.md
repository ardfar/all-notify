# All-Notify

Personal, self-hosted, **end-to-end encrypted (E2EE)** notification hub: mirror notifications in real time from your **Android phones** to your **other Android phones, Macs, and Windows PCs** over the internet — with two-way dismissal sync, cached app icons, compressed E2EE image attachments, and zero cloud or Firebase dependencies.

```text
Android Phones (Send + Receive) ◄── wss:// + HTTPS E2EE ──► Go VPS Relay ◄── wss:// + HTTPS E2EE ──► macOS & Windows (Receive + Dismiss)
```

---

## Features (`v1.0.0`)

- **Zero-Knowledge Relay (E2EE)**: Every notification payload, app icon, and image attachment is encrypted client-side with `XChaCha20-Poly1305` and domain-separated `HKDF-SHA256` subkeys (`protocol/test_vectors.json` verified across Go, Kotlin, and Rust). The VPS never sees `K_master` or plaintext.
- **Real-Time Mirroring & Two-Way Dismissal Sync**: Dismiss a mirrored notification on macOS (banner **Dismiss** button or menu-bar popover), Windows (Toast **Dismiss** button, native swipe-dismiss, or tray popover), or another Android phone, and the original notification is cancelled everywhere with loop & echo protection.
- **Web Admin Panel & One-Time Pairing Codes (`/admin`)**:
  - Embedded lightweight web UI inside the Go binary (strict CSP, argon2id auth, random first-boot password with forced change, CSRF + rate limiting).
  - `K_master` is generated and kept strictly in browser tab memory (verified via one-way KCV); QRs are rendered client-side with single-use, 10-minute `v=2` pairing codes (`POST /v1/pair/claim`).
  - **Trusted-device "Add device"**: Mark a device trusted to generate one-time pairing QRs directly from your Mac, Windows PC, or Android phone (`FLAG_SECURE` / content protection while displayed).
- **Rich Media with Strict Budgets**:
  - `64×64` WebP app icons cached by `(packageName, sha256)` — fetched only on cache miss.
  - Image attachments (`BigPictureStyle` / `MessagingStyle`) downscaled on Android (`≤800px`, `≤512 KB`), encrypted, and relayed via 24h-TTL HTTPS blobs (`256 MB` server cap).
- **Noise Control & Anti-Popup-Storm**:
  - Skips ongoing, foreground-service, group-summary, `MediaStyle`/`CATEGORY_TRANSPORT`, and low-priority notifications by default, with per-app filter toggles on Android.
  - **5-second cross-device deduplication** merges identical notifications arriving on two phones into a single entry; dismissing clears both phones.
  - **Offline replay** buffers events until `replay_complete`, silently archives already-dismissed items, and pops only still-active ones (collapsing `>5` into a summary).
  - **Android DND & OEM resilience**: Posts mirrored notifications silently (`setSilent(true)`) into the shade while Do Not Disturb is active, and automatically invokes `NotificationListenerService.requestRebind()` after OEM battery-saver kills.
- **Lightweight Stack**:
  - **Server (`server/`)**: Single static Go binary (`modernc.org/sqlite` WAL, zero CGO) + Docker/Caddy auto-TLS.
  - **Android (`android/`)**: Native Kotlin + Jetpack Compose + Room + OkHttp Foreground Service + ZXing QR (no Google Play Services / Firebase).
  - **Desktop (`desktop/`)**: Tauri v2 (Rust + vanilla JS/CSS tray/menu-bar app, OS Keychain / Credential Manager, ad-hoc signed macOS `.app`/`.dmg` + Windows `.msi`/`.exe`).

---

## Quick Start

### 1. Deploy the VPS Relay Server
Download the container image from GHCR (`ghcr.io/ardfar/all-notify-server:v1.0.0`) or static Linux binaries from [Releases](https://github.com/ardfar/all-notify/releases):

```bash
cd server
cp .env.example .env              # set ALLNOTIFY_DOMAIN=notify.yourdomain.com
mkdir -p data && sudo chown 10001:10001 data
docker compose --profile tls up -d
docker compose logs all-notify-server | grep "ADMIN INITIAL PASSWORD"
```

1. Open `https://notify.yourdomain.com/admin` and sign in with the one-time initial password from the logs.
2. Set your permanent admin password (minimum 12 characters).
3. Generate (or import) your `K_master` in the browser and save it in your password manager — **the server never stores it**.
4. Click **Add Device** to create a one-time pairing QR code.

> See [docs/SERVER.md](docs/SERVER.md) and [docs/PAIRING.md](docs/PAIRING.md) for reverse-proxy setup (Nginx/Caddy), CLI commands (`admin reset-password`, `pair create`), and GHCR auto-deploy.

### 2. Install & Pair Clients
Download installers from the latest [GitHub Release](https://github.com/ardfar/all-notify/releases):
- **Android**: Sideload `app-release.apk`, grant Notification Access, Post Notifications, and Battery Optimization exemption, then scan the QR code from `/admin` (or from a trusted desktop/phone).
- **macOS**: Open `All-Notify_1.0.0_aarch64.dmg`, drag **All-Notify** to `/Applications`, launch it, allow macOS Notifications, and paste the pairing link or drop the QR PNG.
- **Windows**: Run `All-Notify_1.0.0_x64_en-US.msi` (or `.exe`), paste the pairing link or drop the QR PNG.

---

## Repository Layout

```text
all-notify/
├── docs/               # Architecture, protocol, pairing, server, Android, desktop specs
├── protocol/           # JSON schemas & cross-language E2EE + KCV + v1/v2 pairing test vectors
├── server/             # Go relay server, SQLite queue, E2EE blob store, embedded /admin UI
├── android/            # Native Kotlin Android client (NotificationListener + Foreground Service)
├── desktop/            # Tauri v2 desktop tray app for macOS & Windows
└── tests/live_e2e/     # Hardware-in-the-loop E2E test suite (2 Android phones + MacBook + /admin)
```

---

## Development & Verification

```bash
# Protocol test vectors
cd protocol && go test -v ./...

# Go VPS relay server
cd server && go test -race -v ./...

# Android client
cd android && ./gradlew testDebugUnitTest lintDebug assembleDebug

# Desktop client (unit tests + live Go relay E2E matrix)
cd desktop/src-tauri && cargo clippy --all-targets -- -D warnings && cargo test

# Hardware-in-the-loop live verification (2 ADB phones + MacBook + /admin)
python3 tests/live_e2e/run_live_suite.py --suite all
```

---

## Documentation

Full technical specifications live in [`docs/`](docs/README.md):
- [Architecture & Data Flows](docs/ARCHITECTURE.md)
- [Wire Protocol & E2EE Specification](docs/PROTOCOL.md)
- [Pairing Web UI & One-Time Pairing Codes](docs/PAIRING.md)
- [Go VPS Relay Server](docs/SERVER.md)
- [Android Client](docs/ANDROID.md)
- [Desktop Client (macOS & Windows)](docs/DESKTOP.md)
- [Phased Roadmap](docs/ROADMAP.md) & [Implementation Plan](docs/IMPLEMENTATION_PLAN.md)
