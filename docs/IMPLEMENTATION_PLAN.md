# Phased Implementation Plan

This document breaks down the **All-Notify** build into concrete, ordered engineering tasks with exact target paths, implementation details, and verification commands for each phase.

> **Working rule**: Complete and verify each phase's exit checks before starting the next dependent phase. Every component that touches encryption MUST validate against `protocol/test_vectors.json`.

---

## Phase 0: Protocol & Shared Crypto Test Vectors (`protocol/`)

**Goal**: Establish a single source of truth for wire frames, decrypted payloads, pairing URIs, and E2EE primitives before writing any server or client code.

### Tasks

1. **0.1 — JSON Schemas (`protocol/schemas/`)**
   - `protocol/schemas/ws_outer.schema.json`: `relay`, `event`, `replay_complete`, `ack`, `error`.
   - `protocol/schemas/notification_posted.schema.json`: `notification.posted` inner payload (including `app.icon_sha256`, `app.icon_blob_id`, `attachments[]`).
   - `protocol/schemas/notification_dismissed.schema.json`: `notification.dismissed` inner payload (`notification_uids[]`).
2. **0.2 — Deterministic Crypto Test Vectors (`protocol/test_vectors.json`)**
   - Write a small Go generator (`protocol/cmd/genvectors/main.go`) using `golang.org/x/crypto/hkdf` and `golang.org/x/crypto/chacha20poly1305` (`NewX`) to emit `protocol/test_vectors.json` containing:
     - Fixed 32-byte `K_master` (hex + `base64url`)
     - Expected derived `K_event` and `K_blob` via `HKDF-SHA256`
     - Event encryption vector: fixed 24-byte nonce, `event_id`, `sender_device_id`, `AAD`, sample `notification.posted` JSON, expected `base64url(nonce || ct || tag)`
     - Blob encryption vector: fixed 24-byte nonce, `blob_id`, `AAD`, sample bytes, expected raw ciphertext hex
     - Valid and invalid `allnotify://pair?...` URI parsing cases

### Verification
- Run the generator twice and confirm identical deterministic output.
- Validate sample payloads against `protocol/schemas/*.json`.

---

## Phase 1: Go VPS Relay Server (`server/`)

**Goal**: Ship a production-ready, zero-CGO Go binary + Docker setup that authenticates devices, fans out encrypted events, buffers offline queues for 24h, and serves E2EE blobs.

### Tasks

1. **1.1 — Module Scaffold & SQLite Store (`server/internal/store/`)**
   - Initialize `server/go.mod` (`modernc.org/sqlite`, `github.com/coder/websocket`, `github.com/mdp/qrterminal/v3`, `golang.org/x/crypto`).
   - Implement embedded SQL migrations creating `devices`, `offline_events`, and `blobs` tables in WAL mode with foreign keys enabled.
   - Implement repository methods: device CRUD/lookup-by-token-hash, enqueue offline event, query replay slice (`seq > after_seq`), bulk ack delete (`seq <= ack_seq`), blob metadata CRUD, and expired-row cleanup.
2. **1.2 — Auth & CLI (`server/internal/auth/`, `server/cmd/all-notify-server/`)**
   - Token generation (32 random bytes, `base64url`), SHA-256 hashing for DB storage, constant-time bearer middleware.
   - Subcommands:
     - `keygen` (prints random 32-byte `K_master` in `base64url`, never writes to DB)
     - `token create --name <name> --platform <android|macos|windows> [--url <url> --key <k_master>]` (prints device ID, raw token, `allnotify://pair?...` URI, and terminal QR code)
     - `token list` (tabular status with `last_seen` and active/revoked state)
     - `token revoke <device_id>` (sets `revoked_at` and signals active WS disconnect if running)
     - `serve` (starts HTTP/WS server + TTL reaper + graceful `SIGINT`/`SIGTERM` shutdown)
3. **1.3 — WebSocket Hub (`server/internal/hub/`, `server/internal/api/ws.go`)**
   - Single active socket per `device_id` (cleanly closes stale socket on reconnect).
   - 30s server Ping / 90s read deadline.
   - On connect: stream `offline_events` (`seq > after_seq`), then emit `replay_complete`.
   - On `relay`: enforce 64 KB max frame, persist to `offline_events` for every other active device, non-blocking fan-out to online recipients.
   - On `ack`: prune `offline_events` where `seq <= ack.seq` and update `devices.last_seq` / `last_seen`.
4. **1.4 — HTTPS Blob Store & Reaper (`server/internal/blobs/`, `server/internal/api/blobs.go`)**
   - Validate `blob_id` regex (`^[a-zA-Z0-9_-]{8,64}$`).
   - `HEAD /v1/blobs/{id}`: check existence, refresh 24h TTL for `icon_*` blobs.
   - `PUT /v1/blobs/{id}`: enforce `550 KB` cap, atomic temp-file write + rename to `<data_dir>/blobs/<id>.bin`, enforce `ALLNOTIFY_MAX_TOTAL_BLOB_MB` (default `256 MB`) by evicting oldest blobs when exceeded.
   - `GET /v1/blobs/{id}`: stream raw ciphertext bytes (`application/octet-stream`).
   - 15-minute background reaper goroutine deleting expired `offline_events` and expired `blobs` (DB rows + `.bin` files).
5. **1.5 — Packaging & Tests (`server/Dockerfile`, `server/docker-compose.yml`)**
   - Multi-stage Alpine/distroless `Dockerfile` (`CGO_ENABLED=0`).
   - `docker-compose.yml` with `all-notify-server` service and optional `caddy` (`--profile tls`) service.
   - Unit + integration tests:
     - `protocol/test_vectors.json` verification test.
     - Multi-client WS test (online fan-out, offline buffering + `replay_complete`, `ack` cleanup, duplicate-connection replacement, revoked-token rejection).
     - Blob `HEAD`/`PUT`/`GET`, oversize rejection (`413`), and TTL reaper test.

### Verification
```bash
cd server && go test -race -v ./...
docker build -t all-notify-server ./server
```

---

## Phase 2: Native Kotlin Android Client (`android/`)

**Goal**: Build a reliable, battery-friendly native Kotlin Android app that captures notifications (with icons & images), mirrors them via the VPS, displays mirrored notifications from other phones, and syncs dismissals both ways.

### Tasks

1. **2.1 — Project Scaffold & E2EE Core (`android/app/src/main/java/.../crypto/`)**
   - Gradle Kotlin DSL project (`minSdk = 26`, `targetSdk = 35`), Jetpack Compose + Material 3, Room, OkHttp 4, WorkManager, ZXing.
   - Implement `HkdfSha256`, `XChaCha20Poly1305`, `PairingUriParser`.
   - Store `K_master`, `device_token`, `server_url`, `device_id`, `device_name` in `EncryptedSharedPreferences` (Android Keystore).
   - Add JUnit test loading `../../protocol/test_vectors.json` to assert byte-exact compatibility.
2. **2.2 — Room Database & Local Caching (`.../data/`)**
   - Entities & DAOs: `notifications`, `active_key_map`, `app_filters`, `outbox`, `kv_state`.
   - `BlobCacheManager`: disk cache for decrypted `64×64` WebP icons (`icons/<sha256>.webp`, LRU 200) and decrypted image attachments (`attachments/<blob_id>.webp`).
   - `RetentionWorker` (daily `WorkManager` periodic job): prune notifications older than 30 days or beyond 5,000 rows and delete orphaned attachment files.
3. **2.3 — Persistent Foreground Service & WS Client (`.../service/RelayForegroundService.kt`)**
   - Low-priority persistent notification channel (`Connected` / `Reconnecting` / `Paused`).
   - OkHttp WebSocket client with exponential backoff (`1s` → `30s` + jitter) and `ConnectivityManager.NetworkCallback` instant reconnect.
   - Flush Room `outbox` on connect; track `replay_complete` boundary so offline backlog is batched before showing popups.
4. **2.4 — Notification Capture & Remote Cancel (`.../service/AllNotifyListenerService.kt`)**
   - `onNotificationPosted`:
     - Loop guard (`packageName == BuildConfig.APPLICATION_ID`).
     - Default noise filters (ongoing, foreground service, group summary shell, `CATEGORY_TRANSPORT`/media, `IMPORTANCE_MIN`) + `app_filters` lookup.
     - Extract title, big text / text, sub-text, category, group key.
     - Icon pipeline: extract app icon → `64×64` WebP → SHA-256 → check local uploaded cache / `HEAD` → encrypt & `PUT /v1/blobs/icon_<hash16>` on miss.
     - Image pipeline: extract `EXTRA_PICTURE` / `MessagingStyle` image → downscale `≤800px` WebP (`≤512 KB`) → encrypt & `PUT /v1/blobs/img_<ULID>`.
     - Persist `(notification_uid <-> sbn.key)` in `active_key_map`, encrypt `notification.posted`, enqueue to `RelayForegroundService`.
   - `onNotificationRemoved`:
     - Check `remotelyCancelledKeys` (10s TTL) to avoid dismissal echo; otherwise emit `notification.dismissed`.
   - Remote dismiss handler: look up `sbn.key`, add to `remotelyCancelledKeys`, call `cancelNotification(sbn.key)`.
5. **2.5 — Receiver Pipeline & Mirrored Notifications (`.../receiver/`)**
   - 5-second deduplication by `sha256(package + "\0" + title + "\0" + body)` merging `sender_device_name` and `notification_uid`s.
   - Respect Pause/Mute toggle and Android DND (`currentInterruptionFilter`).
   - Post mirrored notification on dedicated `mirrored_notifications` channel with cached app icon, optional `BigPictureStyle` attachment, and a `DeleteIntent` (`DismissBroadcastReceiver`) that emits `notification.dismissed` for all merged `notification_uid`s.
6. **2.6 — Minimal Compose UI (`.../ui/`)**
   - **Onboarding / Pairing**: QR scanner (ZXing) + manual `allnotify://pair?...` paste + guided permission checklist (Notification Access, Post Notifications, Battery Optimization exemption).
   - **Home (History & Status)**: Live connection badge, Pause/Resume toggle, search bar, chronological notification list with app icons, source device pills, image thumbnails, and swipe-to-dismiss.
   - **App Filters**: Searchable installed-app list with Enable and "Allow ongoing" toggles.
   - **Settings**: Device info, copy pairing/group key helper, clear history, permission status diagnostics.

### Verification
```bash
cd android && ./gradlew testDebugUnitTest assembleDebug
```
- Install debug APK on two Android devices (or phone + emulator), pair with local/VPS server, verify bidirectional mirroring (text, icon, photo) and two-way dismissal.

---

## Phase 3: Tauri Desktop Client (`desktop/` — Windows & macOS)

**Goal**: Build a lean Tauri v2 tray/menu-bar app for macOS and Windows with native OS notifications, dismissal sync, offline anti-popup-storm replay, and searchable local history.

### Tasks

1. **3.1 — Tauri v2 Scaffold & Rust Crypto (`desktop/src-tauri/src/crypto.rs`)**
   - Initialize Tauri v2 project with minimal Svelte 5 (or vanilla TypeScript) frontend.
   - Implement `HKDF-SHA256`, `XChaCha20-Poly1305`, and `allnotify://pair?...` URI parser.
   - Add `cargo test` unit test validating against `../../protocol/test_vectors.json`.
   - Store `K_master` and `device_token` in OS Keychain / Windows Credential Manager (`keyring` crate).
2. **3.2 — Local SQLite, Blob Cache & Retention (`desktop/src-tauri/src/storage.rs`)**
   - SQLite schema (`notifications`, `kv_state`) in WAL mode via `rusqlite`.
   - 5-second deduplication engine matching Android's exact fingerprint formula.
   - Disk cache for decrypted icons (`icons/<sha256>.webp`, LRU 200) and image attachments (`attachments/<blob_id>.webp`).
   - Startup + 24h background retention sweeper (30 days / 5,000 rows + orphan attachment cleanup).
3. **3.3 — Rust WebSocket Client & Replay Drain (`desktop/src-tauri/src/sync.rs`)**
   - `tokio-tungstenite` (`rustls`) client with exponential backoff and Ping/Pong keepalive.
   - Buffer incoming events until `replay_complete`: apply `notification.posted` and `notification.dismissed` to SQLite first, then pop up only still-active items (collapsing >5 active items into 1 summary notification).
   - Emit `ack` after durable SQLite commit.
   - Download & decrypt missing icon/attachment blobs via `reqwest` (`rustls`).
4. **3.4 — Native OS Notification & Dismissal Hooks (`desktop/src-tauri/src/notifier/`)**
   - Define `PlatformNotifier` trait: `show(notification)`, `clear(id)`, and action callback channel sending `notification.dismissed`.
   - **macOS (`macos.rs`)**: `UNUserNotificationCenter` category `ALL_NOTIFY_MSG` with explicit **`Dismiss`** action button, `UNNotificationAttachment` for icon/image, `removeDeliveredNotificationsWithIdentifiers` on remote dismiss.
   - **Windows (`windows.rs`)**: WinRT `ToastNotificationManager` XML with app logo override, hero image, explicit **`Dismiss`** button, native `ToastNotification::Dismissed` (`UserCanceled`) hook, and `History.Remove(tag)` on remote dismiss.
5. **3.5 — System Tray & Popover UI (`desktop/src/`)**
   - System tray / menu-bar icon with state variants (connected, unread dot, muted, disconnected) and no Dock icon on macOS.
   - Compact `380×540px` popover window:
     - Top bar: status indicator, Pause/Mute toggle, Clear all, Settings button.
     - Search bar + Active/Dismissed feed with app icon, source device badge, timestamp, image lightbox preview, and one-click **Dismiss** button.
     - First-run Pairing view (paste URI or drop QR image) and Settings view (autostart, privacy mode to hide body in OS banner, retention settings, unpair).

### Verification
```bash
cd desktop/src-tauri && cargo test
cd desktop && npm run tauri build
```
- Verify on macOS (menu bar, native notification + **Dismiss** action button, popover dismiss, Focus/DND respect).
- Verify on Windows (tray icon, native Toast + **Dismiss** button + swipe-dismiss hook, Focus Assist respect).

---

## Phase 4: End-to-End Integration, Hardening & Packaging

**Goal**: Prove every cross-device scenario works under real network conditions and automate builds for easy personal updates.

### Tasks

1. **4.1 — End-to-End Verification Matrix** (automated in `desktop/src-tauri/tests/e2e_matrix.rs` and `android/app/src/test/java/com/allnotify/app/net/GoServerInteropTest.kt`)
   - [x] **Basic Mirror**: Android A posts notification → appears on Android B, macOS, and Windows within <1s (plus zero-knowledge VPS SQLite inspection).
   - [x] **Icon Cache**: First notification from app uploads `64×64` WebP icon; second notification hits cache (zero `PUT`/`GET` blob calls).
   - [x] **Image Attachment**: WhatsApp/Telegram photo notification downscales `≤800px / ≤512 KB`, uploads encrypted blob, renders on Android B + macOS + Windows (plus `>550 KB` 413 rejection).
   - [x] **Dismissal Sync** (automated protocol/sync/clear verification; live OS native banner/Toast button UI clicks require physical macOS/Windows session):
     - Dismiss on macOS → cancels on Android A & clears Android B / Windows.
     - Dismiss on Windows → cancels on Android A & clears Android B / macOS.
     - Dismiss on Android A → clears Android B, macOS, Windows (and no echo loop).
   - [x] **5-Second Deduplication**: Same notification arrives on Android A and Android B within 5s → desktop/receiver shows 1 merged notification tagged `Phone A, Phone B`; dismissing it clears **both** phones.
   - [x] **Offline Replay**: Put laptop/phone offline, send 10 notifications on Phone A, dismiss 7 on Phone A, reconnect → 7 go silently into history, only 3 active pop up (plus >5 active collapses into 1 summary and ACK prunes server queue).
   - [x] **Revocation**: Run `all-notify-server token revoke <dev_id>` → device immediately disconnects and cannot reconnect (WS & Blob API return 401).
2. **4.2 — CI/CD & Release Packaging (`.github/workflows/`)**
   - [x] `server.yml`: Build static Linux `amd64`/`arm64` binaries & Docker image (with container `/healthz` smoke test).
   - [x] `android.yml`: Run unit/Go-interop tests, `lintDebug`, and build signed sideloadable release APK (`apksigner verify`).
   - [x] `desktop.yml`: Matrix build on `macos-latest` (`.dmg`) and `windows-latest` (`.msi`/`.exe`) with clippy, unit tests, and live Go-relay E2E matrix.
3. **4.3 — VPS Production Rollout** (Docker Compose healthcheck, `server/.env.example`, and rollout runbook ready in `docs/SERVER.md`)
   - [ ] Deploy `server/` via `docker-compose.yml` on your VPS with TLS (`wss://`).
   - [ ] Generate `K_master`, mint tokens/QR codes for each phone and laptop, pair all devices, and monitor server RAM/disk and Android battery usage over 48 hours.
