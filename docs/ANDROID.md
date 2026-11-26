# Android Client Specification (`android/`)

The Android client is a **native Kotlin** app that acts as both a **sender** (capturing notifications from all apps) and a **receiver** (displaying mirrored notifications from other Android phones and syncing dismissals).

---

## 1. Target & Tech Stack

- **Language**: Kotlin 2.x, Coroutines + Flow
- **SDK**: `minSdk = 26` (Android 8.0+), `targetSdk = 35`
- **UI**: Jetpack Compose (minimal Material 3 UI: Setup/QR, History, App Filters, Settings)
- **Networking**: OkHttp 4 (WebSocket + HTTPS blob upload/download)
- **Local Database**: Room (SQLite)
- **Crypto**: `XChaCha20-Poly1305` + `HKDF-SHA256` validated against `protocol/test_vectors.json`
- **Secure Storage**: `EncryptedSharedPreferences` / Android Keystore for `K_master` and `device_token`
- **QR Scanning**: CameraX + ML Kit Barcode Scanning (or ZXing embedded, zero Google Play Services dependency — **prefer ZXing** so it works on GrapheneOS / de-Googled Android too)

---

## 2. Required Permissions & Onboarding Flow

1. **Notification Access (`BIND_NOTIFICATION_LISTENER_SERVICE`)**: Prompts user to enable All-Notify in *Settings → Notification access*.
2. **Post Notifications (`POST_NOTIFICATIONS`, Android 13+)**: Required to display mirrored notifications and the persistent Foreground Service status notification.
3. **Foreground Service (`FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`)**: Keeps the WebSocket alive in the background.
4. **Ignore Battery Optimizations (`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`)**: Guided prompt during onboarding so Doze mode does not kill the persistent socket.
5. **Camera (`CAMERA`, optional)**: Only for scanning the pairing QR code (manual URI paste always available).

---

## 3. Core Components

### A. `AllNotifyListenerService` (`NotificationListenerService`)
Captures local notifications and executes remote dismissals.

- **`onNotificationPosted(sbn: StatusBarNotification)`**:
  1. **Loop guard**: Ignore immediately if `sbn.packageName == BuildConfig.APPLICATION_ID`.
  2. **Default noise filter**:
     - Skip ongoing notifications (`sbn.isOngoing` or `FLAG_FOREGROUND_SERVICE`) unless user explicitly overrides per app.
     - Skip group summary shells (`FLAG_GROUP_SUMMARY`) when individual child notifications are posted.
     - Skip media transport controls (`CATEGORY_TRANSPORT` / `MediaStyle`).
     - Skip low/min importance notifications (`IMPORTANCE_MIN` / silent progress bars) by default.
  3. **Per-app filter**: Check Room `app_filters` table (default mode: denylist — all apps enabled except user-muted ones; toggleable to allowlist).
  4. **Extract content**:
     - `title` (`EXTRA_TITLE`), `body` (`EXTRA_BIG_TEXT` fallback to `EXTRA_TEXT`), `sub_text` (`EXTRA_SUB_TEXT`), `category`, `group_key`.
     - **App icon**: Load `PackageManager.getApplicationIcon(packageName)`, render to `64×64` bitmap, encode as WebP (quality 80), compute SHA-256. Check local `uploaded_icon_hashes` cache; if missing, `HEAD /v1/blobs/icon_<hash16>` and `PUT` encrypted bytes if `404`.
     - **Image attachment**: Extract `EXTRA_PICTURE` (or latest `MessagingStyle.Message.dataUri` image). Scale down to max `800px` on longest edge, encode WebP (fallback JPEG) targeting `≤512 KB`, encrypt with `K_blob`, upload via `PUT /v1/blobs/img_<ULID>`.
  5. **Record mapping**: Save `(notification_uid <-> sbn.key)` in an in-memory + Room lookup table so future remote dismissals can cancel it.
  6. **Publish**: Encrypt `notification.posted` JSON with `K_event` and enqueue to the WebSocket service (buffered locally in Room `outbox` if temporarily offline).

- **`onNotificationRemoved(sbn: StatusBarNotification, rankingMap, reason)`**:
  1. If `sbn.key` is in `remotelyCancelledKeys` (TTL 10s), remove from set and **do nothing** (prevents dismissal echo).
  2. Otherwise, look up `notification_uid` for `sbn.key` and emit a `notification.dismissed` event so laptops and other phones clear it.

- **Handling incoming remote dismissal**:
  1. Look up `sbn.key` for each `notification_uid`.
  2. Add `sbn.key` to `remotelyCancelledKeys`.
  3. Call `cancelNotification(sbn.key)`.

### B. `RelayForegroundService` (Persistent WebSocket)
- Runs as a low-priority foreground service with a silent notification channel (`"All-Notify Connected"` / `"Reconnecting..."` / `"Paused"`).
- Maintains a single OkHttp WebSocket to `wss://<host>/v1/ws?after_seq=<last_seq>`.
- Monitors `ConnectivityManager.NetworkCallback` to reconnect immediately when switching between Wi-Fi and cellular.
- Flushes local `outbox` events upon reconnect.
- Handles `replay_complete` boundary: buffers replayed events before popping up only still-active notifications.

### C. Receiver & Mirrored Notification Display
- **Mute / Pause toggle** + **OS DND respect** (`NotificationManager.currentInterruptionFilter`).
- **5-second deduplication**: Checks `sha256(package + "\0" + title + "\0" + body)` against recent active notifications; merges `sender_device_name` and `notification_uid`s without double-popping.
- **Display**: Posts a local notification on a dedicated channel (`mirrored_notifications`) with:
  - Small icon: All-Notify badge; Large icon: cached decrypted app icon.
  - Title: `<title>` · Subtext: `<AppName> • <SenderDeviceName>`.
  - BigPictureStyle if an image attachment was downloaded and decrypted.
  - `DeleteIntent` (`BroadcastReceiver`) so swiping away the mirrored notification on Phone B emits `notification.dismissed` back to Phone A and desktops.

---

## 4. Local Room Database Schema

- `notifications`: `id`, `notification_uids_json`, `sender_devices_json`, `package_name`, `app_name`, `icon_sha256`, `title`, `body`, `attachment_path`, `dedup_hash`, `posted_at`, `dismissed_at`, `is_mirrored`
- `active_key_map`: `notification_uid` (PK), `sbn_key`, `created_at`
- `app_filters`: `package_name` (PK), `app_name`, `enabled`, `allow_ongoing`
- `outbox`: `event_id` (PK), `ciphertext`, `created_at` (retried on reconnect; dropped after 24h)
- `kv_state`: `last_acked_seq`, `paused_until`, `filter_mode`

**Retention worker** (`WorkManager`, daily): Prunes `notifications` older than **30 days** or beyond the newest **5,000 rows**, deleting orphaned decrypted attachment files from `cacheDir/attachments/`.

---

## 5. UI Screens (Minimal Jetpack Compose)

1. **Status & History (Home)**: Connection status pill, quick **Pause/Resume** switch, search bar, chronological feed of mirrored & sent notifications (with app icons, device badges, image thumbnails, and swipe-to-dismiss).
2. **App Filters**: Searchable list of installed apps with enable/disable toggle and "Allow ongoing" switch.
3. **Settings & Pairing**: Pair via QR / URI, view connected device name & server URL, copy group key/URI to pair another device, clear local history, battery/permission health checks.
