# Desktop Client Specification (`desktop/` — Windows & macOS)

The desktop client is a lightweight **Tauri v2** system tray / menu-bar application targeting **Windows 10/11** and **macOS 13+**. It is **receive-only** (plus dismissal sync and local searchable history).

---

## 1. Tech Stack

- **Core / Backend**: **Rust** (Tauri v2)
  - WebSocket: `tokio-tungstenite` (with `rustls` TLS)
  - HTTPS Blob Client: `reqwest` (with `rustls`)
  - Crypto: `chacha20poly1305` (`XChaCha20Poly1305`) + `hkdf` + `sha2` (validated against `protocol/test_vectors.json`)
  - Local DB: `rusqlite` (bundled SQLite, WAL mode)
  - Secrets: OS Keychain / Credential Manager (`keyring` crate) for `K_master` and `device_token`
  - Autostart: `tauri-plugin-autostart`
- **Frontend (Tray Popover / Window)**: Minimal **Svelte 5** (or vanilla TypeScript + lightweight CSS) — no heavy UI library, tiny memory footprint.

---

## 2. System Tray & Window Lifecycle

- Launches directly into the **macOS menu bar** / **Windows system tray** (no Dock icon on macOS when popover is closed).
- **Tray Icon States**:
  - Connected (normal)
  - Connected + Unread count badge / dot
  - Muted / Paused
  - Disconnected / Reconnecting
- **Tray Click**: Toggles a compact floating popover window (e.g., `380×540px`) anchored near the tray icon, containing:
  - Header: Connection status dot, quick **Pause/Mute** toggle, **Clear all** button, Settings gear.
  - Search input (filters local SQLite history by title, body, app name, or device name).
  - Notification list: Grouped by Active vs. Dismissed, showing `64×64` app icon, source device pill (e.g., `Pixel 9`), timestamp, title, body, inline image preview (click to expand), and a one-click **Dismiss** button.

---

## 3. Native OS Notifications & Dismissal Sync

Because macOS and Windows handle native notification dismissal differently, the Rust backend abstracts a `PlatformNotifier` trait:

### macOS (`UNUserNotificationCenter` via Objective-C/Swift bridge or `objc2`)
- Registers a `UNNotificationCategory` (`ALL_NOTIFY_MSG`) with an explicit **`Dismiss`** action (`UNNotificationActionOptions::none`, runs in background without bringing the app to foreground).
- Attaches the decrypted app icon / image attachment via `UNNotificationAttachment` (temp file in app cache).
- Respects macOS Focus / Do Not Disturb automatically via `UNUserNotificationCenter`.
- `tauri.conf.json` configures `bundle.macOS.signingIdentity: "-"` (ad-hoc bundle signing, overridable via `APPLE_SIGNING_IDENTITY` for Developer ID certs) so `Info.plist` and `CFBundleIdentifier` (`com.allnotify.desktop`) are sealed into `_CodeSignature` — required by macOS `usernoted` to accept `UNUserNotificationCenter` authorization and delivery.
- Tracks live `UNAuthorizationStatus` (`authorized`, `denied`, `not_determined`, `unavailable`), refreshes on popover focus, surfaces an actionable banner/Settings card with one-click **Open Settings** (`x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=com.allnotify.desktop`) / **Allow** (falling back to System Settings if an earlier prompt timed out) and **Send test** notification (awaiting live `UNNotificationSettings` + delivery `NSError` and warning if banner style is set to `None`).
- When the user clicks **Dismiss** (either on the native banner action or in the tray popover):
  - Removes the delivered notification (`removeDeliveredNotificationsWithIdentifiers`).
  - Emits `notification.dismissed` over WebSocket for all `notification_uids` on that entry.

### Windows (WinRT `ToastNotificationManager` via `windows` crate)
- Builds a native Windows Toast XML with:
  - App logo override (cached decrypted app icon).
  - Hero/inline image (decrypted image attachment, if present).
  - Explicit **`Dismiss`** action button (`activationType="background"`).
- Hooks **both**:
  1. Explicit **Dismiss** button click → emits `notification.dismissed`.
  2. Native `ToastNotification::Dismissed` event (when `ToastDismissalReason::UserCanceled`) → emits `notification.dismissed` automatically when the user swipes/clicks X!
- Respects Windows Focus Assist / DND automatically.
- On incoming remote `notification.dismissed`: calls `ToastNotificationManager.History.Remove(tag)` to silently clear the notification from Windows Action Center.

---

## 4. Offline Replay, Deduplication & Caching

- **Replay boundary**: On WebSocket connect, all events before `replay_complete` are decrypted, deduplicated, and inserted into SQLite without popping up OS notifications. Once `replay_complete` arrives:
  - Already-dismissed items remain silently in history.
  - Still-active items trigger OS popups (if >5 are active at once, fire 1 summary notification `"N unread notifications from your phones"` + populate the tray list).
- **5-second deduplication**: Identical to Android — `sha256(package + "\0" + title + "\0" + body)` within 5s merges `sender_device_name` and `notification_uid`s into one row.
- **Blob cache**:
  - Icons stored in `<app_cache_dir>/icons/<sha256>.webp` (LRU capped at 200 files).
  - Image attachments stored in `<app_cache_dir>/attachments/<blob_id>.<ext>`, deleted when their parent notification is pruned.
- **Local retention**: On startup and every 24h, prune SQLite rows older than **30 days** or beyond **5,000 rows**, plus orphaned attachment files.

---

## 5. Pairing & Settings UI

- **First-run setup**: Paste `allnotify://pair?...` URI (or drop/upload a QR code image). Accepts v1 (token) and v2 (one-time code → `POST /v1/pair/claim`). Stores `K_master` and `device_token` in OS Keychain, connects immediately.
- **Add device** (Phase 5, trusted devices only via `GET /v1/me`): create a one-time pairing code, render the v2 QR locally with the `qrcode` crate, countdown + claim status, window content protection while visible. See [PAIRING.md §8](./PAIRING.md#8-client-changes).
- **Settings panel**:
  - Server URL & Device Name (read-only from pairing, with "Unpair / Reset" button).
  - Launch at login toggle.
  - Show notification body preview vs. privacy mode (hide body in OS popup, show only in tray window).
  - Local history retention limit (default 30 days / 5,000 items) + "Clear history now".
