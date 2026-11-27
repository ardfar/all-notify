# Live Status & Remote Media Controls Specification (Phase 6 / `v1.1`)

Adds two real-time capabilities on top of the `v1.0` E2EE relay with **zero new Android permissions** (both use the existing `AllNotifyListenerService` binding) and **zero re-pairing** (100% additive on protocol `v1`):

- **(A) Live Status / Ongoing Tracking**: Mirrors real-time updating ongoing notifications (Grab, Gojek, Uber, deliveries, timers, downloads) as a **single pinned live card** updated silently in place with progress bars, archiving cleanly into local history once finished.
- **(B) Remote Media Controls**: Mirrors active Android `MediaSession` Now Playing metadata + album art and lets your Mac, Windows PC, or other Android phone control **Play/Pause, Previous, Next, Seek, and Volume +/−** via targeted, strictly ephemeral E2EE frames.

---

## 1. Invariants (Phase 6 additions)

1. **Zero-knowledge VPS preserved**: All `media.state`, `media.command`, album art blobs, and `live` notification fields remain E2EE (`XChaCha20-Poly1305` + AAD). The server only sees `ephemeral`, `target`, and `sender_device_id`.
2. **Media is 100% ephemeral**: `media.state` and `media.command` frames set `ephemeral: true`. The server NEVER writes them to `offline_events`, and receivers NEVER write them to the local `notifications` history table.
3. **No popup storms on live updates**: Ongoing/live notifications fire **at most 1 initial OS banner** (when first created), then apply all subsequent updates **silently in place** (`silentUpdate = true`, zero sound, zero repeat banners), coalesced on Android to **≥2s intervals** (skipping identical title/body/progress).
4. **Opt-in ongoing capture**: Ongoing notifications are captured ONLY for apps with `allow_ongoing = true` in Android `app_filters` (preventing VPN/system/antivirus ongoing spam).
5. **No desktop media-key hijacking**: Desktop media controls live strictly inside the All-Notify tray popover (never hooking macOS `MPNowPlayingInfoCenter` or Windows SMTC hardware keys).
6. **Backward compatibility**: Existing `v1.0.0` clients ignore unknown optional fields and unknown inner payload `type`s safely without crashing or dropping normal notifications.

---

## 2. Additive Wire Protocol (`v1`)

### 2.1 Outer WebSocket Frame Extensions

#### Client → Server: `relay` (extended)
```json
{
  "op": "relay",
  "event_id": "01JABCDEF1234567890ABCDEFG",
  "target": "broadcast",
  "ephemeral": true,
  "ciphertext": "<base64url(nonce || ct || tag)>"
}
```
- `target` (string, required):
  - `"broadcast"` — fan out to all other active devices (default, unchanged).
  - `"dev_<id>"` — route **only** to that specific active device (must not equal `sender_device_id`; if unknown/revoked/offline, drop silently for `ephemeral: true` or return `error` code `INVALID_TARGET` if malformed).
- `ephemeral` (bool, optional, defaults to `false`):
  - When `false`: existing durable behavior (insert into `offline_events`, assign monotonic `seq`, deliver to online recipients).
  - When `true`: **skip SQLite `offline_events`**, deliver immediately to online matching recipient(s) with `seq: 0` and `"ephemeral": true` on the `event` frame. Receivers MUST NOT send `ack` or advance `last_acked_seq` for `ephemeral: true` frames.

#### Server → Client: `event` (extended)
```json
{
  "op": "event",
  "seq": 0,
  "ephemeral": true,
  "event_id": "01JABCDEF1234567890ABCDEFG",
  "sender_device_id": "dev_01J...",
  "server_ts": 1764060000123,
  "ciphertext": "<base64url(nonce || ct || tag)>"
}
```
- AAD remains unchanged: `"v1|" + event_id + "|" + sender_device_id`.

#### Server → Client: `device_offline` (new control frame)
Emitted by the hub to all other currently connected clients when a device's active WebSocket closes (and was not immediately replaced by a newer socket for the same `device_id`):
```json
{
  "op": "device_offline",
  "device_id": "dev_01J...",
  "server_ts": 1764060099000
}
```
Receivers immediately clear any in-memory ephemeral `media.state` belonging to `device_id` (preventing stuck Now Playing cards if a phone loses battery or drops off the network).

---

### 2.2 Inner Payload Extension: `notification.posted` (`live` object)

Optional `live` object on `notification.posted` (present when an opt-in `allow_ongoing` notification is captured):
```json
{
  "type": "notification.posted",
  "notification_uid": "dev_01J...:1764060000123:a8f3c1",
  "sender_device_name": "VX100PAF",
  "posted_at": 1764060000123,
  "app": {
    "package": "com.grabtaxi.passenger",
    "name": "Grab",
    "icon_sha256": "...",
    "icon_blob_id": "icon_..."
  },
  "content": {
    "title": "Driver is 4 min away",
    "body": "B 1234 XYZ • Toyota Avanza — Arriving at Lobby",
    "sub_text": "GrabCar",
    "category": "progress",
    "group_key": "grab:ride:981"
  },
  "live": {
    "replace_key": "dev_01J...:sha256_16_of_sbn_key",
    "is_ongoing": true,
    "progress": 65,
    "progress_max": 100,
    "indeterminate": false
  },
  "attachments": []
}
```

Field rules:
- `live.replace_key`: Deterministic string `sender_device_id + ":" + hex(sha256(sbn.key))[0..16]` (max 96 chars). Hides raw Android UID/tag internals while uniquely identifying the live slot per sender device.
- `live.is_ongoing`: `true` while the notification is active/ongoing on Android.
- `live.progress` / `live.progress_max`: Optional integers (`>= 0`, `progress_max > 0` when determinate). Extracted from `Notification.EXTRA_PROGRESS`, `Notification.EXTRA_PROGRESS_MAX`, `Notification.EXTRA_PROGRESS_INDETERMINATE` (plus Android 16 `ProgressStyle` when available).
- **In-place update semantics on receivers**:
  - When `live.replace_key` matches an existing **active (`dismissed_at IS NULL`)** row in local DB:
    - Update `title`, `body`, `sub_text`, `posted_at`, `live_*` columns, and append `notification_uid` (if new) in place — **never insert a duplicate row**.
    - Update the pinned live card and any OS mirrored notification **silently** (`silentUpdate = true`).
  - When `notification.dismissed` arrives for that row's `notification_uid` (fired automatically when Grab finishes and removes the ongoing notification):
    - Mark `dismissed_at = dismissed_at`, set `is_ongoing = false` (unpinning it from the Live section), clear any OS mirrored notification, and **keep the final row in local history**.

---

### 2.3 New Inner Payload: `media.state` (ephemeral, `target: "broadcast"`)

Sent by Android whenever the active `MediaSession` metadata, playback state, or track changes (plus on seek/state transition; **NOT** sent every second for elapsed position — receivers interpolate elapsed time locally from `position_ms` + `updated_at` + `playback_rate` while `state == "playing"`!):

```json
{
  "type": "media.state",
  "session_id": "dev_01J...:com.spotify.music",
  "sender_device_name": "VX100PAF",
  "active": true,
  "app": {
    "package": "com.spotify.music",
    "name": "Spotify"
  },
  "track": {
    "title": "Blinding Lights",
    "artist": "The Weeknd",
    "album": "After Hours",
    "duration_ms": 200040,
    "art_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "art_blob_id": "art_9f86d081884c7d65"
  },
  "playback": {
    "state": "playing",
    "position_ms": 42500,
    "playback_rate": 1.0,
    "updated_at": 1764060000123,
    "can_play_pause": true,
    "can_next": true,
    "can_prev": true,
    "can_seek": true
  },
  "volume": {
    "current": 9,
    "max": 15,
    "adjustable": true
  }
}
```

Rules:
- `active: false` (minimal payload with `session_id`, `active: false`, `app.package`) is sent immediately when the Android `MediaSession` closes, stops, or is ignored by the user — receivers remove the Now Playing card immediately.
- `playback.state`: `"playing" | "paused" | "buffering" | "stopped"`.
- **Album art blob**: Downscaled to `≤256×256` WebP (`≤64 KB`), deterministic `blob_id = "art_" + first_16_hex_of_sha256`, uploaded via existing `HEAD`/`PUT /v1/blobs/{id}` (cached by `art_sha256`, reusing existing blob API & 24h TTL!).
- **Paused auto-expiry**: Receivers hide a session whose `playback.state == "paused"` once `now - playback.updated_at > 10 minutes` (or immediately on `active: false` or `device_offline`).
- **On new device connect**: No server-side media cache is required; Android emits a fresh `media.state` snapshot when its `MediaSession` changes or when a `media.command` with `action: "sync"` arrives (receivers may broadcast one ephemeral `{"type":"media.command","action":"sync"}` right after `replay_complete` so a waking laptop immediately picks up already-playing music!).

---

### 2.4 New Inner Payload: `media.command` (ephemeral, `target: "<phone_device_id>"` or `"broadcast"` for `"sync"`)

Sent by Desktop (macOS/Windows) or Phone B to control playback on Phone A:

```json
{
  "type": "media.command",
  "session_id": "dev_01J...:com.spotify.music",
  "action": "play_pause",
  "seek_ms": 0,
  "volume_delta": 0,
  "issued_at": 1764060010000
}
```

Supported `action` values:
| `action` | Parameters | Android `MediaController` Execution |
| :--- | :--- | :--- |
| `"play_pause"` | none | If playing → `transportControls.pause()`, else `transportControls.play()` |
| `"play"` / `"pause"` | none | Explicit `play()` / `pause()` |
| `"next"` | none | `transportControls.skipToNext()` |
| `"previous"` | none | `transportControls.skipToPrevious()` |
| `"seek"` | `seek_ms` (`>= 0`) | `transportControls.seekTo(seek_ms)` |
| `"volume_up"` / `"volume_down"` | none | `controller.adjustVolume(ADJUST_RAISE / ADJUST_LOWER, FLAG_SHOW_UI)` (fallback `AudioManager.adjustStreamVolume(STREAM_MUSIC, ...)`) |
| `"sync"` | `session_id` optional | Phone re-emits current active `media.state` (if any) so a freshly woken laptop sees already-playing music immediately |

---

## 3. Component Specifications

### 3.1 Protocol (`protocol/`)
- Add JSON schemas:
  - `protocol/schemas/media_state.schema.json`
  - `protocol/schemas/media_command.schema.json`
  - Update `protocol/schemas/ws_outer.schema.json` (`ephemeral`, `target` device ID pattern, `device_offline` op) and `protocol/schemas/notification_posted.schema.json` (optional `live` object).
- Extend `protocol/cmd/genvectors/main.go` and `protocol/test_vectors.json` with deterministic E2EE event vectors for `notification.posted` (with `live`), `media.state`, and `media.command`.

### 3.2 Go Server (`server/`)
- **WS `relay` handling (`internal/hub/hub.go`, `internal/api/ws.go`)**:
  - Allow `target == "broadcast"` OR `target` matching a valid active `device_id` (`^dev_[a-zA-Z0-9_-]{8,64}$`, `target != sender_device_id`).
  - When `ephemeral == true`: skip `store.EnqueueOfflineEvent`, fan out directly to online target(s) with `seq: 0, ephemeral: true`.
  - When a device disconnects (not replaced by a newer socket for the same `device_id`), broadcast `{"op":"device_offline","device_id":"...","server_ts":...}` to other online sockets.
- **Blob API**: `HEAD /v1/blobs/{id}` refreshes TTL for `art_*` blobs just like `icon_*` blobs.

### 3.3 Android Client (`android/`)
1. **Live Status Capture (`AllNotifyListenerService.kt`)**:
   - When `appFilter.allowOngoing == true` and `(isOngoing || isForegroundService)` passes `NotificationFilter`:
     - Extract `EXTRA_PROGRESS`, `EXTRA_PROGRESS_MAX`, `EXTRA_PROGRESS_INDETERMINATE` (and `replace_key = "${config.deviceId}:${sha256Hex(sbn.key).take(16)}"`).
     - **Coalesce / Throttle (`LiveUpdateThrottler`)**: Keep `(replace_key -> lastSentSnapshot(title, body, progress, progressMax, sentAtMs))` in memory. Skip if identical to last sent; if `< 2000ms` since last send, schedule a single trailing debounced emit so the final state is never lost.
     - Note on custom `RemoteViews` (Grab/Gojek): fall back cleanly to `subText` / `tickerText` / `appName` if `EXTRA_TITLE` is blank while `EXTRA_PROGRESS` or `EXTRA_TEXT` is present.
     - When `onNotificationRemoved` fires for a live key, flush/cancel any pending throttled emit and emit `notification.dismissed` so receivers unpin and archive it.
2. **Media Session Monitor (`MediaSessionMonitor.kt`)**:
   - Registers `MediaSessionManager.OnActiveSessionsChangedListener` using `ComponentName(context, AllNotifyListenerService::class.java)` whenever `AllNotifyListenerService` connects (and unregisters on disconnect/destroy).
   - Filters sessions:
     - Ignore sessions with empty track `METADATA_KEY_TITLE`.
     - Check per-app `media_enabled` flag on `app_filters` (Room migration adding `media_enabled INTEGER NOT NULL DEFAULT 1` + `replace_key`/`is_ongoing`/`progress`/`progress_max`/`indeterminate` columns on `notifications`).
   - Attaches `MediaController.Callback` for metadata, playback state, and audio/volume changes (throttled `>= 500ms` for rapid seek/volume bursts).
   - Uploads `≤256×256` WebP album art as `art_<hash16>` (cached by `art_sha256` in `BlobCacheManager`).
   - Handles incoming `media.command` frames via `MediaController.transportControls` / `adjustVolume` (and responds to `action == "sync"` with current active session(s)).
3. **Android Receiver & UI (Phone B)**:
   - **Room migration** (v1 → v2): add `replace_key`, `is_ongoing`, `progress`, `progress_max`, `indeterminate` to `notifications`, and `media_enabled` to `app_filters`.
   - **In-place Live Status update**: `NotificationPipeline` looks up active row by `replace_key`; on match updates silently in place (`silentUpdate = true`) and updates the ongoing shade notification with `.setProgress(max, progress, indeterminate)`.
   - **Now Playing on Phone B**:
     - Pinned **Live & Now Playing** section at top of Home screen (all active Live cards + active phone media cards with Play/Pause, Prev, Next, Seek, Vol +/−, and "Ignore app" action).
     - Optional (toggleable in Settings, ON by default) **silent ongoing media notification** (`channel = mirrored_media`) with Play/Pause, Prev, Next `BroadcastReceiver` action buttons (`MediaActionBroadcastReceiver`) sending `media.command` back to Phone A, auto-cancelled on `active: false`, 10-min paused timeout, or `device_offline`.

### 3.4 Desktop Client (`desktop/` — macOS & Windows)
1. **SQLite migration & In-Place Live Status (`storage.rs`, `sync.rs`)**:
   - Add idempotent column migrations on `notifications`: `replace_key TEXT`, `is_ongoing INTEGER NOT NULL DEFAULT 0`, `progress INTEGER`, `progress_max INTEGER`, `indeterminate INTEGER NOT NULL DEFAULT 0` (plus index on `replace_key`).
   - In `ingest_posted`: if `live.replace_key` matches an active row (`dismissed_at IS NULL`), update in place and return `IngestOutcome::UpdatedInPlace(rec)` (triggers silent UI/tray refresh, zero repeat OS popup).
   - On `notification.dismissed`: mark `dismissed_at`, clear `is_ongoing = 0` so it moves cleanly from pinned Live into regular history.
2. **Ephemeral Media State & Commands (`sync.rs`, `lib.rs`)**:
   - Handle `ServerFrame::Event { ephemeral: true, .. }` (do NOT send `ack` or update `last_acked_seq`) and `ServerFrame::DeviceOffline { device_id, .. }` (purge that device's media sessions).
   - Send one ephemeral `media.command` (`action: "sync"`) right after `ReplayComplete` so waking laptops immediately show active playback.
   - Maintain in-memory `HashMap<String, MediaSessionView>` with a 30s sweeper evicting sessions paused `> 10 min`.
   - Expose Tauri commands: `get_live_state()`, `send_media_command(target_device_id, session_id, action, seek_ms)`, `ignore_media_app(package_name)`, `set_menubar_ticker_enabled(bool)`.
3. **Tray Popover UI & macOS Menu-Bar Ticker (`tray.rs`, `desktop/src/`)**:
   - **Pinned Live Header** above the search bar in the popover:
     - Active **Live Status cards** (Grab/delivery title, body, determinate/indeterminate progress bar, source phone badge).
     - Active **Now Playing card(s)** (album art thumbnail, track title, artist, source phone badge, live client-interpolated progress/seek slider, Prev / Play-Pause / Next, Vol − / +, and "Ignore player" icon button).
   - **macOS Menu-Bar Live Ticker** (`tray.rs`, toggleable in Settings, ON by default on macOS):
     - Calls `tray.set_title(Some(text))` when active (and `tray.set_title(None)` when idle/disabled).
     - Priority: active **Live Status** first (`🚗 <short title/ETA>`), then playing **Media** (`♫ <track title>`), truncated cleanly to **≤24 chars** (`…`).

---

## 4. Verification Criteria (Phase 6 Exit Gate)

- **Protocol (`protocol/`)**: `go test -v ./...` passes; all 3 languages pass new `live`, `media.state`, and `media.command` vectors.
- **Server (`server/`)**: `go test -race -v ./...` proves:
  - `ephemeral: true` delivers to online devices with `seq: 0` and writes **0 rows** to `offline_events`.
  - Targeted `target: "dev_B"` delivers ONLY to `dev_B` (never to `dev_C` or sender `dev_A`).
  - `device_offline` fires on disconnect (and NOT on duplicate-socket replacement).
- **Android (`android/`)**: `./gradlew testDebugUnitTest lintDebug assembleDebug` proves:
  - `LiveUpdateThrottler` coalesces rapid updates (`>=2s`) and skips identical updates.
  - Room v1 → v2 migration preserves existing notifications & app filters.
  - `NotificationPipeline` replaces active `replace_key` row in place silently, and archives into history on dismiss.
  - `MediaSessionMonitor` filters empty titles & ignored apps, uploads `art_<hash16>` once, and executes `play_pause`/`next`/`previous`/`seek`/`volume` commands.
- **Desktop (`desktop/`)**: `cargo clippy --all-targets -- -D warnings && cargo test` proves:
  - In-place `replace_key` updates keep 1 SQLite row with zero second OS popup and unpin on dismiss.
  - Ephemeral `media.state` never touches SQLite or `last_acked_seq`, clears on `device_offline` and 10-min paused TTL.
  - macOS menu-bar ticker prioritizes Live Status over Media and enforces `<= 24` char truncation.
  - Live Go-relay E2E test covers Grab-style 5-update live progress + finish-archive AND Spotify `media.state` → Mac `media.command` round-trip.
- **Live Hardware Verification**: Extend `tests/live_e2e/` with `t08_live_and_media.py` verifying in-place ongoing progress updates on Phone A → MacBook & Phone B, and real Spotify/media Play/Pause/Next control from MacBook → Phone A.
