# Go VPS Relay Server Specification (`server/`)

The relay server is a lightweight, single-binary **Go** service designed to run on a small VPS (512 MB RAM is plenty). It handles device authentication, real-time WebSocket fan-out, a 24-hour SQLite offline queue, and a 24-hour encrypted blob store. It **never** holds `K_master` and never decrypts payloads.

---

## 1. Tech Stack & Dependencies

- **Language**: Go 1.23+
- **WebSockets**: `github.com/coder/websocket` (or `gorilla/websocket`)
- **SQLite**: Pure-Go `modernc.org/sqlite` (zero CGO, trivially cross-compiles static Linux binaries for `amd64`/`arm64`)
- **HTTP Router**: Go stdlib `net/http` (`http.ServeMux` with method/path routing)
- **QR Code (CLI)**: `github.com/mdp/qrterminal/v3` (renders pairing QR directly in terminal)

---

## 2. Directory Structure

```text
server/
├── cmd/all-notify-server/main.go   # CLI entrypoint (serve, token, keygen)
├── internal/
│   ├── auth/                       # Bearer token hashing (SHA-256) & middleware
│   ├── store/                      # SQLite migrations, offline queue, blob metadata
│   ├── blobs/                      # Filesystem blob store + 24h TTL reaper
│   ├── hub/                        # Active WS connections, fan-out, replay, acks
│   └── api/                        # HTTP handlers (/v1/ws, /v1/blobs, /healthz)
├── Dockerfile
└── docker-compose.yml
```

---

## 3. SQLite Schema (`data/all-notify.db`, WAL Mode)

```sql
CREATE TABLE devices (
    id          TEXT PRIMARY KEY,          -- e.g. "dev_01J..."
    name        TEXT NOT NULL,             -- e.g. "Pixel 9"
    platform    TEXT NOT NULL,             -- "android" | "macos" | "windows"
    token_hash  TEXT NOT NULL UNIQUE,      -- hex(sha256(raw_token))
    last_seq    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,          -- unix ms
    last_seen   INTEGER,                   -- unix ms
    revoked_at  INTEGER                    -- NULL if active
);

CREATE TABLE offline_events (
    seq               INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id      TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_id          TEXT NOT NULL,
    sender_device_id  TEXT NOT NULL,
    ciphertext        TEXT NOT NULL,       -- base64url AEAD blob
    created_at        INTEGER NOT NULL,    -- unix ms
    expires_at        INTEGER NOT NULL     -- created_at + 24h
);

CREATE INDEX idx_offline_recipient_seq ON offline_events(recipient_id, seq);
CREATE INDEX idx_offline_expires ON offline_events(expires_at);

CREATE TABLE blobs (
    blob_id     TEXT PRIMARY KEY,          -- "icon_..." or "img_..."
    size_bytes  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL           -- created_at + 24h
);

CREATE INDEX idx_blobs_expires ON blobs(expires_at);
```

- **Blob files** are stored on disk at `<DATA_DIR>/blobs/<blob_id>.bin` (written atomically via temp file + rename).
- **TTL Reaper**: A background goroutine runs every **15 minutes** to delete rows from `offline_events` and `blobs` where `expires_at < now`, and removes the corresponding `.bin` files from disk.

---

## 4. Hub & Delivery Semantics

1. **Auth**: On `GET /v1/ws`, hash the `Bearer` token with SHA-256 and look up an active (`revoked_at IS NULL`) device row.
2. **Single active socket per device**: If `device_id` already has an active WS connection, close the old connection cleanly (`1000` / replaced) and register the new one.
3. **Replay on connect**:
   - Query `offline_events` for `recipient_id = device_id AND seq > after_seq AND expires_at > now ORDER BY seq ASC`.
   - Stream each as an `op: "event"` frame.
   - Send `op: "replay_complete"` with `latest_seq`.
4. **Live fan-out (`op: "relay"`)**:
   - Validate `len(ciphertext) <= 65536` and `event_id` non-empty.
   - For every active device where `id != sender_device_id`:
     - Insert into `offline_events` (getting its `seq`) so even an online device that drops mid-flight won't lose the event before `ack`.
     - If the recipient is currently connected, write the `op: "event"` frame to its send channel (non-blocking; if slow/full, close socket so it reconnects and replays).
5. **Ack (`op: "ack"`)**:
   - Delete from `offline_events` where `recipient_id = device_id AND seq <= ack.seq`.
   - Update `devices.last_seq = MAX(last_seq, ack.seq)` and `last_seen = now`.

---

## 5. CLI Commands

```bash
# Start the HTTP/WS server
all-notify-server serve --addr :8080 --data-dir /var/lib/all-notify

# Generate a random 32-byte K_master (prints base64url; NOT saved on server)
all-notify-server keygen

# Mint a new device token (and optionally print a terminal QR code if --key & --url are passed)
all-notify-server token create \
  --name "Pixel 9" \
  --platform android \
  --url https://notify.example.com \
  --key "<base64url_K_master>"

# List registered devices & last-seen status
all-notify-server token list

# Revoke a lost/retired device immediately (closes active WS if online)
all-notify-server token revoke dev_01J...
```

---

## 6. Configuration & Limits

| Env Variable | Default | Description |
| :--- | :--- | :--- |
| `ALLNOTIFY_ADDR` | `:8080` | Listen address |
| `ALLNOTIFY_DATA_DIR` | `./data` | Directory for SQLite DB and encrypted blobs |
| `ALLNOTIFY_TTL_HOURS` | `24` | Offline queue and blob expiration TTL |
| `ALLNOTIFY_MAX_EVENT_BYTES` | `65536` | Max WS frame size (64 KB) |
| `ALLNOTIFY_MAX_BLOB_BYTES` | `563200` | Max encrypted blob size (~550 KB) |
| `ALLNOTIFY_MAX_TOTAL_BLOB_MB` | `256` | Hard cap on total blob disk usage (evicts oldest on overflow) |

Health check endpoint: `GET /healthz` returns `200 OK` (`{"status":"ok"}`) without auth.

---

## 7. Deployment

### Option A: Behind Existing Nginx / Caddy Reverse Proxy
Run the binary via `systemd` or Docker bound to `127.0.0.1:8080`, and proxy `/v1/ws` (with WebSocket upgrade headers + long read timeout ≥ 120s) and `/v1/blobs` over HTTPS.

### Option B: Standalone Docker Compose with Caddy Auto-TLS
`server/docker-compose.yml` includes:
- `all-notify-server` container mounting `./data:/data` with a built-in `/healthz` Docker healthcheck
- Optional `caddy` profile (`--profile tls`) that terminates HTTPS/WSS automatically via Let's Encrypt for your domain.

### VPS Production Rollout Checklist
1. Copy `server/.env.example` to `server/.env` and set `ALLNOTIFY_DOMAIN=notify.yourdomain.com` (ensure DNS A/AAAA points to the VPS and TCP ports 80/443 are open).
2. Prepare the host data directory for the non-root container user (`allnotify`, UID `10001`), start the stack, and confirm healthy status:
   ```bash
   cd server
   mkdir -p data && sudo chown 10001:10001 data
   docker compose --profile tls up -d --build
   docker compose ps
   curl -fsS https://notify.yourdomain.com/healthz
   ```
3. Generate `K_master` once (keep it in your password manager — **never** save it on the VPS):
   ```bash
   K_MASTER="$(docker compose exec -T all-notify-server all-notify-server keygen)"
   ```
4. Mint a per-device token + pairing QR for each Android phone, Mac, and Windows PC:
   ```bash
   docker compose exec all-notify-server all-notify-server token create \
     --name "Pixel 9" --platform android \
     --url "https://notify.yourdomain.com" --key "$K_MASTER"
   ```
   Clear your shell history / unset `K_MASTER` once all devices are paired.
5. **Soak & health checks**: Verify `docker stats --no-stream all-notify-server` (target <50 MB RAM), `du -sh server/data` (bounded by 24h TTL + `256 MB` blob cap), `all-notify-server token list` (`LAST_SEEN` updating), and Android battery usage over 48 hours.
6. **Rollback / Update**: Pull the new commit or binary, run `docker compose --profile tls up -d --build` (SQLite WAL data in `./data` persists across upgrades); to roll back, check out the previous tag and re-run `up -d --build`.
