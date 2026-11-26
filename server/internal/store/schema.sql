CREATE TABLE IF NOT EXISTS devices (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    platform    TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    last_seq    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER,
    revoked_at  INTEGER
);

CREATE TABLE IF NOT EXISTS offline_events (
    seq               INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id      TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_id          TEXT NOT NULL,
    sender_device_id  TEXT NOT NULL,
    ciphertext        TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_offline_recipient_seq ON offline_events(recipient_id, seq);
CREATE INDEX IF NOT EXISTS idx_offline_expires ON offline_events(expires_at);

CREATE TABLE IF NOT EXISTS blobs (
    blob_id     TEXT PRIMARY KEY,
    size_bytes  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blobs_expires ON blobs(expires_at);
