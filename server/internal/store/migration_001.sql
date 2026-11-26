CREATE TABLE IF NOT EXISTS pairing_codes (
    id                 TEXT PRIMARY KEY,
    code_hash          TEXT NOT NULL UNIQUE,
    name               TEXT NOT NULL,
    platform           TEXT NOT NULL,
    can_add_devices    INTEGER NOT NULL DEFAULT 0,
    created_by         TEXT NOT NULL,
    created_at         INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    claimed_at         INTEGER,
    claimed_device_id  TEXT,
    cancelled_at       INTEGER
);

CREATE INDEX IF NOT EXISTS idx_pairing_codes_created_by ON pairing_codes(created_by, created_at);

CREATE TABLE IF NOT EXISTS admin_credentials (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash  TEXT NOT NULL,
    must_change    INTEGER NOT NULL DEFAULT 1,
    updated_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash   TEXT PRIMARY KEY,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
