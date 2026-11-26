use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::{
    attachment_extension_for_mime, dedup_fingerprint, is_valid_blob_id, is_valid_sha256_hex,
    NotificationPosted, DEDUP_WINDOW_MS,
};

pub const DEFAULT_RETENTION_DAYS: i64 = 30;
pub const DEFAULT_RETENTION_MAX_ROWS: i64 = 5_000;
pub const DEFAULT_MAX_ICONS: usize = 200;
const OUTBOX_TTL_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid identifier: {0}")]
    InvalidId(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationRecord {
    pub id: i64,
    pub notification_uids: Vec<String>,
    pub sender_devices: Vec<String>,
    pub sender_device_ids: Vec<String>,
    pub package_name: String,
    pub app_name: String,
    pub icon_sha256: Option<String>,
    pub title: String,
    pub body: String,
    pub sub_text: Option<String>,
    pub category: Option<String>,
    pub group_key: Option<String>,
    pub attachment_path: Option<String>,
    pub attachment_mime: Option<String>,
    pub dedup_hash: String,
    pub posted_at: i64,
    pub dismissed_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    AlreadyExists(NotificationRecord),
    Merged(NotificationRecord),
    Inserted(NotificationRecord),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxRow {
    pub event_id: String,
    pub ciphertext: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionSettings {
    pub days: i64,
    pub max_rows: i64,
}

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS notifications (
                id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                notification_uids_json TEXT NOT NULL,
                sender_devices_json    TEXT NOT NULL,
                sender_device_ids_json TEXT NOT NULL,
                package_name           TEXT NOT NULL,
                app_name               TEXT NOT NULL,
                icon_sha256            TEXT,
                title                  TEXT NOT NULL,
                body                   TEXT NOT NULL,
                sub_text               TEXT,
                category               TEXT,
                group_key              TEXT,
                attachment_path        TEXT,
                attachment_mime        TEXT,
                dedup_hash             TEXT NOT NULL,
                posted_at              INTEGER NOT NULL,
                dismissed_at           INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_notifications_dedup
                ON notifications(dedup_hash, posted_at);
            CREATE INDEX IF NOT EXISTS idx_notifications_posted
                ON notifications(posted_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_notifications_dismissed
                ON notifications(dismissed_at);

            CREATE TABLE IF NOT EXISTS kv_state (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS outbox (
                event_id   TEXT PRIMARY KEY,
                ciphertext TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    pub fn ingest_posted(
        &self,
        sender_device_id: &str,
        payload: &NotificationPosted,
        attachment_path: Option<String>,
        attachment_mime: Option<String>,
    ) -> Result<IngestOutcome, StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");

        // 1. Idempotency check by notification_uid.
        if let Some(existing) = find_by_uid(&conn, &payload.notification_uid)? {
            return Ok(IngestOutcome::AlreadyExists(existing));
        }

        let dedup_hash = dedup_fingerprint(
            &payload.app.package,
            &payload.content.title,
            &payload.content.body,
        );

        // 2. 5-second cross-device deduplication window.
        let candidates = find_recent_active_by_hash(&conn, &dedup_hash, payload.posted_at)?;
        if let Some(mut dup) = candidates
            .into_iter()
            .find(|c| !c.sender_device_ids.iter().any(|id| id == sender_device_id))
        {
            push_unique(&mut dup.notification_uids, &payload.notification_uid);
            push_unique(&mut dup.sender_devices, &payload.sender_device_name);
            push_unique(&mut dup.sender_device_ids, sender_device_id);
            if dup.icon_sha256.is_none() {
                dup.icon_sha256 = payload.app.icon_sha256.clone();
            }
            if dup.attachment_path.is_none() && attachment_path.is_some() {
                dup.attachment_path = attachment_path;
                dup.attachment_mime = attachment_mime;
            }
            conn.execute(
                r#"
                UPDATE notifications
                SET notification_uids_json = ?1,
                    sender_devices_json = ?2,
                    sender_device_ids_json = ?3,
                    icon_sha256 = ?4,
                    attachment_path = ?5,
                    attachment_mime = ?6
                WHERE id = ?7
                "#,
                params![
                    encode_json_vec(&dup.notification_uids),
                    encode_json_vec(&dup.sender_devices),
                    encode_json_vec(&dup.sender_device_ids),
                    dup.icon_sha256,
                    dup.attachment_path,
                    dup.attachment_mime,
                    dup.id,
                ],
            )?;
            return Ok(IngestOutcome::Merged(dup));
        }

        // 3. Insert new notification row.
        let uids = vec![payload.notification_uid.clone()];
        let devices = vec![payload.sender_device_name.clone()];
        let device_ids = vec![sender_device_id.to_string()];

        conn.execute(
            r#"
            INSERT INTO notifications (
                notification_uids_json, sender_devices_json, sender_device_ids_json,
                package_name, app_name, icon_sha256, title, body, sub_text, category,
                group_key, attachment_path, attachment_mime, dedup_hash, posted_at, dismissed_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, NULL)
            "#,
            params![
                encode_json_vec(&uids),
                encode_json_vec(&devices),
                encode_json_vec(&device_ids),
                payload.app.package,
                payload.app.name,
                payload.app.icon_sha256,
                payload.content.title,
                payload.content.body,
                payload.content.sub_text,
                payload.content.category,
                payload.content.group_key,
                attachment_path,
                attachment_mime,
                dedup_hash,
                payload.posted_at,
            ],
        )?;
        let id = conn.last_insert_rowid();
        Ok(IngestOutcome::Inserted(NotificationRecord {
            id,
            notification_uids: uids,
            sender_devices: devices,
            sender_device_ids: device_ids,
            package_name: payload.app.package.clone(),
            app_name: payload.app.name.clone(),
            icon_sha256: payload.app.icon_sha256.clone(),
            title: payload.content.title.clone(),
            body: payload.content.body.clone(),
            sub_text: payload.content.sub_text.clone(),
            category: payload.content.category.clone(),
            group_key: payload.content.group_key.clone(),
            attachment_path,
            attachment_mime,
            dedup_hash,
            posted_at: payload.posted_at,
            dismissed_at: None,
        }))
    }

    /// Marks any rows matching the given `notification_uids` as dismissed.
    /// Returns the IDs of rows affected.
    pub fn mark_dismissed_by_uids(
        &self,
        uids: &[String],
        dismissed_at: i64,
    ) -> Result<Vec<i64>, StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut affected = Vec::new();
        for uid in uids {
            let quoted = serde_json::to_string(uid).unwrap_or_default();
            let pattern = format!("%{}%", escape_like(&quoted));
            let mut stmt = conn.prepare(
                "SELECT id, notification_uids_json FROM notifications WHERE notification_uids_json LIKE ?1 ESCAPE '\\'",
            )?;
            let rows = stmt
                .query_map(params![pattern], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for (row_id, uids_json) in rows {
                let parsed = decode_json_vec(&uids_json);
                if parsed.iter().any(|u| u == uid) {
                    let changed = conn.execute(
                        "UPDATE notifications SET dismissed_at = ?1 WHERE id = ?2 AND dismissed_at IS NULL",
                        params![dismissed_at, row_id],
                    )?;
                    if changed > 0 && !affected.contains(&row_id) {
                        affected.push(row_id);
                    }
                }
            }
        }
        Ok(affected)
    }

    /// Marks a row dismissed if it is currently active.
    /// Returns `Some(record)` only when the row transitioned from active to dismissed.
    pub fn mark_dismissed_by_id(
        &self,
        row_id: i64,
        dismissed_at: i64,
    ) -> Result<Option<NotificationRecord>, StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let changed = conn.execute(
            "UPDATE notifications SET dismissed_at = ?1 WHERE id = ?2 AND dismissed_at IS NULL",
            params![dismissed_at, row_id],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        get_row_by_id(&conn, row_id)
    }

    pub fn mark_all_active_dismissed(
        &self,
        dismissed_at: i64,
    ) -> Result<Vec<NotificationRecord>, StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(&format!(
            "SELECT {NOTIFICATION_COLS} FROM notifications WHERE dismissed_at IS NULL ORDER BY posted_at DESC, id DESC"
        ))?;
        let active = stmt
            .query_map([], map_notification_row)?
            .collect::<Result<Vec<_>, _>>()?;
        conn.execute(
            "UPDATE notifications SET dismissed_at = ?1 WHERE dismissed_at IS NULL",
            params![dismissed_at],
        )?;
        Ok(active)
    }

    pub fn get_by_id(&self, row_id: i64) -> Result<Option<NotificationRecord>, StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        get_row_by_id(&conn, row_id)
    }

    pub fn has_uid(&self, uid: &str) -> Result<bool, StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        Ok(find_by_uid(&conn, uid)?.is_some())
    }

    pub fn list_notifications(
        &self,
        query: Option<&str>,
        limit: usize,
    ) -> Result<Vec<NotificationRecord>, StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let trimmed = query.map(str::trim).unwrap_or("");
        if trimmed.is_empty() {
            let mut stmt = conn.prepare(&format!(
                "SELECT {NOTIFICATION_COLS} FROM notifications ORDER BY posted_at DESC, id DESC LIMIT ?1"
            ))?;
            let rows = stmt
                .query_map(params![limit as i64], map_notification_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        } else {
            let pattern = format!("%{}%", escape_like(trimmed));
            let mut stmt = conn.prepare(&format!(
                r#"
                SELECT {NOTIFICATION_COLS}
                FROM notifications
                WHERE title LIKE ?1 ESCAPE '\'
                   OR body LIKE ?1 ESCAPE '\'
                   OR app_name LIKE ?1 ESCAPE '\'
                   OR package_name LIKE ?1 ESCAPE '\'
                   OR sender_devices_json LIKE ?1 ESCAPE '\'
                ORDER BY posted_at DESC, id DESC
                LIMIT ?2
                "#
            ))?;
            let rows = stmt
                .query_map(params![pattern, limit as i64], map_notification_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        }
    }

    pub fn count_active(&self) -> Result<usize, StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM notifications WHERE dismissed_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(count.max(0) as usize)
    }

    pub fn clear_history(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute("DELETE FROM notifications", [])?;
        Ok(())
    }

    /// Prunes rows older than `max_days` or beyond the newest `max_rows` (plus stale outbox entries).
    /// Returns `(deleted_notification_rows, remaining_referenced_attachment_paths)`.
    pub fn prune_retention(
        &self,
        now_ms: i64,
        max_days: i64,
        max_rows: i64,
    ) -> Result<(usize, HashSet<String>), StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let cutoff = now_ms.saturating_sub(max_days.clamp(1, 3650).saturating_mul(86_400_000));
        let d1 = conn.execute(
            "DELETE FROM notifications WHERE posted_at < ?1",
            params![cutoff],
        )?;
        let d2 = conn.execute(
            r#"
            DELETE FROM notifications
            WHERE id NOT IN (
                SELECT id FROM notifications ORDER BY posted_at DESC, id DESC LIMIT ?1
            )
            "#,
            params![max_rows.max(1)],
        )?;
        conn.execute(
            "DELETE FROM outbox WHERE created_at < ?1",
            params![now_ms.saturating_sub(OUTBOX_TTL_MS)],
        )?;

        let mut stmt =
            conn.prepare("SELECT attachment_path FROM notifications WHERE attachment_path IS NOT NULL")?;
        let referenced = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<HashSet<_>, _>>()?;

        Ok((d1 + d2, referenced))
    }

    // ---- Outbox (offline dismissal queue) ----

    pub fn enqueue_outbox(
        &self,
        event_id: &str,
        ciphertext: &str,
        created_at: i64,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO outbox (event_id, ciphertext, created_at) VALUES (?1, ?2, ?3)",
            params![event_id, ciphertext, created_at],
        )?;
        Ok(())
    }

    pub fn list_outbox(&self, now_ms: i64) -> Result<Vec<OutboxRow>, StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "DELETE FROM outbox WHERE created_at < ?1",
            params![now_ms.saturating_sub(OUTBOX_TTL_MS)],
        )?;
        let mut stmt = conn.prepare(
            "SELECT event_id, ciphertext, created_at FROM outbox ORDER BY created_at ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(OutboxRow {
                    event_id: row.get(0)?,
                    ciphertext: row.get(1)?,
                    created_at: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_outbox(&self, event_id: &str) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute("DELETE FROM outbox WHERE event_id = ?1", params![event_id])?;
        Ok(())
    }

    pub fn clear_outbox(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute("DELETE FROM outbox", [])?;
        Ok(())
    }

    // ---- KV state ----

    pub fn get_kv(&self, key: &str) -> Result<Option<String>, StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.query_row("SELECT value FROM kv_state WHERE key = ?1", params![key], |r| {
            r.get(0)
        })
        .optional()
        .map_err(Into::into)
    }

    pub fn set_kv(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO kv_state (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_last_acked_seq(&self) -> Result<i64, StorageError> {
        Ok(self
            .get_kv("last_acked_seq")?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0))
    }

    pub fn set_last_acked_seq(&self, seq: i64) -> Result<(), StorageError> {
        let current = self.get_last_acked_seq()?;
        if seq > current {
            self.set_kv("last_acked_seq", &seq.to_string())?;
        }
        Ok(())
    }

    pub fn reset_last_acked_seq(&self) -> Result<(), StorageError> {
        self.set_kv("last_acked_seq", "0")
    }

    pub fn is_muted(&self) -> Result<bool, StorageError> {
        Ok(self.get_kv("muted")?.as_deref() == Some("1"))
    }

    pub fn set_muted(&self, muted: bool) -> Result<(), StorageError> {
        self.set_kv("muted", if muted { "1" } else { "0" })
    }

    pub fn is_privacy_mode(&self) -> Result<bool, StorageError> {
        Ok(self.get_kv("privacy_mode")?.as_deref() == Some("1"))
    }

    pub fn set_privacy_mode(&self, enabled: bool) -> Result<(), StorageError> {
        self.set_kv("privacy_mode", if enabled { "1" } else { "0" })
    }

    pub fn retention_settings(&self) -> Result<RetentionSettings, StorageError> {
        let days = self
            .get_kv("retention_days")?
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|&d| d >= 1)
            .unwrap_or(DEFAULT_RETENTION_DAYS);
        let max_rows = self
            .get_kv("retention_max_rows")?
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|&r| r >= 10)
            .unwrap_or(DEFAULT_RETENTION_MAX_ROWS);
        Ok(RetentionSettings { days, max_rows })
    }

    pub fn set_retention_settings(&self, days: i64, max_rows: i64) -> Result<(), StorageError> {
        self.set_kv("retention_days", &days.clamp(1, 3650).to_string())?;
        self.set_kv("retention_max_rows", &max_rows.clamp(10, 100_000).to_string())?;
        Ok(())
    }
}

const NOTIFICATION_COLS: &str = r#"
    id, notification_uids_json, sender_devices_json, sender_device_ids_json,
    package_name, app_name, icon_sha256, title, body, sub_text, category,
    group_key, attachment_path, attachment_mime, dedup_hash, posted_at, dismissed_at
"#;

fn map_notification_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NotificationRecord> {
    let uids_json: String = row.get(1)?;
    let devices_json: String = row.get(2)?;
    let device_ids_json: String = row.get(3)?;
    Ok(NotificationRecord {
        id: row.get(0)?,
        notification_uids: decode_json_vec(&uids_json),
        sender_devices: decode_json_vec(&devices_json),
        sender_device_ids: decode_json_vec(&device_ids_json),
        package_name: row.get(4)?,
        app_name: row.get(5)?,
        icon_sha256: row.get(6)?,
        title: row.get(7)?,
        body: row.get(8)?,
        sub_text: row.get(9)?,
        category: row.get(10)?,
        group_key: row.get(11)?,
        attachment_path: row.get(12)?,
        attachment_mime: row.get(13)?,
        dedup_hash: row.get(14)?,
        posted_at: row.get(15)?,
        dismissed_at: row.get(16)?,
    })
}

fn get_row_by_id(
    conn: &Connection,
    row_id: i64,
) -> Result<Option<NotificationRecord>, StorageError> {
    conn.query_row(
        &format!("SELECT {NOTIFICATION_COLS} FROM notifications WHERE id = ?1"),
        params![row_id],
        map_notification_row,
    )
    .optional()
    .map_err(Into::into)
}

fn find_by_uid(conn: &Connection, uid: &str) -> Result<Option<NotificationRecord>, StorageError> {
    let quoted = serde_json::to_string(uid).unwrap_or_default();
    let pattern = format!("%{}%", escape_like(&quoted));
    let mut stmt = conn.prepare(&format!(
        "SELECT {NOTIFICATION_COLS} FROM notifications WHERE notification_uids_json LIKE ?1 ESCAPE '\\'"
    ))?;
    let rows = stmt
        .query_map(params![pattern], map_notification_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows
        .into_iter()
        .find(|r| r.notification_uids.iter().any(|u| u == uid)))
}

fn find_recent_active_by_hash(
    conn: &Connection,
    dedup_hash: &str,
    posted_at: i64,
) -> Result<Vec<NotificationRecord>, StorageError> {
    let min_ts = posted_at.saturating_sub(DEDUP_WINDOW_MS);
    let max_ts = posted_at.saturating_add(DEDUP_WINDOW_MS);
    let mut stmt = conn.prepare(&format!(
        r#"
        SELECT {NOTIFICATION_COLS}
        FROM notifications
        WHERE dedup_hash = ?1
          AND dismissed_at IS NULL
          AND posted_at BETWEEN ?2 AND ?3
        ORDER BY posted_at DESC, id DESC
        "#
    ))?;
    let rows = stmt
        .query_map(params![dedup_hash, min_ts, max_ts], map_notification_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn encode_json_vec(items: &[String]) -> String {
    serde_json::to_string(items).unwrap_or_else(|_| "[]".to_string())
}

fn decode_json_vec(raw: &str) -> Vec<String> {
    serde_json::from_str(raw).unwrap_or_default()
}

fn push_unique(vec: &mut Vec<String>, item: &str) {
    if !vec.iter().any(|x| x == item) {
        vec.push(item.to_string());
    }
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Disk cache for decrypted 64x64 WebP icons (LRU 200) and image attachments.
pub struct BlobCache {
    icons_dir: PathBuf,
    attachments_dir: PathBuf,
    max_icons: usize,
    icon_lock: Mutex<()>,
    attachment_lock: Mutex<()>,
}

impl BlobCache {
    pub fn new(cache_root: &Path, max_icons: usize) -> Result<Self, StorageError> {
        let icons_dir = cache_root.join("icons");
        let attachments_dir = cache_root.join("attachments");
        fs::create_dir_all(&icons_dir)?;
        fs::create_dir_all(&attachments_dir)?;
        Ok(Self {
            icons_dir,
            attachments_dir,
            max_icons: max_icons.max(1),
            icon_lock: Mutex::new(()),
            attachment_lock: Mutex::new(()),
        })
    }

    pub fn icons_dir(&self) -> &Path {
        &self.icons_dir
    }

    pub fn attachments_dir(&self) -> &Path {
        &self.attachments_dir
    }

    pub fn get_icon_path(&self, sha256: &str) -> Option<PathBuf> {
        if !is_valid_sha256_hex(sha256) {
            return None;
        }
        let _guard = self.icon_lock.lock().expect("icon_lock poisoned");
        let path = self.icons_dir.join(format!("{sha256}.webp"));
        if !path.is_file() {
            return None;
        }
        let _ = touch_mtime(&path);
        Some(path)
    }

    pub fn put_icon(&self, sha256: &str, bytes: &[u8]) -> Result<PathBuf, StorageError> {
        if !is_valid_sha256_hex(sha256) {
            return Err(StorageError::InvalidId("invalid icon sha256".into()));
        }
        let _guard = self.icon_lock.lock().expect("icon_lock poisoned");
        fs::create_dir_all(&self.icons_dir)?;
        let target = self.icons_dir.join(format!("{sha256}.webp"));
        write_atomic(&self.icons_dir, sha256, &target, bytes)?;
        let _ = touch_mtime(&target);
        self.evict_icons_if_needed()?;
        Ok(target)
    }

    pub fn get_attachment_path(&self, blob_id: &str, mime: &str) -> Option<PathBuf> {
        if !is_valid_blob_id(blob_id) {
            return None;
        }
        let ext = attachment_extension_for_mime(mime);
        let path = self.attachments_dir.join(format!("{blob_id}.{ext}"));
        if path.is_file() {
            Some(path)
        } else {
            None
        }
    }

    pub fn put_attachment(
        &self,
        blob_id: &str,
        mime: &str,
        bytes: &[u8],
    ) -> Result<PathBuf, StorageError> {
        if !is_valid_blob_id(blob_id) {
            return Err(StorageError::InvalidId("invalid blob_id".into()));
        }
        let _guard = self
            .attachment_lock
            .lock()
            .expect("attachment_lock poisoned");
        fs::create_dir_all(&self.attachments_dir)?;
        let ext = attachment_extension_for_mime(mime);
        let target = self.attachments_dir.join(format!("{blob_id}.{ext}"));
        write_atomic(&self.attachments_dir, blob_id, &target, bytes)?;
        Ok(target)
    }

    pub fn prune_orphan_attachments(&self, referenced_paths: &HashSet<String>) -> usize {
        let Ok(entries) = fs::read_dir(&self.attachments_dir) else {
            return 0;
        };
        // Match by file name so symlinked cache prefixes (e.g. /var vs /private/var) never cause false pruning.
        let referenced_names: HashSet<OsString> = referenced_paths
            .iter()
            .filter_map(|p| Path::new(p).file_name().map(|n| n.to_os_string()))
            .collect();
        let now = SystemTime::now();
        let stale_tmp_age = Duration::from_secs(60 * 60);

        let mut deleted = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) == Some("tmp") {
                let is_stale = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|m| now.duration_since(m).ok())
                    .is_some_and(|age| age >= stale_tmp_age);
                if is_stale {
                    let _ = fs::remove_file(&path);
                }
                continue;
            }
            let Some(name) = path.file_name() else {
                continue;
            };
            if !referenced_names.contains(name) && fs::remove_file(&path).is_ok() {
                deleted += 1;
            }
        }
        deleted
    }

    pub fn clear_attachments(&self) {
        if let Ok(entries) = fs::read_dir(&self.attachments_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let _ = fs::remove_file(p);
                }
            }
        }
    }

    fn evict_icons_if_needed(&self) -> Result<(), StorageError> {
        let mut files: Vec<(SystemTime, PathBuf)> = Vec::new();
        for entry in fs::read_dir(&self.icons_dir)?.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("webp") {
                let mtime = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(UNIX_EPOCH);
                files.push((mtime, path));
            }
        }
        if files.len() <= self.max_icons {
            return Ok(());
        }
        files.sort_by_key(|(mtime, _)| *mtime);
        let to_remove = files.len() - self.max_icons;
        for (_, path) in files.into_iter().take(to_remove) {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }
}

static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

fn write_atomic(
    dir: &Path,
    prefix: &str,
    target: &Path,
    bytes: &[u8],
) -> Result<(), StorageError> {
    let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!("{prefix}.{}.{seq}.tmp", std::process::id()));
    fs::write(&tmp, bytes)?;
    if let Err(err) = fs::rename(&tmp, target) {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

/// Removes files inside `dir` whose mtime is older than `max_age` (used to sweep stale macOS staging files).
pub fn prune_stale_dir_files(dir: &Path, max_age: Duration) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut deleted = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let is_stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age >= max_age);
        if is_stale && fs::remove_file(&path).is_ok() {
            deleted += 1;
        }
    }
    deleted
}

fn touch_mtime(path: &Path) -> std::io::Result<()> {
    let f = File::options().write(true).open(path)?;
    f.set_modified(SystemTime::now())
}

pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AppInfo, NotificationContent};

    fn sample_posted(uid: &str, device: &str, posted_at: i64, title: &str, body: &str) -> NotificationPosted {
        NotificationPosted {
            notification_uid: uid.to_string(),
            sender_device_name: device.to_string(),
            posted_at,
            app: AppInfo {
                package: "com.whatsapp".to_string(),
                name: "WhatsApp".to_string(),
                icon_sha256: None,
                icon_blob_id: None,
            },
            content: NotificationContent {
                title: title.to_string(),
                body: body.to_string(),
                sub_text: None,
                category: Some("msg".to_string()),
                group_key: None,
            },
            attachments: vec![],
        }
    }

    #[test]
    fn dedup_merges_within_5s_from_different_devices_and_tracks_all_uids() {
        let db = Database::open_in_memory().unwrap();
        let n1 = sample_posted("uid_a", "Pixel 9", 1_700_000_000_000, "Alice ", "Hello\r\nworld");
        let n2 = sample_posted("uid_b", "Galaxy S24", 1_700_000_004_900, "Alice", "Hello\nworld ");
        let n3 = sample_posted("uid_c", "OnePlus 12", 1_700_000_010_000, "Alice", "Hello\nworld");

        let r1 = db.ingest_posted("dev_a", &n1, None, None).unwrap();
        let row_id = match r1 {
            IngestOutcome::Inserted(r) => r.id,
            other => panic!("expected Inserted, got {other:?}"),
        };

        // Re-ingesting same UID is idempotent.
        assert!(matches!(
            db.ingest_posted("dev_a", &n1, None, None).unwrap(),
            IngestOutcome::AlreadyExists(_)
        ));

        // Second device within 5s merges into row_id.
        let r2 = db.ingest_posted("dev_b", &n2, None, None).unwrap();
        match r2 {
            IngestOutcome::Merged(r) => {
                assert_eq!(r.id, row_id);
                assert_eq!(r.notification_uids, vec!["uid_a", "uid_b"]);
                assert_eq!(r.sender_devices, vec!["Pixel 9", "Galaxy S24"]);
                assert_eq!(r.sender_device_ids, vec!["dev_a", "dev_b"]);
            }
            other => panic!("expected Merged, got {other:?}"),
        }

        // Third device after 5s creates a new row.
        assert!(matches!(
            db.ingest_posted("dev_c", &n3, None, None).unwrap(),
            IngestOutcome::Inserted(_)
        ));
        assert_eq!(db.count_active().unwrap(), 2);

        // Dismissing by uid_b marks the merged row dismissed.
        let affected = db
            .mark_dismissed_by_uids(&["uid_b".to_string()], 1_700_000_020_000)
            .unwrap();
        assert_eq!(affected, vec![row_id]);
        assert_eq!(db.count_active().unwrap(), 1);

        // mark_dismissed_by_id transitions only once (idempotent).
        let active_row = db
            .list_notifications(None, 10)
            .unwrap()
            .into_iter()
            .find(|r| r.dismissed_at.is_none())
            .unwrap();
        assert!(db
            .mark_dismissed_by_id(active_row.id, 1_700_000_030_000)
            .unwrap()
            .is_some());
        assert!(db
            .mark_dismissed_by_id(active_row.id, 1_700_000_031_000)
            .unwrap()
            .is_none());
    }

    #[test]
    fn search_and_retention_prune_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("test.db")).unwrap();
        let cache = BlobCache::new(dir.path(), 3).unwrap();

        let att_keep = cache
            .put_attachment("img_keep0001", "image/webp", b"keep-bytes")
            .unwrap();
        let att_old = cache
            .put_attachment("img_old00001", "image/jpeg", b"old-bytes")
            .unwrap();
        let att_orphan = cache
            .put_attachment("img_orphan01", "image/png", b"orphan-bytes")
            .unwrap();

        let now = 2_000_000_000_000i64;
        let old_ts = now - 31 * 86_400_000;

        db.ingest_posted(
            "dev_a",
            &sample_posted("u_old", "Pixel 9", old_ts, "Old", "Expired msg"),
            Some(att_old.to_string_lossy().to_string()),
            Some("image/jpeg".into()),
        )
        .unwrap();
        db.ingest_posted(
            "dev_a",
            &sample_posted("u_new", "Pixel 9", now - 1000, "Dinner 100%_ok", "See you at 7"),
            Some(att_keep.to_string_lossy().to_string()),
            Some("image/webp".into()),
        )
        .unwrap();

        // Search escapes LIKE wildcards cleanly.
        let found = db.list_notifications(Some("100%_ok"), 50).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].title, "Dinner 100%_ok");

        // Retention prunes >30d row and orphan attachments.
        let (deleted, referenced) = db.prune_retention(now, 30, 5000).unwrap();
        assert_eq!(deleted, 1);
        let pruned_files = cache.prune_orphan_attachments(&referenced);
        assert_eq!(pruned_files, 2);
        assert!(att_keep.exists());
        assert!(!att_old.exists());
        assert!(!att_orphan.exists());
    }

    #[test]
    fn blob_cache_lru_eviction_and_path_traversal_guard() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::new(dir.path(), 2).unwrap();

        // Reject path traversal IDs.
        assert!(cache.put_icon("../evil", b"x").is_err());
        assert!(cache.get_icon_path("../evil").is_none());
        assert!(cache.put_attachment("../evil123", "image/webp", b"x").is_err());

        let h1 = "a".repeat(64);
        let h2 = "b".repeat(64);
        let h3 = "c".repeat(64);

        let p1 = cache.put_icon(&h1, b"1").unwrap();
        // Set deterministic mtimes so LRU order is unambiguous even on coarse filesystems.
        File::options()
            .write(true)
            .open(&p1)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(100))
            .unwrap();

        let p2 = cache.put_icon(&h2, b"2").unwrap();
        File::options()
            .write(true)
            .open(&p2)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(200))
            .unwrap();

        // Access h1 so it becomes newer than h2.
        assert!(cache.get_icon_path(&h1).is_some());

        // Inserting h3 evicts h2 (oldest).
        let _p3 = cache.put_icon(&h3, b"3").unwrap();
        assert!(cache.get_icon_path(&h1).is_some());
        assert!(cache.get_icon_path(&h3).is_some());
        assert!(cache.get_icon_path(&h2).is_none());
    }

    #[test]
    fn mark_dismissed_by_uids_is_idempotent_and_extreme_timestamps_do_not_overflow() {
        let db = Database::open_in_memory().unwrap();
        let n1 = sample_posted("uid_x", "Pixel 9", i64::MAX, "MaxTs", "Body");
        let n2 = sample_posted("uid_y", "Pixel 9", i64::MIN, "MinTs", "Body");
        let r1 = match db.ingest_posted("dev_a", &n1, None, None).unwrap() {
            IngestOutcome::Inserted(r) => r.id,
            other => panic!("expected Inserted, got {other:?}"),
        };
        assert!(matches!(
            db.ingest_posted("dev_a", &n2, None, None).unwrap(),
            IngestOutcome::Inserted(_)
        ));

        // First dismissal transitions active -> dismissed and reports row_id.
        assert_eq!(
            db.mark_dismissed_by_uids(&["uid_x".to_string()], 1_700_000_000_000)
                .unwrap(),
            vec![r1]
        );
        // Second dismissal on already-dismissed row returns empty affected list.
        assert!(db
            .mark_dismissed_by_uids(&["uid_x".to_string()], 1_700_000_005_000)
            .unwrap()
            .is_empty());

        // Extreme max_days and extreme negative now_ms do not overflow/underflow arithmetic.
        let _ = db.prune_retention(now_unix_ms(), i64::MAX, 5000).unwrap();
        let _ = db.prune_retention(i64::MIN, 30, 5000).unwrap();
        let _ = db.list_outbox(i64::MIN).unwrap();
    }

    #[test]
    fn concurrent_blob_writes_and_tmp_and_staging_pruning() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(BlobCache::new(dir.path(), 10).unwrap());

        // 8 concurrent writers targeting the same attachment blob_id must never collide on temp file.
        let mut threads = Vec::new();
        for i in 0..8u8 {
            let c = Arc::clone(&cache);
            threads.push(std::thread::spawn(move || {
                let payload = vec![i; 128];
                c.put_attachment("img_concurrent01", "image/webp", &payload)
                    .unwrap()
            }));
        }
        for t in threads {
            assert!(t.join().unwrap().is_file());
        }

        // Fresh .tmp file is preserved; stale .tmp file is deleted; filename-based matching handles symlink prefix drift.
        let fresh_tmp = cache.attachments_dir().join("img_live.1.tmp");
        let stale_tmp = cache.attachments_dir().join("img_stale.2.tmp");
        fs::write(&fresh_tmp, b"in-flight").unwrap();
        fs::write(&stale_tmp, b"abandoned").unwrap();
        File::options()
            .write(true)
            .open(&stale_tmp)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(100))
            .unwrap();

        let mut referenced = HashSet::new();
        referenced.insert("/different/symlink/prefix/img_concurrent01.webp".to_string());
        let pruned = cache.prune_orphan_attachments(&referenced);
        assert_eq!(pruned, 0);
        assert!(cache.get_attachment_path("img_concurrent01", "image/webp").is_some());
        assert!(fresh_tmp.exists());
        assert!(!stale_tmp.exists());

        // Stale staging directory cleanup removes old files while leaving fresh ones.
        let staging = dir.path().join("macos_attachments");
        fs::create_dir_all(&staging).unwrap();
        let fresh_stage = staging.join("fresh.png");
        let stale_stage = staging.join("stale.png");
        fs::write(&fresh_stage, b"new").unwrap();
        fs::write(&stale_stage, b"old").unwrap();
        File::options()
            .write(true)
            .open(&stale_stage)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(100))
            .unwrap();

        assert_eq!(prune_stale_dir_files(&staging, Duration::from_secs(3600)), 1);
        assert!(fresh_stage.exists());
        assert!(!stale_stage.exists());
    }
}
