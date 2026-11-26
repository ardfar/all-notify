use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_EVENT_CIPHERTEXT_BYTES: usize = 65_536;
pub const MAX_BLOB_BYTES: usize = 563_200; // 550 KB
pub const DEDUP_WINDOW_MS: i64 = 5_000;

/// Client -> Server WebSocket frames.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ClientFrame {
    Relay {
        event_id: String,
        target: String,
        ciphertext: String,
    },
    Ack {
        seq: i64,
    },
}

/// Server -> Client WebSocket frames.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ServerFrame {
    Event {
        seq: i64,
        event_id: String,
        sender_device_id: String,
        server_ts: i64,
        ciphertext: String,
    },
    ReplayComplete {
        latest_seq: i64,
    },
    Error {
        code: String,
        message: String,
    },
}

/// Decrypted inner notification payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum InnerPayload {
    #[serde(rename = "notification.posted")]
    Posted(Box<NotificationPosted>),
    #[serde(rename = "notification.dismissed")]
    Dismissed(NotificationDismissed),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationPosted {
    pub notification_uid: String,
    pub sender_device_name: String,
    pub posted_at: i64,
    pub app: AppInfo,
    pub content: NotificationContent,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppInfo {
    pub package: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_blob_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationContent {
    pub title: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentInfo {
    pub kind: String,
    pub blob_id: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationDismissed {
    pub notification_uids: Vec<String>,
    pub dismissed_at: i64,
    pub dismissed_by_device_name: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

/// Exact cross-device 5-second deduplication fingerprint matching Android (`Deduplicator.kt`).
pub fn dedup_fingerprint(package: &str, title: &str, body: &str) -> String {
    let norm_title = normalize_text(title);
    let norm_body = normalize_text(body);
    let raw = format!("{package}\0{norm_title}\0{norm_body}");
    sha256_hex(raw.as_bytes())
}

pub fn normalize_text(s: &str) -> String {
    s.replace("\r\n", "\n").trim().to_string()
}

/// Validates `^[a-zA-Z0-9_-]{8,64}$` to guarantee path safety and protocol conformance.
pub fn is_valid_blob_id(id: &str) -> bool {
    let len = id.len();
    (8..=64).contains(&len)
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Validates lowercase 64-char hex SHA-256 string (`^[0-9a-f]{64}$`).
pub fn is_valid_sha256_hex(h: &str) -> bool {
    h.len() == 64
        && h.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn attachment_extension_for_mime(mime: &str) -> &'static str {
    match mime {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        _ => "webp",
    }
}

pub fn mime_for_extension(ext: &str) -> &'static str {
    match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        _ => "image/webp",
    }
}
