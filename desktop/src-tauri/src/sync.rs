use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use http::Request;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    protocol::frame::coding::CloseCode,
    Error as WsError, Message,
};

use crate::crypto::{generate_ulid, CryptoEngine, PairingConfig};
use crate::notifier::{notification_id_for_row, OsNotification, PlatformNotifier};
use crate::protocol::{
    is_valid_blob_id, is_valid_sha256_hex, sha256_hex, ClientFrame, InnerPayload,
    NotificationDismissed, ServerFrame, MAX_BLOB_BYTES,
};
use crate::storage::{now_unix_ms, BlobCache, Database, IngestOutcome, NotificationRecord};

pub const SUMMARY_THRESHOLD: usize = 5;
const READ_TIMEOUT: Duration = Duration::from_secs(90);
const BACKOFF_STEPS_SECS: &[u64] = &[1, 2, 4, 8, 15, 30];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Unpaired,
    Connecting,
    Connected,
    Reconnecting,
    Disconnected,
    Unauthorized,
}

pub trait SyncObserver: Send + Sync {
    fn on_status_changed(&self, status: ConnectionStatus);
    fn on_notifications_changed(&self);
}

pub struct NoopObserver;
impl SyncObserver for NoopObserver {
    fn on_status_changed(&self, _status: ConnectionStatus) {}
    fn on_notifications_changed(&self) {}
}

/// Downloads and decrypts missing icon / image attachment blobs.
pub trait BlobFetcher: Send + Sync {
    fn fetch_icon<'a>(
        &'a self,
        sha256: &'a str,
        blob_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<PathBuf>> + Send + 'a>>;

    fn fetch_attachment<'a>(
        &'a self,
        blob_id: &'a str,
        mime: &'a str,
        sha256: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<PathBuf>> + Send + 'a>>;
}

pub struct NoopBlobFetcher;
impl BlobFetcher for NoopBlobFetcher {
    fn fetch_icon<'a>(
        &'a self,
        _sha256: &'a str,
        _blob_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<PathBuf>> + Send + 'a>> {
        Box::pin(async { None })
    }

    fn fetch_attachment<'a>(
        &'a self,
        _blob_id: &'a str,
        _mime: &'a str,
        _sha256: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<PathBuf>> + Send + 'a>> {
        Box::pin(async { None })
    }
}

pub struct HttpBlobFetcher {
    client: reqwest::Client,
    server_url: String,
    token: String,
    crypto: CryptoEngine,
    cache: Arc<BlobCache>,
}

impl HttpBlobFetcher {
    pub fn new(
        server_url: String,
        token: String,
        crypto: CryptoEngine,
        cache: Arc<BlobCache>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .expect("reqwest client build");
        Self {
            client,
            server_url: server_url.trim_end_matches('/').to_string(),
            token,
            crypto,
            cache,
        }
    }

    async fn download_and_decrypt(&self, blob_id: &str, expected_sha256: &str) -> Option<Vec<u8>> {
        if !is_valid_blob_id(blob_id) || !is_valid_sha256_hex(expected_sha256) {
            return None;
        }
        let url = format!("{}/v1/blobs/{blob_id}", self.server_url);
        let resp = self
            .client
            .get(&url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.token),
            )
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        if let Some(len) = resp.content_length() {
            if len as usize > MAX_BLOB_BYTES {
                return None;
            }
        }
        let encrypted = resp.bytes().await.ok()?;
        if encrypted.len() > MAX_BLOB_BYTES {
            return None;
        }
        let plaintext = self.crypto.decrypt_blob(blob_id, &encrypted).ok()?;
        if sha256_hex(&plaintext) != expected_sha256 {
            return None;
        }
        Some(plaintext)
    }
}

impl BlobFetcher for HttpBlobFetcher {
    fn fetch_icon<'a>(
        &'a self,
        sha256: &'a str,
        blob_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<PathBuf>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(cached) = self.cache.get_icon_path(sha256) {
                return Some(cached);
            }
            let plaintext = self.download_and_decrypt(blob_id, sha256).await?;
            self.cache.put_icon(sha256, &plaintext).ok()
        })
    }

    fn fetch_attachment<'a>(
        &'a self,
        blob_id: &'a str,
        mime: &'a str,
        sha256: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<PathBuf>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(cached) = self.cache.get_attachment_path(blob_id, mime) {
                return Some(cached);
            }
            let plaintext = self.download_and_decrypt(blob_id, sha256).await?;
            self.cache.put_attachment(blob_id, mime, &plaintext).ok()
        })
    }
}

/// Stateful protocol processor implementing anti-popup-storm replay buffering,
/// 5-second dedup, mute/privacy mode, and ACK progression.
pub struct SyncProcessor {
    db: Arc<Database>,
    blob_cache: Arc<BlobCache>,
    blob_fetcher: Arc<dyn BlobFetcher>,
    notifier: Arc<dyn PlatformNotifier>,
    observer: Arc<dyn SyncObserver>,
    crypto: CryptoEngine,
    own_device_id: String,
    replaying: bool,
    replay_highest_seq: i64,
    replay_active_row_ids: Vec<i64>,
    replay_pending_dismissals: Vec<NotificationDismissed>,
}

impl SyncProcessor {
    pub fn new(
        db: Arc<Database>,
        blob_cache: Arc<BlobCache>,
        blob_fetcher: Arc<dyn BlobFetcher>,
        notifier: Arc<dyn PlatformNotifier>,
        observer: Arc<dyn SyncObserver>,
        crypto: CryptoEngine,
        own_device_id: String,
    ) -> Self {
        Self {
            db,
            blob_cache,
            blob_fetcher,
            notifier,
            observer,
            crypto,
            own_device_id,
            replaying: true,
            replay_highest_seq: 0,
            replay_active_row_ids: Vec::new(),
            replay_pending_dismissals: Vec::new(),
        }
    }

    pub fn on_replay_start(&mut self) {
        self.replaying = true;
        self.replay_highest_seq = 0;
        self.replay_active_row_ids.clear();
        self.replay_pending_dismissals.clear();
    }

    pub async fn handle_server_frame(&mut self, frame: ServerFrame) -> Option<ClientFrame> {
        match frame {
            ServerFrame::Event {
                seq,
                event_id,
                sender_device_id,
                server_ts: _,
                ciphertext,
            } => {
                if self.replaying && seq > self.replay_highest_seq {
                    self.replay_highest_seq = seq;
                }

                // Defense-in-depth against server echo.
                if sender_device_id != self.own_device_id {
                    if let Ok(plaintext) =
                        self.crypto
                            .decrypt_event(&event_id, &sender_device_id, &ciphertext)
                    {
                        if let Ok(inner) = serde_json::from_slice::<InnerPayload>(&plaintext) {
                            match inner {
                                InnerPayload::Posted(posted) => {
                                    self.handle_posted(&sender_device_id, *posted).await;
                                }
                                InnerPayload::Dismissed(dismissed) => {
                                    self.handle_dismissed(dismissed);
                                }
                            }
                            if !self.replaying {
                                self.observer.on_notifications_changed();
                            }
                        }
                    }
                }

                if !self.replaying {
                    let _ = self.db.set_last_acked_seq(seq);
                    return Some(ClientFrame::Ack { seq });
                }
                None
            }
            ServerFrame::ReplayComplete { latest_seq } => {
                self.replaying = false;
                let pending_dismissals = std::mem::take(&mut self.replay_pending_dismissals);
                for dismissed in pending_dismissals {
                    self.handle_dismissed(dismissed);
                }
                let pending_ids = std::mem::take(&mut self.replay_active_row_ids);

                let muted = self.db.is_muted().unwrap_or(false);
                if !muted && !pending_ids.is_empty() {
                    let mut still_active = Vec::new();
                    for id in pending_ids {
                        if let Ok(Some(rec)) = self.db.get_by_id(id) {
                            if rec.dismissed_at.is_none() {
                                still_active.push(rec);
                            }
                        }
                    }

                    if still_active.len() > SUMMARY_THRESHOLD {
                        self.notifier.show_summary(still_active.len());
                    } else {
                        let privacy_mode = self.db.is_privacy_mode().unwrap_or(false);
                        for rec in &still_active {
                            let os_notif =
                                self.build_os_notification(rec, privacy_mode, false);
                            self.notifier.show(&os_notif);
                        }
                    }
                }

                self.observer.on_notifications_changed();

                let ack_seq = self.replay_highest_seq.max(latest_seq);
                if ack_seq > 0 {
                    let _ = self.db.set_last_acked_seq(ack_seq);
                    return Some(ClientFrame::Ack { seq: ack_seq });
                }
                None
            }
            ServerFrame::Error { code, message } => {
                eprintln!("[all-notify] relay error ({code}): {message}");
                None
            }
        }
    }

    async fn handle_posted(
        &mut self,
        sender_device_id: &str,
        posted: crate::protocol::NotificationPosted,
    ) {
        if self.db.has_uid(&posted.notification_uid).unwrap_or(false) {
            // Already ingested previously (e.g. live notification whose ACK was lost
            // before disconnect); skip redundant blob downloads and do not re-pop on replay.
            return;
        }

        let icon_fut = async {
            if let (Some(sha), Some(blob_id)) = (
                posted.app.icon_sha256.as_deref(),
                posted.app.icon_blob_id.as_deref(),
            ) {
                let _ = self.blob_fetcher.fetch_icon(sha, blob_id).await;
            }
        };

        let att_fut = async {
            if let Some(att) = posted.attachments.iter().find(|a| a.kind == "image") {
                if let Some(path) = self
                    .blob_fetcher
                    .fetch_attachment(&att.blob_id, &att.mime, &att.sha256)
                    .await
                {
                    return (
                        Some(path.to_string_lossy().to_string()),
                        Some(att.mime.clone()),
                    );
                }
            }
            (None, None)
        };

        let (_, (attachment_path, attachment_mime)) = tokio::join!(icon_fut, att_fut);

        let Ok(outcome) = self
            .db
            .ingest_posted(sender_device_id, &posted, attachment_path, attachment_mime)
        else {
            return;
        };

        let muted = self.db.is_muted().unwrap_or(false);
        let privacy_mode = self.db.is_privacy_mode().unwrap_or(false);

        match outcome {
            IngestOutcome::AlreadyExists(_) => {
                // Already ingested previously (e.g. live notification whose ACK was lost
                // before disconnect); do not pop it up again on reconnect replay.
            }
            IngestOutcome::Merged(rec) => {
                if !self.replaying && !muted {
                    let os_notif = self.build_os_notification(&rec, privacy_mode, true);
                    self.notifier.show(&os_notif);
                }
            }
            IngestOutcome::Inserted(rec) => {
                if self.replaying {
                    if !self.replay_active_row_ids.contains(&rec.id) {
                        self.replay_active_row_ids.push(rec.id);
                    }
                } else if !muted {
                    let os_notif = self.build_os_notification(&rec, privacy_mode, false);
                    self.notifier.show(&os_notif);
                }
            }
        }
    }

    fn handle_dismissed(&mut self, dismissed: NotificationDismissed) {
        if self.replaying {
            self.replay_pending_dismissals.push(dismissed.clone());
        }
        if let Ok(affected_ids) = self
            .db
            .mark_dismissed_by_uids(&dismissed.notification_uids, dismissed.dismissed_at)
        {
            for id in affected_ids {
                self.replay_active_row_ids.retain(|&x| x != id);
                self.notifier.clear(id);
            }
        }
    }

    fn build_os_notification(
        &self,
        rec: &NotificationRecord,
        privacy_mode: bool,
        silent_update: bool,
    ) -> OsNotification {
        let icon_path = rec
            .icon_sha256
            .as_deref()
            .and_then(|sha| self.blob_cache.get_icon_path(sha));
        let attachment_path = if privacy_mode {
            None
        } else {
            rec.attachment_path
                .as_deref()
                .map(PathBuf::from)
                .filter(|p| p.is_file())
        };
        let body = if privacy_mode {
            "New notification".to_string()
        } else {
            rec.body.clone()
        };
        let sender_label = rec.sender_devices.join(", ");

        OsNotification {
            id: notification_id_for_row(rec.id),
            row_id: rec.id,
            app_name: rec.app_name.clone(),
            sender_label,
            title: rec.title.clone(),
            body,
            icon_path,
            attachment_path,
            silent_update,
        }
    }
}

pub fn encrypt_dismiss_event(
    crypto: &CryptoEngine,
    own_device_id: &str,
    own_device_name: &str,
    notification_uids: Vec<String>,
) -> Option<(String, String)> {
    let mut unique_uids = Vec::with_capacity(notification_uids.len());
    for uid in notification_uids {
        if !uid.is_empty() && !unique_uids.contains(&uid) {
            unique_uids.push(uid);
        }
    }
    if unique_uids.is_empty() {
        return None;
    }
    let payload = InnerPayload::Dismissed(NotificationDismissed {
        notification_uids: unique_uids,
        dismissed_at: now_unix_ms(),
        dismissed_by_device_name: own_device_name.to_string(),
    });
    let plaintext = serde_json::to_vec(&payload).ok()?;
    let event_id = generate_ulid();
    let ciphertext = crypto
        .encrypt_event(&event_id, own_device_id, &plaintext)
        .ok()?;
    Some((event_id, ciphertext))
}

enum SyncTask {
    Tokio(JoinHandle<()>),
    Tauri(tauri::async_runtime::JoinHandle<()>),
}

impl SyncTask {
    fn abort(self) {
        match self {
            SyncTask::Tokio(handle) => handle.abort(),
            SyncTask::Tauri(handle) => handle.abort(),
        }
    }
}

/// Handle controlling a running background WebSocket sync loop.
pub struct SyncHandle {
    shutdown_tx: watch::Sender<bool>,
    outbox_notify: Arc<Notify>,
    db: Arc<Database>,
    crypto: Option<CryptoEngine>,
    device_id: String,
    device_name: String,
    task: SyncTask,
}

impl SyncHandle {
    /// Durably encrypts and persists the dismissal to SQLite outbox before waking the WS loop,
    /// chunking to <=100 unique UIDs per frame to stay well below the 64 KB WS frame limit.
    pub fn send_dismiss(&self, notification_uids: Vec<String>) {
        if notification_uids.is_empty() {
            return;
        }
        let Some(crypto) = self.crypto.as_ref() else {
            return;
        };
        let mut unique = Vec::with_capacity(notification_uids.len());
        for uid in notification_uids {
            if !uid.is_empty() && !unique.contains(&uid) {
                unique.push(uid);
            }
        }
        let mut enqueued = false;
        let now = now_unix_ms();
        for chunk in unique.chunks(100) {
            if let Some((event_id, ct)) = encrypt_dismiss_event(
                crypto,
                &self.device_id,
                &self.device_name,
                chunk.to_vec(),
            ) {
                let _ = self.db.enqueue_outbox(&event_id, &ct, now);
                enqueued = true;
            }
        }
        if enqueued {
            self.outbox_notify.notify_one();
        }
    }

    pub fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        self.task.abort();
    }
}

pub fn spawn_sync_loop(
    config: PairingConfig,
    db: Arc<Database>,
    blob_cache: Arc<BlobCache>,
    notifier: Arc<dyn PlatformNotifier>,
    observer: Arc<dyn SyncObserver>,
) -> SyncHandle {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let outbox_notify = Arc::new(Notify::new());
    let crypto = CryptoEngine::new(&config.key_bytes).ok();
    let device_id = config.device_id.clone();
    let device_name = config.device_name.clone();

    let fut = run_sync_loop(
        config,
        Arc::clone(&db),
        blob_cache,
        notifier,
        observer,
        shutdown_rx,
        Arc::clone(&outbox_notify),
    );
    let task = match tokio::runtime::Handle::try_current() {
        Ok(handle) => SyncTask::Tokio(handle.spawn(fut)),
        Err(_) => SyncTask::Tauri(tauri::async_runtime::spawn(fut)),
    };

    SyncHandle {
        shutdown_tx,
        outbox_notify,
        db,
        crypto,
        device_id,
        device_name,
        task,
    }
}

async fn flush_outbox<S>(db: &Database, ws_sink: &mut S) -> bool
where
    S: SinkExt<Message> + Unpin,
{
    let Ok(pending) = db.list_outbox(now_unix_ms()) else {
        return true;
    };
    for row in pending {
        let frame = ClientFrame::Relay {
            event_id: row.event_id.clone(),
            target: "broadcast".to_string(),
            ciphertext: row.ciphertext,
        };
        if let Ok(txt) = serde_json::to_string(&frame) {
            if ws_sink.send(Message::Text(txt.into())).await.is_ok() {
                let _ = db.delete_outbox(&row.event_id);
            } else {
                return false;
            }
        }
    }
    true
}

async fn run_sync_loop(
    config: PairingConfig,
    db: Arc<Database>,
    blob_cache: Arc<BlobCache>,
    notifier: Arc<dyn PlatformNotifier>,
    observer: Arc<dyn SyncObserver>,
    mut shutdown_rx: watch::Receiver<bool>,
    outbox_notify: Arc<Notify>,
) {
    let Ok(crypto) = CryptoEngine::new(&config.key_bytes) else {
        observer.on_status_changed(ConnectionStatus::Disconnected);
        return;
    };

    let blob_fetcher: Arc<dyn BlobFetcher> = Arc::new(HttpBlobFetcher::new(
        config.server_url.clone(),
        config.token.clone(),
        crypto.clone(),
        Arc::clone(&blob_cache),
    ));

    let mut processor = SyncProcessor::new(
        Arc::clone(&db),
        Arc::clone(&blob_cache),
        blob_fetcher,
        notifier,
        Arc::clone(&observer),
        crypto,
        config.device_id.clone(),
    );

    let mut attempt: usize = 0;

    loop {
        if *shutdown_rx.borrow() {
            observer.on_status_changed(ConnectionStatus::Disconnected);
            return;
        }

        observer.on_status_changed(if attempt == 0 {
            ConnectionStatus::Connecting
        } else {
            ConnectionStatus::Reconnecting
        });

        let after_seq = db.get_last_acked_seq().unwrap_or(0);
        let ws_uri = format!("{}?after_seq={after_seq}", config.ws_url);

        let req = match build_ws_request(&ws_uri, &config.token) {
            Ok(r) => r,
            Err(_) => {
                observer.on_status_changed(ConnectionStatus::Disconnected);
                return;
            }
        };

        match tokio_tungstenite::connect_async(req).await {
            Ok((ws_stream, _)) => {
                processor.on_replay_start();
                observer.on_status_changed(ConnectionStatus::Connected);

                let (mut ws_sink, mut ws_read) = ws_stream.split();
                let mut revoked = false;

                // Flush any offline dismissals persisted in outbox; on failure fall through to backoff.
                if flush_outbox(&db, &mut ws_sink).await {
                    let mut read_deadline = tokio::time::Instant::now() + READ_TIMEOUT;

                    // Active connection read/write loop.
                    loop {
                        tokio::select! {
                            _ = shutdown_rx.changed() => {
                                let _ = ws_sink.send(Message::Close(None)).await;
                                observer.on_status_changed(ConnectionStatus::Disconnected);
                                return;
                            }
                            _ = outbox_notify.notified() => {
                                if !flush_outbox(&db, &mut ws_sink).await {
                                    break;
                                }
                            }
                            _ = tokio::time::sleep_until(read_deadline) => {
                                // Server keepalive timeout (90s without any incoming WS frame).
                                break;
                            }
                            incoming = ws_read.next() => {
                                read_deadline = tokio::time::Instant::now() + READ_TIMEOUT;
                                match incoming {
                                    Some(Ok(Message::Text(text))) => {
                                        if let Ok(frame) = serde_json::from_str::<ServerFrame>(&text) {
                                            if matches!(frame, ServerFrame::ReplayComplete { .. }) {
                                                attempt = 0;
                                            }
                                            if let Some(ack) = processor.handle_server_frame(frame).await {
                                                if let Ok(ack_txt) = serde_json::to_string(&ack) {
                                                    if ws_sink.send(Message::Text(ack_txt.into())).await.is_err() {
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Some(Ok(Message::Ping(payload))) => {
                                        if ws_sink.send(Message::Pong(payload)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Some(Ok(Message::Pong(_))) => {}
                                    Some(Ok(Message::Close(Some(cf))))
                                        if cf.code == CloseCode::Policy
                                            && cf.reason.to_ascii_lowercase().contains("revok") =>
                                    {
                                        revoked = true;
                                        break;
                                    }
                                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                                        break;
                                    }
                                    Some(Ok(_)) => {}
                                }
                            }
                        }
                    }
                }

                if revoked {
                    observer.on_status_changed(ConnectionStatus::Unauthorized);
                    return;
                }
            }
            Err(WsError::Http(resp))
                if resp.status() == http::StatusCode::UNAUTHORIZED
                    || resp.status() == http::StatusCode::FORBIDDEN =>
            {
                observer.on_status_changed(ConnectionStatus::Unauthorized);
                return;
            }
            Err(_) => {
                // Transient connection failure; fall through to backoff.
            }
        }

        if *shutdown_rx.borrow() {
            observer.on_status_changed(ConnectionStatus::Disconnected);
            return;
        }

        observer.on_status_changed(ConnectionStatus::Reconnecting);
        let delay = backoff_duration(attempt);
        attempt = attempt.saturating_add(1);

        tokio::select! {
            _ = shutdown_rx.changed() => {
                observer.on_status_changed(ConnectionStatus::Disconnected);
                return;
            }
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

fn build_ws_request(uri: &str, token: &str) -> Result<Request<()>, String> {
    let mut req = uri.into_client_request().map_err(|e| e.to_string())?;
    let headers = req.headers_mut();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {token}")).map_err(|e| e.to_string())?,
    );
    headers.insert(
        http::header::HeaderName::from_static("x-allnotify-protocol"),
        http::HeaderValue::from_static("1"),
    );
    Ok(req)
}

pub fn backoff_duration(attempt: usize) -> Duration {
    let base_secs = BACKOFF_STEPS_SECS[attempt.min(BACKOFF_STEPS_SECS.len() - 1)];
    let base_ms = (base_secs * 1000) as f64;
    let factor: f64 = rand::thread_rng().gen_range(0.8..=1.2);
    Duration::from_millis((base_ms * factor).round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AppInfo, AttachmentInfo, NotificationContent, NotificationPosted};
    use base64::Engine;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockNotifier {
        shown: Mutex<Vec<OsNotification>>,
        summaries: Mutex<Vec<usize>>,
        cleared: Mutex<Vec<i64>>,
    }

    impl PlatformNotifier for MockNotifier {
        fn show(&self, notif: &OsNotification) {
            self.shown.lock().unwrap().push(notif.clone());
        }
        fn show_summary(&self, unread_count: usize) {
            self.summaries.lock().unwrap().push(unread_count);
        }
        fn clear(&self, row_id: i64) {
            self.cleared.lock().unwrap().push(row_id);
        }
        fn clear_all(&self) {}
    }

    #[allow(clippy::too_many_arguments)]
    fn make_posted_frame(
        crypto: &CryptoEngine,
        seq: i64,
        sender_id: &str,
        sender_name: &str,
        uid: &str,
        title: &str,
        body: &str,
        posted_at: i64,
    ) -> ServerFrame {
        let event_id = format!("EVT{seq:023}");
        let payload = InnerPayload::Posted(Box::new(NotificationPosted {
            notification_uid: uid.to_string(),
            sender_device_name: sender_name.to_string(),
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
        }));
        let pt = serde_json::to_vec(&payload).unwrap();
        let ct = crypto.encrypt_event(&event_id, sender_id, &pt).unwrap();
        ServerFrame::Event {
            seq,
            event_id,
            sender_device_id: sender_id.to_string(),
            server_ts: posted_at,
            ciphertext: ct,
        }
    }

    fn make_dismiss_frame(
        crypto: &CryptoEngine,
        seq: i64,
        sender_id: &str,
        uids: Vec<&str>,
        dismissed_at: i64,
    ) -> ServerFrame {
        let event_id = format!("DIS{seq:023}");
        let payload = InnerPayload::Dismissed(NotificationDismissed {
            notification_uids: uids.into_iter().map(String::from).collect(),
            dismissed_at,
            dismissed_by_device_name: "Pixel 9".to_string(),
        });
        let pt = serde_json::to_vec(&payload).unwrap();
        let ct = crypto.encrypt_event(&event_id, sender_id, &pt).unwrap();
        ServerFrame::Event {
            seq,
            event_id,
            sender_device_id: sender_id.to_string(),
            server_ts: dismissed_at,
            ciphertext: ct,
        }
    }

    #[tokio::test]
    async fn replay_suppresses_already_dismissed_and_pops_only_still_active() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_in_memory().unwrap());
        let cache = Arc::new(BlobCache::new(dir.path(), 200).unwrap());
        let notifier = Arc::new(MockNotifier::default());
        let crypto = CryptoEngine::new(&[7u8; 32]).unwrap();

        let mut proc = SyncProcessor::new(
            Arc::clone(&db),
            cache,
            Arc::new(NoopBlobFetcher),
            notifier.clone(),
            Arc::new(NoopObserver),
            crypto.clone(),
            "dev_mac".to_string(),
        );
        proc.on_replay_start();

        // 10 posted, 7 dismissed during offline replay.
        for i in 1..=10 {
            let f = make_posted_frame(
                &crypto,
                i,
                "dev_phone",
                "Pixel 9",
                &format!("uid_{i}"),
                &format!("Msg {i}"),
                &format!("Body {i}"),
                1_700_000_000_000 + i * 10_000,
            );
            assert!(proc.handle_server_frame(f).await.is_none());
        }
        let d = make_dismiss_frame(
            &crypto,
            11,
            "dev_phone",
            vec!["uid_1", "uid_2", "uid_3", "uid_4", "uid_5", "uid_6", "uid_7"],
            1_700_000_200_000,
        );
        assert!(proc.handle_server_frame(d).await.is_none());

        // Nothing popped up before replay_complete.
        assert!(notifier.shown.lock().unwrap().is_empty());

        let ack = proc
            .handle_server_frame(ServerFrame::ReplayComplete { latest_seq: 11 })
            .await;
        assert_eq!(ack, Some(ClientFrame::Ack { seq: 11 }));
        assert_eq!(db.get_last_acked_seq().unwrap(), 11);

        // Only the 3 still-active notifications popped up; all 10 are in history.
        let shown = notifier.shown.lock().unwrap();
        assert_eq!(shown.len(), 3);
        assert_eq!(shown[0].title, "Msg 8");
        assert_eq!(shown[1].title, "Msg 9");
        assert_eq!(shown[2].title, "Msg 10");
        assert_eq!(db.list_notifications(None, 50).unwrap().len(), 10);
        assert_eq!(db.count_active().unwrap(), 3);
    }

    #[tokio::test]
    async fn replay_collapses_more_than_5_active_into_summary() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_in_memory().unwrap());
        let cache = Arc::new(BlobCache::new(dir.path(), 200).unwrap());
        let notifier = Arc::new(MockNotifier::default());
        let crypto = CryptoEngine::new(&[9u8; 32]).unwrap();

        let mut proc = SyncProcessor::new(
            Arc::clone(&db),
            cache,
            Arc::new(NoopBlobFetcher),
            notifier.clone(),
            Arc::new(NoopObserver),
            crypto.clone(),
            "dev_mac".to_string(),
        );
        proc.on_replay_start();

        for i in 1..=6 {
            let f = make_posted_frame(
                &crypto,
                i,
                "dev_phone",
                "Pixel 9",
                &format!("uid_{i}"),
                &format!("Title {i}"),
                "Body",
                1_700_000_000_000 + i * 10_000,
            );
            proc.handle_server_frame(f).await;
        }
        proc.handle_server_frame(ServerFrame::ReplayComplete { latest_seq: 6 })
            .await;

        assert!(notifier.shown.lock().unwrap().is_empty());
        assert_eq!(*notifier.summaries.lock().unwrap(), vec![6]);
    }

    #[tokio::test]
    async fn replay_suppresses_out_of_order_dismissed_before_posted() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_in_memory().unwrap());
        let cache = Arc::new(BlobCache::new(dir.path(), 200).unwrap());
        let notifier = Arc::new(MockNotifier::default());
        let crypto = CryptoEngine::new(&[13u8; 32]).unwrap();

        let mut proc = SyncProcessor::new(
            Arc::clone(&db),
            cache,
            Arc::new(NoopBlobFetcher),
            notifier.clone(),
            Arc::new(NoopObserver),
            crypto.clone(),
            "dev_mac".to_string(),
        );
        proc.on_replay_start();

        // Out-of-order: dismissal arrives before its matching posted event in the same replay batch.
        let dismiss_early = make_dismiss_frame(
            &crypto,
            1,
            "dev_phone",
            vec!["uid_early_dismiss"],
            1_700_000_050_000,
        );
        let posted_late = make_posted_frame(
            &crypto,
            2,
            "dev_phone",
            "Pixel 9",
            "uid_early_dismiss",
            "Already Dismissed",
            "Should stay silent",
            1_700_000_040_000,
        );
        let posted_active = make_posted_frame(
            &crypto,
            3,
            "dev_phone",
            "Pixel 9",
            "uid_still_active",
            "Still Active",
            "Should pop up",
            1_700_000_060_000,
        );

        assert!(proc.handle_server_frame(dismiss_early).await.is_none());
        assert!(proc.handle_server_frame(posted_late).await.is_none());
        assert!(proc.handle_server_frame(posted_active).await.is_none());
        assert!(notifier.shown.lock().unwrap().is_empty());

        let ack = proc
            .handle_server_frame(ServerFrame::ReplayComplete { latest_seq: 3 })
            .await;
        assert_eq!(ack, Some(ClientFrame::Ack { seq: 3 }));

        let shown = notifier.shown.lock().unwrap();
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].title, "Still Active");

        let all = db.list_notifications(None, 20).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(db.count_active().unwrap(), 1);
        let dismissed_row = all
            .iter()
            .find(|r| r.title == "Already Dismissed")
            .expect("dismissed notification archived in history");
        assert!(dismissed_row.dismissed_at.is_some());
        assert!(proc.replay_pending_dismissals.is_empty());
    }

    #[tokio::test]
    async fn replay_does_not_repop_already_existing_unacked_notification() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_in_memory().unwrap());
        let cache = Arc::new(BlobCache::new(dir.path(), 200).unwrap());
        let notifier = Arc::new(MockNotifier::default());
        let crypto = CryptoEngine::new(&[15u8; 32]).unwrap();

        let mut proc = SyncProcessor::new(
            Arc::clone(&db),
            cache,
            Arc::new(NoopBlobFetcher),
            notifier.clone(),
            Arc::new(NoopObserver),
            crypto.clone(),
            "dev_mac".to_string(),
        );

        // Complete initial empty replay to enter live mode.
        proc.handle_server_frame(ServerFrame::ReplayComplete { latest_seq: 0 })
            .await;

        // Live notification arrives and pops up once.
        let live_frame = make_posted_frame(
            &crypto,
            1,
            "dev_phone",
            "Pixel 9",
            "uid_live_unacked",
            "Live Message",
            "Shown before disconnect",
            1_700_000_000_000,
        );
        proc.handle_server_frame(live_frame.clone()).await;
        assert_eq!(notifier.shown.lock().unwrap().len(), 1);

        // Simulate disconnect where server never received ACK for seq 1, so reconnect replays seq 1 + new seq 2.
        proc.on_replay_start();
        assert!(proc.handle_server_frame(live_frame).await.is_none());

        let new_frame = make_posted_frame(
            &crypto,
            2,
            "dev_phone",
            "Pixel 9",
            "uid_new_offline",
            "Offline Message",
            "Arrived while disconnected",
            1_700_000_010_000,
        );
        assert!(proc.handle_server_frame(new_frame).await.is_none());

        let ack = proc
            .handle_server_frame(ServerFrame::ReplayComplete { latest_seq: 2 })
            .await;
        assert_eq!(ack, Some(ClientFrame::Ack { seq: 2 }));

        // Only the newly inserted offline notification pops up on replay; uid_live_unacked is NOT shown a second time.
        let shown = notifier.shown.lock().unwrap();
        assert_eq!(shown.len(), 2);
        assert_eq!(shown[0].title, "Live Message");
        assert_eq!(shown[1].title, "Offline Message");
        assert_eq!(db.count_active().unwrap(), 2);
    }

    #[derive(Default)]
    struct CountingBlobFetcher {
        icon_calls: std::sync::atomic::AtomicUsize,
        att_calls: std::sync::atomic::AtomicUsize,
    }

    impl BlobFetcher for CountingBlobFetcher {
        fn fetch_icon<'a>(
            &'a self,
            _sha256: &'a str,
            _blob_id: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<PathBuf>> + Send + 'a>>
        {
            self.icon_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { None })
        }

        fn fetch_attachment<'a>(
            &'a self,
            _blob_id: &'a str,
            _mime: &'a str,
            _sha256: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<PathBuf>> + Send + 'a>>
        {
            self.att_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { None })
        }
    }

    #[tokio::test]
    async fn replay_skips_blob_fetches_for_already_existing_uid_and_suppresses_merged_out_of_order_dismiss()
    {
        use std::sync::atomic::Ordering;

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_in_memory().unwrap());
        let cache = Arc::new(BlobCache::new(dir.path(), 200).unwrap());
        let fetcher = Arc::new(CountingBlobFetcher::default());
        let notifier = Arc::new(MockNotifier::default());
        let crypto = CryptoEngine::new(&[19u8; 32]).unwrap();

        let mut proc = SyncProcessor::new(
            Arc::clone(&db),
            cache,
            fetcher.clone(),
            notifier.clone(),
            Arc::new(NoopObserver),
            crypto.clone(),
            "dev_mac".to_string(),
        );
        proc.handle_server_frame(ServerFrame::ReplayComplete { latest_seq: 0 })
            .await;

        // Live event with icon + image attachment fetches blobs once.
        let icon_sha = "a".repeat(64);
        let img_sha = "b".repeat(64);
        let payload = InnerPayload::Posted(Box::new(NotificationPosted {
            notification_uid: "uid_with_blobs".to_string(),
            sender_device_name: "Pixel 9".to_string(),
            posted_at: 1_700_000_000_000,
            app: AppInfo {
                package: "com.whatsapp".to_string(),
                name: "WhatsApp".to_string(),
                icon_sha256: Some(icon_sha),
                icon_blob_id: Some("icon_aaaaaaaaaaaaaaaa".to_string()),
            },
            content: NotificationContent {
                title: "Photo".to_string(),
                body: "Check this".to_string(),
                sub_text: None,
                category: Some("msg".to_string()),
                group_key: None,
            },
            attachments: vec![AttachmentInfo {
                kind: "image".to_string(),
                blob_id: "img_01JTESTBLOB000002".to_string(),
                mime: "image/webp".to_string(),
                width: 400,
                height: 300,
                size_bytes: 1234,
                sha256: img_sha,
            }],
        }));
        let event_id = "EVT0000000000000000000001".to_string();
        let ct = crypto
            .encrypt_event(&event_id, "dev_phone_a", &serde_json::to_vec(&payload).unwrap())
            .unwrap();
        let blob_frame = ServerFrame::Event {
            seq: 1,
            event_id,
            sender_device_id: "dev_phone_a".to_string(),
            server_ts: 1_700_000_000_000,
            ciphertext: ct,
        };

        proc.handle_server_frame(blob_frame.clone()).await;
        assert_eq!(fetcher.icon_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fetcher.att_calls.load(Ordering::SeqCst), 1);
        assert_eq!(notifier.shown.lock().unwrap().len(), 1);

        // Reconnect replay: re-delivering uid_with_blobs must NOT fetch blobs again or re-pop.
        // Also test out-of-order dismissal arriving before a 5s dedup-merged pair from two phones.
        proc.on_replay_start();
        proc.handle_server_frame(blob_frame).await;
        assert_eq!(fetcher.icon_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fetcher.att_calls.load(Ordering::SeqCst), 1);

        let early_dismiss = make_dismiss_frame(
            &crypto,
            2,
            "dev_phone_b",
            vec!["uid_dedup_b"],
            1_700_000_025_000,
        );
        let dedup_a = make_posted_frame(
            &crypto,
            3,
            "dev_phone_a",
            "Pixel 9",
            "uid_dedup_a",
            "Same Title",
            "Same Body",
            1_700_000_020_000,
        );
        let dedup_b = make_posted_frame(
            &crypto,
            4,
            "dev_phone_b",
            "Galaxy S24",
            "uid_dedup_b",
            "Same Title",
            "Same Body",
            1_700_000_022_000,
        );
        proc.handle_server_frame(early_dismiss).await;
        proc.handle_server_frame(dedup_a).await;
        proc.handle_server_frame(dedup_b).await;

        proc.handle_server_frame(ServerFrame::ReplayComplete { latest_seq: 4 })
            .await;

        // No new popups: uid_with_blobs was already shown live, and merged dedup row was dismissed.
        assert_eq!(notifier.shown.lock().unwrap().len(), 1);
        let all = db.list_notifications(None, 20).unwrap();
        let merged = all
            .iter()
            .find(|r| r.title == "Same Title")
            .expect("merged row archived");
        assert_eq!(merged.notification_uids, vec!["uid_dedup_a", "uid_dedup_b"]);
        assert!(merged.dismissed_at.is_some());
    }

    #[tokio::test]
    async fn live_privacy_mode_mute_and_remote_dismiss() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_in_memory().unwrap());
        let cache = Arc::new(BlobCache::new(dir.path(), 200).unwrap());
        let notifier = Arc::new(MockNotifier::default());
        let crypto = CryptoEngine::new(&[5u8; 32]).unwrap();

        db.set_privacy_mode(true).unwrap();

        let mut proc = SyncProcessor::new(
            Arc::clone(&db),
            cache,
            Arc::new(NoopBlobFetcher),
            notifier.clone(),
            Arc::new(NoopObserver),
            crypto.clone(),
            "dev_mac".to_string(),
        );
        proc.handle_server_frame(ServerFrame::ReplayComplete { latest_seq: 0 })
            .await;

        // Live event with privacy mode redacts OS notification body, but stores real body in DB.
        let f1 = make_posted_frame(
            &crypto,
            1,
            "dev_phone",
            "Pixel 9",
            "uid_priv",
            "Bank OTP",
            "Code 123456",
            1_700_000_000_000,
        );
        let ack = proc.handle_server_frame(f1).await;
        assert_eq!(ack, Some(ClientFrame::Ack { seq: 1 }));
        {
            let shown = notifier.shown.lock().unwrap();
            assert_eq!(shown.len(), 1);
            assert_eq!(shown[0].body, "New notification");
        }
        assert_eq!(
            db.list_notifications(None, 10).unwrap()[0].body,
            "Code 123456"
        );

        // Mute suppresses new OS popups while still storing history.
        db.set_muted(true).unwrap();
        let f2 = make_posted_frame(
            &crypto,
            2,
            "dev_phone",
            "Pixel 9",
            "uid_muted",
            "Chat",
            "Muted body",
            1_700_000_020_000,
        );
        proc.handle_server_frame(f2).await;
        assert_eq!(notifier.shown.lock().unwrap().len(), 1);
        assert_eq!(db.count_active().unwrap(), 2);

        // Remote dismiss clears OS notification and marks row dismissed.
        let row_id = db.list_notifications(Some("Bank OTP"), 10).unwrap()[0].id;
        let d = make_dismiss_frame(&crypto, 3, "dev_phone", vec!["uid_priv"], 1_700_000_030_000);
        proc.handle_server_frame(d).await;
        assert_eq!(*notifier.cleared.lock().unwrap(), vec![row_id]);
        assert_eq!(db.count_active().unwrap(), 1);
    }

    #[tokio::test]
    async fn live_integration_with_real_go_relay_server() {
        use std::net::TcpListener;
        use std::path::Path;
        use std::process::Command;

        let server_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server");
        if !server_dir.join("go.mod").exists() {
            panic!("server/go.mod not found for Go interop test");
        }

        let work_dir = tempfile::tempdir().unwrap();
        let bin_path = work_dir
            .path()
            .join(format!("all-notify-server{}", std::env::consts::EXE_SUFFIX));
        let build_status = Command::new("go")
            .args(["build", "-o", bin_path.to_str().unwrap(), "./cmd/all-notify-server"])
            .current_dir(&server_dir)
            .status()
            .expect("invoke go build");
        assert!(build_status.success(), "go build failed");

        let data_dir = work_dir.path().join("server_data");
        std::fs::create_dir_all(&data_dir).unwrap();

        // Pick an ephemeral free localhost port.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let addr = format!("127.0.0.1:{port}");
        let http_base = format!("http://{addr}");
        let ws_base = format!("ws://{addr}/v1/ws");

        let k_master = [0x42u8; 32];
        let k_master_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(k_master);

        // Mint Android phone token and macOS desktop token using real server CLI.
        let mint = |name: &str, platform: &str| -> (String, String) {
            let out = Command::new(&bin_path)
                .args([
                    "token",
                    "create",
                    "--data-dir",
                    data_dir.to_str().unwrap(),
                    "--name",
                    name,
                    "--platform",
                    platform,
                ])
                .output()
                .expect("token create");
            assert!(out.status.success(), "token create failed: {:?}", out);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut dev_id = String::new();
            let mut token = String::new();
            for line in stdout.lines() {
                if let Some(v) = line.strip_prefix("Device ID:") {
                    dev_id = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("Token:") {
                    token = v.trim().to_string();
                }
            }
            assert!(!dev_id.is_empty() && !token.is_empty(), "parse CLI output:\n{stdout}");
            (dev_id, token)
        };

        let (phone_id, phone_token) = mint("Pixel 9", "android");
        let (mac_id, mac_token) = mint("MacBook Pro", "macos");

        let child = Command::new(&bin_path)
            .args([
                "serve",
                "--addr",
                &addr,
                "--data-dir",
                data_dir.to_str().unwrap(),
            ])
            .spawn()
            .expect("spawn server");

        struct KillOnDrop(std::process::Child);
        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let _guard = KillOnDrop(child);

        // Wait for /healthz.
        let http_client = reqwest::Client::new();
        let mut ready = false;
        for _ in 0..40 {
            if let Ok(r) = http_client.get(format!("{http_base}/healthz")).send().await {
                if r.status().is_success() {
                    ready = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ready, "Go relay server failed to become healthy");

        let crypto = CryptoEngine::new(&k_master).unwrap();

        // Phone uploads an encrypted icon + encrypted image attachment via real Blob API.
        let icon_plain = b"fake-webp-icon-bytes-64x64";
        let icon_sha = sha256_hex(icon_plain);
        let icon_blob_id = format!("icon_{}", &icon_sha[..16]);
        let icon_enc = crypto.encrypt_blob(&icon_blob_id, icon_plain).unwrap();
        let put_icon = http_client
            .put(format!("{http_base}/v1/blobs/{icon_blob_id}"))
            .header("Authorization", format!("Bearer {phone_token}"))
            .body(icon_enc)
            .send()
            .await
            .unwrap();
        assert!(put_icon.status().is_success());

        let img_plain = b"fake-jpeg-attachment-bytes";
        let img_sha = sha256_hex(img_plain);
        let img_blob_id = "img_01JTESTBLOB000001";
        let img_enc = crypto.encrypt_blob(img_blob_id, img_plain).unwrap();
        let put_img = http_client
            .put(format!("{http_base}/v1/blobs/{img_blob_id}"))
            .header("Authorization", format!("Bearer {phone_token}"))
            .body(img_enc)
            .send()
            .await
            .unwrap();
        assert!(put_img.status().is_success());

        // Start desktop SyncHandle against the real Go server.
        let db = Arc::new(Database::open_in_memory().unwrap());
        let cache = Arc::new(BlobCache::new(&work_dir.path().join("cache"), 200).unwrap());
        let notifier = Arc::new(MockNotifier::default());
        let desktop_cfg = PairingConfig {
            version: 1,
            server_url: http_base.clone(),
            ws_url: ws_base.clone(),
            token: mac_token,
            key_base64url: k_master_b64,
            key_bytes: k_master,
            device_id: mac_id.clone(),
            device_name: "MacBook Pro".to_string(),
            can_add_devices: false,
        };

        let handle = spawn_sync_loop(
            desktop_cfg,
            Arc::clone(&db),
            Arc::clone(&cache),
            notifier.clone(),
            Arc::new(NoopObserver),
        );

        // Connect simulated Phone WS client to Go server.
        let phone_req = build_ws_request(&ws_base, &phone_token).unwrap();
        let (mut phone_ws, _) = tokio_tungstenite::connect_async(phone_req).await.unwrap();
        // Drain Phone's initial replay_complete.
        let _ = tokio::time::timeout(Duration::from_secs(3), phone_ws.next()).await;

        // Give Desktop a moment to finish connecting.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Phone sends encrypted notification.posted with icon + image attachment.
        let notif_uid = format!("{phone_id}:1764060000123:a1b2c3");
        let posted = InnerPayload::Posted(Box::new(NotificationPosted {
            notification_uid: notif_uid.clone(),
            sender_device_name: "Pixel 9".to_string(),
            posted_at: 1_764_060_000_123,
            app: AppInfo {
                package: "com.whatsapp".to_string(),
                name: "WhatsApp".to_string(),
                icon_sha256: Some(icon_sha.clone()),
                icon_blob_id: Some(icon_blob_id.clone()),
            },
            content: NotificationContent {
                title: "Alice".to_string(),
                body: "Photo from dinner!".to_string(),
                sub_text: None,
                category: Some("msg".to_string()),
                group_key: None,
            },
            attachments: vec![AttachmentInfo {
                kind: "image".to_string(),
                blob_id: img_blob_id.to_string(),
                mime: "image/jpeg".to_string(),
                width: 640,
                height: 480,
                size_bytes: img_plain.len() as u64,
                sha256: img_sha.clone(),
            }],
        }));
        let event_id = generate_ulid();
        let ct = crypto
            .encrypt_event(&event_id, &phone_id, &serde_json::to_vec(&posted).unwrap())
            .unwrap();
        let relay_frame = ClientFrame::Relay {
            event_id,
            target: "broadcast".to_string(),
            ciphertext: ct,
        };
        phone_ws
            .send(Message::Text(serde_json::to_string(&relay_frame).unwrap().into()))
            .await
            .unwrap();

        // Wait until Desktop receives, decrypts, fetches icon + attachment, and pops OS notification.
        let mut received = false;
        for _ in 0..40 {
            if !notifier.shown.lock().unwrap().is_empty() {
                received = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(received, "Desktop did not receive notification from Go relay");

        {
            let shown = notifier.shown.lock().unwrap();
            assert_eq!(shown[0].title, "Alice");
            assert_eq!(shown[0].body, "Photo from dinner!");
            assert!(shown[0].icon_path.as_ref().is_some_and(|p| p.exists()));
            assert!(shown[0].attachment_path.as_ref().is_some_and(|p| p.exists()));
            assert_eq!(std::fs::read(shown[0].icon_path.as_ref().unwrap()).unwrap(), icon_plain);
            assert_eq!(std::fs::read(shown[0].attachment_path.as_ref().unwrap()).unwrap(), img_plain);
        }

        // Desktop dismisses the notification -> Phone receives encrypted notification.dismissed!
        handle.send_dismiss(vec![notif_uid.clone()]);

        let dismissed_msg = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(Ok(Message::Text(txt))) = phone_ws.next().await {
                if let Ok(ServerFrame::Event {
                    event_id,
                    sender_device_id,
                    ciphertext,
                    ..
                }) = serde_json::from_str::<ServerFrame>(&txt)
                {
                    let pt = crypto
                        .decrypt_event(&event_id, &sender_device_id, &ciphertext)
                        .unwrap();
                    return serde_json::from_slice::<InnerPayload>(&pt).unwrap();
                }
            }
            panic!("phone ws closed before dismissal received");
        })
        .await
        .expect("timed out waiting for desktop dismissal on phone");

        match dismissed_msg {
            InnerPayload::Dismissed(d) => {
                assert_eq!(d.notification_uids, vec![notif_uid]);
                assert_eq!(d.dismissed_by_device_name, "MacBook Pro");
            }
            other => panic!("expected Dismissed, got {other:?}"),
        }

        handle.stop();
    }

    #[derive(Default)]
    struct RecordingObserver {
        statuses: Mutex<Vec<ConnectionStatus>>,
        notif_updates: std::sync::atomic::AtomicUsize,
    }

    impl SyncObserver for RecordingObserver {
        fn on_status_changed(&self, status: ConnectionStatus) {
            self.statuses.lock().unwrap().push(status);
        }
        fn on_notifications_changed(&self) {
            self.notif_updates
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn replay_batches_observer_notifications_until_replay_complete() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_in_memory().unwrap());
        let cache = Arc::new(BlobCache::new(dir.path(), 50).unwrap());
        let notifier = Arc::new(MockNotifier::default());
        let observer = Arc::new(RecordingObserver::default());
        let crypto = CryptoEngine::new(&[11u8; 32]).unwrap();

        let mut proc = SyncProcessor::new(
            Arc::clone(&db),
            cache,
            Arc::new(NoopBlobFetcher),
            notifier,
            observer.clone(),
            crypto.clone(),
            "dev_mac".to_string(),
        );
        proc.on_replay_start();

        for i in 1..=5 {
            let f = make_posted_frame(
                &crypto,
                i,
                "dev_phone",
                "Pixel 9",
                &format!("u_{i}"),
                "Title",
                &format!("Body {i}"),
                1_700_000_000_000 + i * 10_000,
            );
            proc.handle_server_frame(f).await;
        }
        // Must not spam observer during replay.
        assert_eq!(
            observer
                .notif_updates
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        proc.handle_server_frame(ServerFrame::ReplayComplete { latest_seq: 5 })
            .await;
        assert_eq!(
            observer
                .notif_updates
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        // Live event emits immediately.
        let live = make_posted_frame(
            &crypto,
            6,
            "dev_phone",
            "Pixel 9",
            "u_6",
            "Live",
            "Now",
            1_700_000_100_000,
        );
        proc.handle_server_frame(live).await;
        assert_eq!(
            observer
                .notif_updates
                .load(std::sync::atomic::Ordering::SeqCst),
            2
        );
    }

    #[tokio::test]
    async fn send_dismiss_deduplicates_and_chunks_over_100_uids() {
        let db = Arc::new(Database::open_in_memory().unwrap());
        let crypto = CryptoEngine::new(&[3u8; 32]).unwrap();
        let (tx, _rx) = watch::channel(false);
        let handle = SyncHandle {
            shutdown_tx: tx,
            outbox_notify: Arc::new(Notify::new()),
            db: Arc::clone(&db),
            crypto: Some(crypto.clone()),
            device_id: "dev_mac".to_string(),
            device_name: "MacBook Pro".to_string(),
            task: SyncTask::Tokio(tokio::spawn(async {})),
        };

        let mut uids = vec![String::new(), "uid_0".to_string()];
        for i in 0..250 {
            uids.push(format!("uid_{i}"));
        }
        handle.send_dismiss(uids);

        let rows = db.list_outbox(now_unix_ms()).unwrap();
        assert_eq!(rows.len(), 3, "250 unique UIDs must chunk into 100 + 100 + 50");

        let mut total_uids = 0usize;
        for row in rows {
            let pt = crypto
                .decrypt_event(&row.event_id, "dev_mac", &row.ciphertext)
                .unwrap();
            let InnerPayload::Dismissed(d) = serde_json::from_slice(&pt).unwrap() else {
                panic!("expected Dismissed");
            };
            assert!(d.notification_uids.len() <= 100);
            total_uids += d.notification_uids.len();
        }
        assert_eq!(total_uids, 250);
        handle.stop();
    }

    #[tokio::test]
    async fn live_token_revocation_transitions_to_unauthorized_against_real_go_server() {
        use std::net::TcpListener;
        use std::path::Path;
        use std::process::Command;

        let server_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server");
        let work_dir = tempfile::tempdir().unwrap();
        let bin_path = work_dir
            .path()
            .join(format!("all-notify-server{}", std::env::consts::EXE_SUFFIX));
        let build_status = Command::new("go")
            .args(["build", "-o", bin_path.to_str().unwrap(), "./cmd/all-notify-server"])
            .current_dir(&server_dir)
            .status()
            .expect("invoke go build");
        assert!(build_status.success());

        let data_dir = work_dir.path().join("server_data");
        std::fs::create_dir_all(&data_dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let addr = format!("127.0.0.1:{port}");
        let http_base = format!("http://{addr}");
        let ws_base = format!("ws://{addr}/v1/ws");

        let out = Command::new(&bin_path)
            .args([
                "token",
                "create",
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--name",
                "MacBook Revoke Test",
                "--platform",
                "macos",
            ])
            .output()
            .expect("token create");
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut mac_id = String::new();
        let mut mac_token = String::new();
        for line in stdout.lines() {
            if let Some(v) = line.strip_prefix("Device ID:") {
                mac_id = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Token:") {
                mac_token = v.trim().to_string();
            }
        }
        assert!(!mac_id.is_empty() && !mac_token.is_empty());

        let child = Command::new(&bin_path)
            .args(["serve", "--addr", &addr, "--data-dir", data_dir.to_str().unwrap()])
            .spawn()
            .expect("spawn server");

        struct KillOnDrop(std::process::Child);
        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let _guard = KillOnDrop(child);

        let http_client = reqwest::Client::new();
        for _ in 0..40 {
            if let Ok(r) = http_client.get(format!("{http_base}/healthz")).send().await {
                if r.status().is_success() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let k_master = [0x55u8; 32];
        let cfg = PairingConfig {
            version: 1,
            server_url: http_base.clone(),
            ws_url: ws_base.clone(),
            token: mac_token,
            key_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(k_master),
            key_bytes: k_master,
            device_id: mac_id.clone(),
            device_name: "MacBook Revoke Test".to_string(),
            can_add_devices: false,
        };

        // 1. Connect live, wait for Connected, then revoke token via CLI while connected.
        let db1 = Arc::new(Database::open_in_memory().unwrap());
        let cache1 = Arc::new(BlobCache::new(&work_dir.path().join("c1"), 50).unwrap());
        let obs1 = Arc::new(RecordingObserver::default());
        let handle1 = spawn_sync_loop(
            cfg.clone(),
            db1,
            cache1,
            Arc::new(crate::notifier::NoopNotifier),
            obs1.clone(),
        );

        let mut connected = false;
        for _ in 0..40 {
            if obs1.statuses.lock().unwrap().contains(&ConnectionStatus::Connected) {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(connected, "Desktop failed to connect before revocation");

        let revoke_out = Command::new(&bin_path)
            .args([
                "token",
                "revoke",
                "--data-dir",
                data_dir.to_str().unwrap(),
                &mac_id,
            ])
            .output()
            .expect("token revoke");
        assert!(revoke_out.status.success(), "revoke failed: {:?}", revoke_out);

        let mut saw_unauth_live = false;
        for _ in 0..60 {
            if obs1
                .statuses
                .lock()
                .unwrap()
                .last()
                .copied()
                == Some(ConnectionStatus::Unauthorized)
            {
                saw_unauth_live = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            saw_unauth_live,
            "Live revoked session did not transition to Unauthorized; statuses={:?}",
            *obs1.statuses.lock().unwrap()
        );
        handle1.stop();

        // 2. Fresh connection with already-revoked token gets HTTP 401 -> immediate Unauthorized (no reconnect loop).
        let db2 = Arc::new(Database::open_in_memory().unwrap());
        let cache2 = Arc::new(BlobCache::new(&work_dir.path().join("c2"), 50).unwrap());
        let obs2 = Arc::new(RecordingObserver::default());
        let handle2 = spawn_sync_loop(
            cfg,
            db2,
            cache2,
            Arc::new(crate::notifier::NoopNotifier),
            obs2.clone(),
        );

        let mut saw_unauth_401 = false;
        for _ in 0..40 {
            if obs2
                .statuses
                .lock()
                .unwrap()
                .last()
                .copied()
                == Some(ConnectionStatus::Unauthorized)
            {
                saw_unauth_401 = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            saw_unauth_401,
            "Revoked reconnect did not immediately report Unauthorized; statuses={:?}",
            *obs2.statuses.lock().unwrap()
        );
        assert!(
            !obs2.statuses.lock().unwrap().contains(&ConnectionStatus::Reconnecting),
            "Revoked reconnect must not enter Reconnecting loop"
        );
        handle2.stop();
    }

    #[test]
    fn spawn_sync_loop_works_outside_tokio_context() {
        // Mirrors Tauri's `.setup()` hook which runs on the main OS thread with no active Tokio reactor.
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_in_memory().unwrap());
        let cache = Arc::new(BlobCache::new(dir.path(), 16).unwrap());
        let cfg = PairingConfig {
            version: 1,
            server_url: "http://127.0.0.1:1".to_string(),
            ws_url: "ws://127.0.0.1:1/v1/ws".to_string(),
            token: "tok_test".to_string(),
            key_base64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            key_bytes: [0u8; 32],
            device_id: "dev_test".to_string(),
            device_name: "Test Mac".to_string(),
            can_add_devices: false,
        };
        let handle = spawn_sync_loop(
            cfg,
            db,
            cache,
            Arc::new(crate::notifier::NoopNotifier),
            Arc::new(NoopObserver),
        );
        handle.stop();
    }
}
