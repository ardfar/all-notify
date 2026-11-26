//! Phase 4.1 End-to-End Verification Matrix against the real Go `all-notify-server` binary.
//!
//! Covers all 7 cross-device scenarios across a 4-device topology
//! (Phone A, Phone B, MacBook Pro desktop, Windows PC desktop):
//!   1. Basic Mirror (<1s) + zero-knowledge VPS DB/blob inspection
//!   2. Icon Cache hit (1st upload HEAD 404 -> PUT -> GET; 2nd skips PUT & GET)
//!   3. Image Attachment round-trip (<=512 KB WebP, opaque on disk) + >550 KB 413 rejection
//!   4. Dismissal Sync in all directions (Mac -> all, Win -> all, Phone A -> all with zero echo)
//!   5. 5-Second Deduplication (Phone A + Phone B -> 1 merged desktop row; dismiss clears both phones)
//!   6. Offline Replay anti-popup-storm (10 sent, 7 dismissed -> 3 pop up, 7 silent, ACK prunes DB;
//!      plus >5 active collapses into 1 summary notification)
//!   7. Token Revocation (live CLI `token revoke` -> Unauthorized + 401 on WS & Blob reconnect)

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::{SinkExt, StreamExt};
use rusqlite::Connection;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use all_notify_desktop_lib::crypto::{generate_ulid, parse_pairing_uri, CryptoEngine, PairingConfig};
use all_notify_desktop_lib::notifier::{OsNotification, PlatformNotifier};
use all_notify_desktop_lib::protocol::{
    sha256_hex, AppInfo, AttachmentInfo, ClientFrame, InnerPayload, NotificationContent,
    NotificationDismissed, NotificationPosted, ServerFrame,
};
use all_notify_desktop_lib::storage::{now_unix_ms, BlobCache, Database};
use all_notify_desktop_lib::sync::{
    spawn_sync_loop, ConnectionStatus, SyncHandle, SyncObserver,
};

type WsClient = WebSocketStream<MaybeTlsStream<TcpStream>>;

static SERVER_BIN: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();

fn server_binary() -> &'static Path {
    let (_, path) = SERVER_BIN.get_or_init(|| {
        let server_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server");
        assert!(
            server_dir.join("go.mod").exists(),
            "server/go.mod not found at {}",
            server_dir.display()
        );
        let dir = tempfile::tempdir().expect("tempdir for server binary");
        let bin = dir
            .path()
            .join(format!("all-notify-server{}", std::env::consts::EXE_SUFFIX));
        let status = Command::new("go")
            .args(["build", "-o", bin.to_str().unwrap(), "./cmd/all-notify-server"])
            .current_dir(&server_dir)
            .status()
            .expect("invoke go build");
        assert!(status.success(), "go build all-notify-server failed");
        (dir, bin)
    });
    path.as_path()
}

struct RunningServer {
    _work_dir: tempfile::TempDir,
    data_dir: PathBuf,
    http_base: String,
    ws_base: String,
    k_master: [u8; 32],
    k_master_b64: String,
    crypto: CryptoEngine,
    child: Child,
    http: reqwest::Client,
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl RunningServer {
    async fn start() -> Self {
        let bin = server_binary();
        let work_dir = tempfile::tempdir().expect("server workdir");
        let data_dir = work_dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        // Generate K_master using the real server CLI `keygen` command.
        let keygen_out = Command::new(bin)
            .arg("keygen")
            .output()
            .expect("run keygen");
        assert!(keygen_out.status.success(), "keygen failed");
        let k_master_b64 = String::from_utf8_lossy(&keygen_out.stdout).trim().to_string();
        let key_vec = URL_SAFE_NO_PAD
            .decode(&k_master_b64)
            .expect("decode keygen base64url");
        let k_master: [u8; 32] = key_vec.try_into().expect("32-byte K_master");
        let crypto = CryptoEngine::new(&k_master).expect("CryptoEngine");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let addr = format!("127.0.0.1:{port}");
        let http_base = format!("http://{addr}");
        let ws_base = format!("ws://{addr}/v1/ws");

        let child = Command::new(bin)
            .args(["serve", "--addr", &addr, "--data-dir", data_dir.to_str().unwrap()])
            .spawn()
            .expect("spawn all-notify-server");

        let http = reqwest::Client::new();
        let mut ready = false;
        for _ in 0..60 {
            if let Ok(resp) = http.get(format!("{http_base}/healthz")).send().await {
                if resp.status().is_success() {
                    ready = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ready, "all-notify-server failed to become healthy");

        Self {
            _work_dir: work_dir,
            data_dir,
            http_base,
            ws_base,
            k_master,
            k_master_b64,
            crypto,
            child,
            http,
        }
    }

    /// Mints a device via real CLI `token create`, parses its `allnotify://pair?...` URI via
    /// the real Rust pairing parser, and adapts URLs to local HTTP/WS for testing.
    fn mint_device(&self, name: &str, platform: &str) -> PairingConfig {
        let bin = server_binary();
        let out = Command::new(bin)
            .args([
                "token",
                "create",
                "--no-qr",
                "--data-dir",
                self.data_dir.to_str().unwrap(),
                "--name",
                name,
                "--platform",
                platform,
                "--url",
                "https://relay.example.test",
                "--key",
                &self.k_master_b64,
            ])
            .output()
            .expect("token create");
        assert!(
            out.status.success(),
            "token create failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let pair_uri = stdout
            .lines()
            .find_map(|l| l.strip_prefix("Pairing URI:"))
            .expect("Pairing URI line in CLI output")
            .trim();
        let mut cfg = parse_pairing_uri(pair_uri).expect("parse CLI pairing URI");
        assert_eq!(cfg.key_bytes, self.k_master);
        assert_eq!(cfg.device_name, name);
        cfg.server_url = self.http_base.clone();
        cfg.ws_url = self.ws_base.clone();
        cfg
    }

    fn revoke_device(&self, device_id: &str) {
        let bin = server_binary();
        let out = Command::new(bin)
            .args([
                "token",
                "revoke",
                "--data-dir",
                self.data_dir.to_str().unwrap(),
                device_id,
            ])
            .output()
            .expect("token revoke");
        assert!(
            out.status.success(),
            "token revoke failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir.join("all-notify.db")
    }

    fn blob_path(&self, blob_id: &str) -> PathBuf {
        self.data_dir.join("blobs").join(format!("{blob_id}.bin"))
    }
}

#[derive(Default)]
struct RecordingNotifier {
    shown: Mutex<Vec<OsNotification>>,
    summaries: Mutex<Vec<usize>>,
    cleared: Mutex<Vec<i64>>,
}

impl PlatformNotifier for RecordingNotifier {
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

#[derive(Default)]
struct RecordingObserver {
    statuses: Mutex<Vec<ConnectionStatus>>,
    updates: AtomicUsize,
}

impl SyncObserver for RecordingObserver {
    fn on_status_changed(&self, status: ConnectionStatus) {
        self.statuses.lock().unwrap().push(status);
    }
    fn on_notifications_changed(&self) {
        self.updates.fetch_add(1, Ordering::SeqCst);
    }
}

impl RecordingObserver {
    fn has_status(&self, target: ConnectionStatus) -> bool {
        self.statuses.lock().unwrap().contains(&target)
    }
}

struct DesktopNode {
    cfg: PairingConfig,
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    cache_dir: PathBuf,
    db: Arc<Database>,
    cache: Arc<BlobCache>,
    notifier: Arc<RecordingNotifier>,
    observer: Arc<RecordingObserver>,
    handle: Option<SyncHandle>,
}

impl DesktopNode {
    async fn start(cfg: PairingConfig) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("desktop.db");
        let cache_dir = dir.path().join("cache");
        let db = Arc::new(Database::open(&db_path).unwrap());
        let cache = Arc::new(BlobCache::new(&cache_dir, 200).unwrap());
        let notifier = Arc::new(RecordingNotifier::default());
        let observer = Arc::new(RecordingObserver::default());
        let handle = spawn_sync_loop(
            cfg.clone(),
            Arc::clone(&db),
            Arc::clone(&cache),
            notifier.clone(),
            observer.clone(),
        );
        let node = Self {
            cfg,
            _dir: dir,
            db_path,
            cache_dir,
            db,
            cache,
            notifier,
            observer,
            handle: Some(handle),
        };
        node.wait_connected().await;
        node
    }

    async fn wait_connected(&self) {
        wait_until(Duration::from_secs(5), || {
            self.observer.has_status(ConnectionStatus::Connected)
        })
        .await;
        // Let initial replay_complete finish before sending live events.
        tokio::time::sleep(Duration::from_millis(80)).await;
    }

    fn disconnect(&mut self) {
        if let Some(h) = self.handle.take() {
            h.stop();
        }
    }

    async fn reconnect(&mut self) {
        self.observer.statuses.lock().unwrap().clear();
        self.notifier.shown.lock().unwrap().clear();
        self.notifier.summaries.lock().unwrap().clear();
        let db = Arc::new(Database::open(&self.db_path).unwrap());
        let cache = Arc::new(BlobCache::new(&self.cache_dir, 200).unwrap());
        self.db = Arc::clone(&db);
        self.cache = Arc::clone(&cache);
        let handle = spawn_sync_loop(
            self.cfg.clone(),
            db,
            cache,
            self.notifier.clone(),
            self.observer.clone(),
        );
        self.handle = Some(handle);
        self.wait_connected().await;
    }

    fn send_dismiss(&self, uids: Vec<String>) {
        self.handle.as_ref().expect("desktop connected").send_dismiss(uids);
    }
}

impl Drop for DesktopNode {
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn build_ws_req(uri: &str, token: &str) -> http::Request<()> {
    let mut req = uri.into_client_request().unwrap();
    req.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    req.headers_mut().insert(
        http::header::HeaderName::from_static("x-allnotify-protocol"),
        http::HeaderValue::from_static("1"),
    );
    req
}

async fn connect_phone(cfg: &PairingConfig) -> WsClient {
    let (mut ws, _) = tokio_tungstenite::connect_async(build_ws_req(&cfg.ws_url, &cfg.token))
        .await
        .expect("phone WS connect");
    // Drain initial replay_complete frame.
    let frame = recv_server_frame(&mut ws, Duration::from_secs(3))
        .await
        .expect("initial replay_complete");
    assert!(matches!(frame, ServerFrame::ReplayComplete { .. }));
    ws
}

async fn send_inner(ws: &mut WsClient, cfg: &PairingConfig, crypto: &CryptoEngine, payload: &InnerPayload) {
    let event_id = generate_ulid();
    let pt = serde_json::to_vec(payload).unwrap();
    let ct = crypto.encrypt_event(&event_id, &cfg.device_id, &pt).unwrap();
    let frame = ClientFrame::Relay {
        event_id,
        target: "broadcast".to_string(),
        ciphertext: ct,
    };
    ws.send(Message::Text(serde_json::to_string(&frame).unwrap().into()))
        .await
        .unwrap();
}

async fn recv_server_frame(ws: &mut WsClient, timeout: Duration) -> Option<ServerFrame> {
    tokio::time::timeout(timeout, async {
        while let Some(msg) = ws.next().await {
            match msg {
                Ok(Message::Text(txt)) => {
                    if let Ok(frame) = serde_json::from_str::<ServerFrame>(&txt) {
                        return Some(frame);
                    }
                }
                Ok(Message::Ping(p)) => {
                    let _ = ws.send(Message::Pong(p)).await;
                }
                Ok(Message::Close(_)) | Err(_) => return None,
                _ => {}
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

async fn recv_decrypted_inner(
    ws: &mut WsClient,
    crypto: &CryptoEngine,
    timeout: Duration,
) -> Option<(String, InnerPayload)> {
    let frame = recv_server_frame(ws, timeout).await?;
    if let ServerFrame::Event {
        seq,
        event_id,
        sender_device_id,
        ciphertext,
        ..
    } = frame
    {
        let ack = ClientFrame::Ack { seq };
        let _ = ws
            .send(Message::Text(serde_json::to_string(&ack).unwrap().into()))
            .await;
        let pt = crypto
            .decrypt_event(&event_id, &sender_device_id, &ciphertext)
            .expect("decrypt received event");
        let inner = serde_json::from_slice::<InnerPayload>(&pt).expect("parse inner payload");
        return Some((sender_device_id, inner));
    }
    None
}

async fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(cond(), "condition not met within {timeout:?}");
}

#[allow(clippy::too_many_arguments)]
fn make_posted(
    cfg: &PairingConfig,
    uid: &str,
    package: &str,
    app_name: &str,
    title: &str,
    body: &str,
    posted_at: i64,
    icon: Option<(String, String)>,
    attachments: Vec<AttachmentInfo>,
) -> InnerPayload {
    let (icon_sha256, icon_blob_id) = match icon {
        Some((sha, id)) => (Some(sha), Some(id)),
        None => (None, None),
    };
    InnerPayload::Posted(Box::new(NotificationPosted {
        notification_uid: uid.to_string(),
        sender_device_name: cfg.device_name.clone(),
        posted_at,
        app: AppInfo {
            package: package.to_string(),
            name: app_name.to_string(),
            icon_sha256,
            icon_blob_id,
        },
        content: NotificationContent {
            title: title.to_string(),
            body: body.to_string(),
            sub_text: None,
            category: Some("msg".to_string()),
            group_key: None,
        },
        attachments,
    }))
}

#[tokio::test]
async fn e2e_01_basic_mirror_under_1s_and_zero_knowledge_vps() {
    let srv = RunningServer::start().await;
    let phone_a = srv.mint_device("Pixel 9", "android");
    let phone_b = srv.mint_device("Galaxy S24", "android");
    let mac_cfg = srv.mint_device("MacBook Pro", "macos");
    let win_cfg = srv.mint_device("Windows PC", "windows");
    // Offline device guarantees the encrypted event stays persisted in SQLite `offline_events` (including WAL) for inspection.
    let offline_cfg = srv.mint_device("Offline Backup Laptop", "macos");

    let mut ws_a = connect_phone(&phone_a).await;
    let mut ws_b = connect_phone(&phone_b).await;
    let mac = DesktopNode::start(mac_cfg).await;
    let win = DesktopNode::start(win_cfg).await;

    let secret_title = "E2E-SECRET-TITLE-99182";
    let secret_body = "Meet at secret cafe 42";
    let uid = format!("{}:{}:basic1", phone_a.device_id, now_unix_ms());
    let posted = make_posted(
        &phone_a,
        &uid,
        "com.whatsapp",
        "WhatsApp",
        secret_title,
        secret_body,
        now_unix_ms(),
        None,
        vec![],
    );

    let t0 = Instant::now();
    send_inner(&mut ws_a, &phone_a, &srv.crypto, &posted).await;

    // Phone B, MacBook Pro, and Windows PC all receive within <1s.
    let (sender_on_b, inner_b) = recv_decrypted_inner(&mut ws_b, &srv.crypto, Duration::from_secs(1))
        .await
        .expect("Phone B did not receive within 1s");
    assert_eq!(sender_on_b, phone_a.device_id);
    assert_eq!(inner_b, posted);

    wait_until(Duration::from_secs(1), || {
        !mac.notifier.shown.lock().unwrap().is_empty()
            && !win.notifier.shown.lock().unwrap().is_empty()
    })
    .await;
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "Basic mirror took {elapsed:?} (>= 1s)"
    );

    assert_eq!(mac.notifier.shown.lock().unwrap()[0].title, secret_title);
    assert_eq!(win.notifier.shown.lock().unwrap()[0].body, secret_body);

    // Zero-knowledge VPS invariant: confirm encrypted row actually exists in SQLite `offline_events`
    // and that neither the main DB file nor the SQLite WAL/SHM files contain plaintext.
    let conn = Connection::open(srv.db_path()).unwrap();
    let queued_ct: String = conn
        .query_row(
            "SELECT ciphertext FROM offline_events WHERE recipient_id = ?1 LIMIT 1",
            [&offline_cfg.device_id],
            |r| r.get(0),
        )
        .expect("offline_events row must exist for offline device");
    assert!(!queued_ct.is_empty());
    assert!(!queued_ct.contains(secret_title));
    assert!(!queued_ct.contains(secret_body));

    for suffix in ["", "-wal", "-shm"] {
        let mut p = srv.db_path().into_os_string();
        p.push(suffix);
        let path = PathBuf::from(p);
        if path.exists() {
            let raw = std::fs::read(&path).unwrap();
            let lossy = String::from_utf8_lossy(&raw);
            assert!(
                !lossy.contains(secret_title),
                "Plaintext title leaked in VPS DB file {}!",
                path.display()
            );
            assert!(
                !lossy.contains(secret_body),
                "Plaintext body leaked in VPS DB file {}!",
                path.display()
            );
        }
    }
}

#[tokio::test]
async fn e2e_02_icon_cache_hit_skips_second_put_and_get() {
    let srv = RunningServer::start().await;
    let phone_a = srv.mint_device("Pixel 9", "android");
    let mac = DesktopNode::start(srv.mint_device("MacBook Pro", "macos")).await;
    let win = DesktopNode::start(srv.mint_device("Windows PC", "windows")).await;
    let mut ws_a = connect_phone(&phone_a).await;

    // Generate a real 64x64 RGBA PNG-encoded-or-WebP icon payload.
    let img = image::RgbaImage::from_pixel(64, 64, image::Rgba([0x1e, 0x88, 0xe5, 0xff]));
    let mut icon_plain = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut icon_plain), image::ImageFormat::WebP)
        .expect("encode 64x64 WebP icon");
    let icon_sha = sha256_hex(&icon_plain);
    let icon_blob_id = format!("icon_{}", &icon_sha[..16]);

    // First notification: HEAD returns 404 -> PUT uploads encrypted icon -> desktops GET & cache.
    let head1 = srv
        .http
        .head(format!("{}/v1/blobs/{icon_blob_id}", srv.http_base))
        .header("Authorization", format!("Bearer {}", phone_a.token))
        .send()
        .await
        .unwrap();
    assert_eq!(head1.status(), reqwest::StatusCode::NOT_FOUND);

    let icon_enc = srv.crypto.encrypt_blob(&icon_blob_id, &icon_plain).unwrap();
    let put1 = srv
        .http
        .put(format!("{}/v1/blobs/{icon_blob_id}", srv.http_base))
        .header("Authorization", format!("Bearer {}", phone_a.token))
        .body(icon_enc)
        .send()
        .await
        .unwrap();
    assert_eq!(put1.status(), reqwest::StatusCode::CREATED);

    let now = now_unix_ms();
    let p1 = make_posted(
        &phone_a,
        &format!("{}:{now}:ic1", phone_a.device_id),
        "org.telegram.messenger",
        "Telegram",
        "First message",
        "Downloads icon once",
        now,
        Some((icon_sha.clone(), icon_blob_id.clone())),
        vec![],
    );
    send_inner(&mut ws_a, &phone_a, &srv.crypto, &p1).await;

    wait_until(Duration::from_secs(3), || {
        mac.notifier.shown.lock().unwrap().len() == 1
            && win.notifier.shown.lock().unwrap().len() == 1
    })
    .await;
    assert_eq!(
        std::fs::read(mac.notifier.shown.lock().unwrap()[0].icon_path.as_ref().unwrap()).unwrap(),
        icon_plain
    );
    assert_eq!(
        std::fs::read(win.notifier.shown.lock().unwrap()[0].icon_path.as_ref().unwrap()).unwrap(),
        icon_plain
    );

    // Second notification: HEAD returns 200 (sender skips PUT).
    let head2 = srv
        .http
        .head(format!("{}/v1/blobs/{icon_blob_id}", srv.http_base))
        .header("Authorization", format!("Bearer {}", phone_a.token))
        .send()
        .await
        .unwrap();
    assert_eq!(head2.status(), reqwest::StatusCode::OK);

    // Delete the server's blob file so any desktop GET would fail; desktops MUST resolve from local BlobCache!
    std::fs::remove_file(srv.blob_path(&icon_blob_id)).expect("remove server blob file");

    let p2 = make_posted(
        &phone_a,
        &format!("{}:{}:ic2", phone_a.device_id, now + 10_000),
        "org.telegram.messenger",
        "Telegram",
        "Second message",
        "Hits icon cache with zero GET",
        now + 10_000,
        Some((icon_sha.clone(), icon_blob_id.clone())),
        vec![],
    );
    send_inner(&mut ws_a, &phone_a, &srv.crypto, &p2).await;

    wait_until(Duration::from_secs(3), || {
        mac.notifier.shown.lock().unwrap().len() == 2
            && win.notifier.shown.lock().unwrap().len() == 2
    })
    .await;

    assert_eq!(
        std::fs::read(mac.notifier.shown.lock().unwrap()[1].icon_path.as_ref().unwrap()).unwrap(),
        icon_plain
    );
    assert_eq!(
        std::fs::read(win.notifier.shown.lock().unwrap()[1].icon_path.as_ref().unwrap()).unwrap(),
        icon_plain
    );
}

#[tokio::test]
async fn e2e_03_image_attachment_round_trip_and_oversize_rejection() {
    let srv = RunningServer::start().await;
    let phone_a = srv.mint_device("Pixel 9", "android");
    let phone_b = srv.mint_device("Galaxy S24", "android");
    let mac = DesktopNode::start(srv.mint_device("MacBook Pro", "macos")).await;
    let win = DesktopNode::start(srv.mint_device("Windows PC", "windows")).await;
    let mut ws_a = connect_phone(&phone_a).await;
    let mut ws_b = connect_phone(&phone_b).await;

    // 1. Oversize blob (> 550 KB) MUST be rejected by server with 413 Payload Too Large.
    let oversize = vec![0xABu8; 563_201];
    let bad_put = srv
        .http
        .put(format!("{}/v1/blobs/img_OVERSIZE000001", srv.http_base))
        .header("Authorization", format!("Bearer {}", phone_a.token))
        .body(oversize)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_put.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);

    // 2. Real 800x600 WebP photo attachment (<= 512 KB) encrypted and uploaded.
    let photo = image::RgbaImage::from_fn(800, 600, |x, y| {
        image::Rgba([(x % 255) as u8, (y % 255) as u8, 0x80, 0xff])
    });
    let mut img_plain = Vec::new();
    photo
        .write_to(&mut std::io::Cursor::new(&mut img_plain), image::ImageFormat::WebP)
        .expect("encode 800x600 WebP");
    assert!(img_plain.len() <= 512 * 1024);

    let img_sha = sha256_hex(&img_plain);
    let img_blob_id = format!("img_{}", generate_ulid());
    let img_enc = srv.crypto.encrypt_blob(&img_blob_id, &img_plain).unwrap();
    let put = srv
        .http
        .put(format!("{}/v1/blobs/{img_blob_id}", srv.http_base))
        .header("Authorization", format!("Bearer {}", phone_a.token))
        .body(img_enc)
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), reqwest::StatusCode::CREATED);

    // Verify blob on VPS disk is opaque ciphertext (does not contain RIFF/WEBP plaintext header).
    let on_disk = std::fs::read(srv.blob_path(&img_blob_id)).unwrap();
    assert!(!on_disk.windows(4).any(|w| w == b"WEBP"));

    let now = now_unix_ms();
    let posted = make_posted(
        &phone_a,
        &format!("{}:{now}:photo1", phone_a.device_id),
        "com.whatsapp",
        "WhatsApp",
        "Alice",
        "Check out this photo!",
        now,
        None,
        vec![AttachmentInfo {
            kind: "image".to_string(),
            blob_id: img_blob_id.clone(),
            mime: "image/webp".to_string(),
            width: 800,
            height: 600,
            size_bytes: img_plain.len() as u64,
            sha256: img_sha.clone(),
        }],
    );
    send_inner(&mut ws_a, &phone_a, &srv.crypto, &posted).await;

    // Phone B receives event and downloads/decrypts the attachment blob.
    let (_, inner_b) = recv_decrypted_inner(&mut ws_b, &srv.crypto, Duration::from_secs(3))
        .await
        .expect("Phone B received photo event");
    assert_eq!(inner_b, posted);
    let dl_b = srv
        .http
        .get(format!("{}/v1/blobs/{img_blob_id}", srv.http_base))
        .header("Authorization", format!("Bearer {}", phone_b.token))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(srv.crypto.decrypt_blob(&img_blob_id, &dl_b).unwrap(), img_plain);

    // Both MacBook Pro and Windows PC automatically download, decrypt, verify SHA-256, and attach.
    wait_until(Duration::from_secs(3), || {
        !mac.notifier.shown.lock().unwrap().is_empty()
            && !win.notifier.shown.lock().unwrap().is_empty()
    })
    .await;

    let mac_att = mac.notifier.shown.lock().unwrap()[0].attachment_path.clone().unwrap();
    let win_att = win.notifier.shown.lock().unwrap()[0].attachment_path.clone().unwrap();
    assert_eq!(std::fs::read(mac_att).unwrap(), img_plain);
    assert_eq!(std::fs::read(win_att).unwrap(), img_plain);
}

#[tokio::test]
async fn e2e_04_dismissal_sync_all_directions_and_no_echo() {
    let srv = RunningServer::start().await;
    let phone_a = srv.mint_device("Pixel 9", "android");
    let phone_b = srv.mint_device("Galaxy S24", "android");
    let mac = DesktopNode::start(srv.mint_device("MacBook Pro", "macos")).await;
    let win = DesktopNode::start(srv.mint_device("Windows PC", "windows")).await;
    let mut ws_a = connect_phone(&phone_a).await;
    let mut ws_b = connect_phone(&phone_b).await;

    let now = now_unix_ms();

    // --- Direction 1: Dismiss on macOS -> clears Phone A, Phone B, and Windows ---
    let uid1 = format!("{}:{now}:d1", phone_a.device_id);
    send_inner(
        &mut ws_a,
        &phone_a,
        &srv.crypto,
        &make_posted(&phone_a, &uid1, "com.chat", "Chat", "Msg 1", "From Mac dismiss", now, None, vec![]),
    )
    .await;
    let _ = recv_decrypted_inner(&mut ws_b, &srv.crypto, Duration::from_secs(2)).await.unwrap();
    wait_until(Duration::from_secs(2), || {
        mac.notifier.shown.lock().unwrap().len() == 1
            && win.notifier.shown.lock().unwrap().len() == 1
    })
    .await;
    let win_row1 = win.notifier.shown.lock().unwrap()[0].row_id;

    mac.send_dismiss(vec![uid1.clone()]);

    let (_, d_a) = recv_decrypted_inner(&mut ws_a, &srv.crypto, Duration::from_secs(2)).await.unwrap();
    let (_, d_b) = recv_decrypted_inner(&mut ws_b, &srv.crypto, Duration::from_secs(2)).await.unwrap();
    assert!(matches!(d_a, InnerPayload::Dismissed(ref d) if d.notification_uids == vec![uid1.clone()]));
    assert!(matches!(d_b, InnerPayload::Dismissed(ref d) if d.notification_uids == vec![uid1.clone()]));
    wait_until(Duration::from_secs(2), || {
        win.notifier.cleared.lock().unwrap().contains(&win_row1)
    })
    .await;
    assert_eq!(win.db.count_active().unwrap(), 0);

    // --- Direction 2: Dismiss on Windows -> clears Phone A, Phone B, and macOS ---
    let uid2 = format!("{}:{}:d2", phone_a.device_id, now + 10_000);
    send_inner(
        &mut ws_a,
        &phone_a,
        &srv.crypto,
        &make_posted(&phone_a, &uid2, "com.chat", "Chat", "Msg 2", "From Win dismiss", now + 10_000, None, vec![]),
    )
    .await;
    let _ = recv_decrypted_inner(&mut ws_b, &srv.crypto, Duration::from_secs(2)).await.unwrap();
    wait_until(Duration::from_secs(2), || {
        mac.notifier.shown.lock().unwrap().len() == 2
            && win.notifier.shown.lock().unwrap().len() == 2
    })
    .await;
    let mac_row2 = mac.notifier.shown.lock().unwrap()[1].row_id;

    win.send_dismiss(vec![uid2.clone()]);

    let (_, d_a2) = recv_decrypted_inner(&mut ws_a, &srv.crypto, Duration::from_secs(2)).await.unwrap();
    let (_, d_b2) = recv_decrypted_inner(&mut ws_b, &srv.crypto, Duration::from_secs(2)).await.unwrap();
    assert!(matches!(d_a2, InnerPayload::Dismissed(ref d) if d.notification_uids == vec![uid2.clone()]));
    assert!(matches!(d_b2, InnerPayload::Dismissed(ref d) if d.notification_uids == vec![uid2.clone()]));
    wait_until(Duration::from_secs(2), || {
        mac.notifier.cleared.lock().unwrap().contains(&mac_row2)
    })
    .await;

    // --- Direction 3: Dismiss on Phone A -> clears Phone B, macOS, Windows with ZERO echo to Phone A ---
    let uid3 = format!("{}:{}:d3", phone_a.device_id, now + 20_000);
    send_inner(
        &mut ws_a,
        &phone_a,
        &srv.crypto,
        &make_posted(&phone_a, &uid3, "com.chat", "Chat", "Msg 3", "From Phone A dismiss", now + 20_000, None, vec![]),
    )
    .await;
    let _ = recv_decrypted_inner(&mut ws_b, &srv.crypto, Duration::from_secs(2)).await.unwrap();
    wait_until(Duration::from_secs(2), || {
        mac.notifier.shown.lock().unwrap().len() == 3
            && win.notifier.shown.lock().unwrap().len() == 3
    })
    .await;
    let mac_row3 = mac.notifier.shown.lock().unwrap()[2].row_id;
    let win_row3 = win.notifier.shown.lock().unwrap()[2].row_id;

    let dismiss_a = InnerPayload::Dismissed(NotificationDismissed {
        notification_uids: vec![uid3.clone()],
        dismissed_at: now + 21_000,
        dismissed_by_device_name: phone_a.device_name.clone(),
    });
    send_inner(&mut ws_a, &phone_a, &srv.crypto, &dismiss_a).await;

    let (_, d_b3) = recv_decrypted_inner(&mut ws_b, &srv.crypto, Duration::from_secs(2)).await.unwrap();
    assert!(matches!(d_b3, InnerPayload::Dismissed(ref d) if d.notification_uids == vec![uid3.clone()]));
    wait_until(Duration::from_secs(2), || {
        mac.notifier.cleared.lock().unwrap().contains(&mac_row3)
            && win.notifier.cleared.lock().unwrap().contains(&win_row3)
    })
    .await;

    // Confirm Phone A receives NO echo of its own dismissal.
    let echo = recv_server_frame(&mut ws_a, Duration::from_millis(250)).await;
    assert!(echo.is_none(), "Unexpected echo sent back to Phone A: {echo:?}");
}

#[tokio::test]
async fn e2e_05_five_second_dedup_merges_and_clears_both_phones() {
    let srv = RunningServer::start().await;
    let phone_a = srv.mint_device("Pixel 9", "android");
    let phone_b = srv.mint_device("Galaxy S24", "android");
    let mac = DesktopNode::start(srv.mint_device("MacBook Pro", "macos")).await;
    let win = DesktopNode::start(srv.mint_device("Windows PC", "windows")).await;
    let mut ws_a = connect_phone(&phone_a).await;
    let mut ws_b = connect_phone(&phone_b).await;

    let now = now_unix_ms();
    let uid_a = format!("{}:{now}:dup_a", phone_a.device_id);
    let uid_b = format!("{}:{}:dup_b", phone_b.device_id, now + 1_500);

    send_inner(
        &mut ws_a,
        &phone_a,
        &srv.crypto,
        &make_posted(&phone_a, &uid_a, "com.whatsapp", "WhatsApp", "Group Chat", "Dinner at 7?", now, None, vec![]),
    )
    .await;
    // Drain Phone B receiving Phone A's message.
    let _ = recv_decrypted_inner(&mut ws_b, &srv.crypto, Duration::from_secs(2)).await.unwrap();
    wait_until(Duration::from_secs(2), || {
        mac.db.count_active().unwrap() == 1 && win.db.count_active().unwrap() == 1
    })
    .await;

    // Same notification arrives on Phone B 1.5s later (within 5s window).
    send_inner(
        &mut ws_b,
        &phone_b,
        &srv.crypto,
        &make_posted(&phone_b, &uid_b, "com.whatsapp", "WhatsApp", "Group Chat", "Dinner at 7?", now + 1_500, None, vec![]),
    )
    .await;
    // Drain Phone A receiving Phone B's message.
    let _ = recv_decrypted_inner(&mut ws_a, &srv.crypto, Duration::from_secs(2)).await.unwrap();

    wait_until(Duration::from_secs(2), || {
        let mac_rows = mac.db.list_notifications(None, 10).unwrap();
        let win_rows = win.db.list_notifications(None, 10).unwrap();
        mac_rows.len() == 1
            && mac_rows[0].notification_uids.len() == 2
            && win_rows.len() == 1
            && win_rows[0].notification_uids.len() == 2
    })
    .await;

    let mac_row = mac.db.list_notifications(None, 10).unwrap().remove(0);
    assert_eq!(mac_row.sender_devices, vec!["Pixel 9", "Galaxy S24"]);
    assert_eq!(mac_row.notification_uids, vec![uid_a.clone(), uid_b.clone()]);
    // First delivery popped loudly; merged update was silent (no double banner popup!).
    {
        let shown = mac.notifier.shown.lock().unwrap();
        assert_eq!(shown.len(), 2);
        assert!(!shown[0].silent_update);
        assert!(shown[1].silent_update);
        assert_eq!(shown[1].row_id, shown[0].row_id);
    }

    // Dismiss merged entry on MacBook Pro -> BOTH Phone A and Phone B receive both UIDs!
    mac.send_dismiss(mac_row.notification_uids.clone());

    let (_, d_a) = recv_decrypted_inner(&mut ws_a, &srv.crypto, Duration::from_secs(2)).await.unwrap();
    let (_, d_b) = recv_decrypted_inner(&mut ws_b, &srv.crypto, Duration::from_secs(2)).await.unwrap();
    for msg in [d_a, d_b] {
        match msg {
            InnerPayload::Dismissed(d) => {
                assert_eq!(d.notification_uids, vec![uid_a.clone(), uid_b.clone()]);
            }
            other => panic!("expected Dismissed, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn e2e_06_offline_replay_anti_popup_storm_and_ack_pruning() {
    let srv = RunningServer::start().await;
    let phone_a = srv.mint_device("Pixel 9", "android");
    let mut mac = DesktopNode::start(srv.mint_device("MacBook Pro", "macos")).await;
    let mut ws_a = connect_phone(&phone_a).await;

    // 1. Put MacBook Pro to sleep (disconnect WS).
    mac.disconnect();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. While MacBook Pro is offline, Phone A posts 10 notifications and dismisses 7 of them.
    let base_ts = now_unix_ms();
    let mut uids = Vec::new();
    for i in 1..=10 {
        let uid = format!("{}:{}:off_{i}", phone_a.device_id, base_ts + i * 10_000);
        uids.push(uid.clone());
        send_inner(
            &mut ws_a,
            &phone_a,
            &srv.crypto,
            &make_posted(
                &phone_a,
                &uid,
                "com.mail",
                "Mail",
                &format!("Msg {i}"),
                &format!("Body {i}"),
                base_ts + i * 10_000,
                None,
                vec![],
            ),
        )
        .await;
    }
    send_inner(
        &mut ws_a,
        &phone_a,
        &srv.crypto,
        &InnerPayload::Dismissed(NotificationDismissed {
            notification_uids: uids[0..7].to_vec(),
            dismissed_at: base_ts + 200_000,
            dismissed_by_device_name: phone_a.device_name.clone(),
        }),
    )
    .await;

    // Confirm server queued 11 offline_events for MacBook Pro.
    wait_until(Duration::from_secs(2), || {
        let conn = Connection::open(srv.db_path()).unwrap();
        let cnt: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM offline_events WHERE recipient_id = ?1",
                [&mac.cfg.device_id],
                |r| r.get(0),
            )
            .unwrap();
        cnt == 11
    })
    .await;

    // 3. Wake MacBook Pro: 7 archived silently, ONLY 3 still-active pop up, and ACK prunes server DB!
    mac.reconnect().await;
    wait_until(Duration::from_secs(3), || {
        mac.notifier.shown.lock().unwrap().len() == 3
            && mac.db.list_notifications(None, 50).unwrap().len() == 10
    })
    .await;

    {
        let shown = mac.notifier.shown.lock().unwrap();
        let titles: Vec<&str> = shown.iter().map(|n| n.title.as_str()).collect();
        assert_eq!(titles, vec!["Msg 8", "Msg 9", "Msg 10"]);
    }
    assert_eq!(mac.db.count_active().unwrap(), 3);
    assert!(mac.notifier.summaries.lock().unwrap().is_empty());

    // Confirm server pruned offline_events for MacBook Pro to 0 after bulk ACK.
    wait_until(Duration::from_secs(2), || {
        let conn = Connection::open(srv.db_path()).unwrap();
        let cnt: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM offline_events WHERE recipient_id = ?1",
                [&mac.cfg.device_id],
                |r| r.get(0),
            )
            .unwrap();
        cnt == 0
    })
    .await;

    // 4. Anti-popup-storm >5 active threshold: sleep again, send 7 active -> wakes with 1 summary!
    mac.disconnect();
    tokio::time::sleep(Duration::from_millis(100)).await;
    for i in 11..=17 {
        let uid = format!("{}:{}:storm_{i}", phone_a.device_id, base_ts + i * 10_000);
        send_inner(
            &mut ws_a,
            &phone_a,
            &srv.crypto,
            &make_posted(
                &phone_a,
                &uid,
                "com.chat",
                "Chat",
                &format!("Storm {i}"),
                &format!("Burst {i}"),
                base_ts + i * 10_000,
                None,
                vec![],
            ),
        )
        .await;
    }
    // Wait for server SQLite to commit all 7 offline events before waking MacBook Pro.
    wait_until(Duration::from_secs(2), || {
        let conn = Connection::open(srv.db_path()).unwrap();
        let cnt: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM offline_events WHERE recipient_id = ?1",
                [&mac.cfg.device_id],
                |r| r.get(0),
            )
            .unwrap();
        cnt == 7
    })
    .await;
    mac.reconnect().await;
    wait_until(Duration::from_secs(3), || {
        !mac.notifier.summaries.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(*mac.notifier.summaries.lock().unwrap(), vec![7]);
    assert!(mac.notifier.shown.lock().unwrap().is_empty());
}

#[tokio::test]
async fn e2e_07_revocation_disconnects_immediately_and_blocks_reconnect() {
    let srv = RunningServer::start().await;
    let mac = DesktopNode::start(srv.mint_device("MacBook Pro", "macos")).await;

    // Revoke MacBook Pro via real CLI while live WS is connected.
    srv.revoke_device(&mac.cfg.device_id);

    wait_until(Duration::from_secs(4), || {
        mac.observer.has_status(ConnectionStatus::Unauthorized)
    })
    .await;

    // Reconnecting WS with the revoked token MUST be rejected with HTTP 401.
    let ws_err = tokio_tungstenite::connect_async(build_ws_req(&mac.cfg.ws_url, &mac.cfg.token))
        .await
        .expect_err("revoked WS connect must fail");
    match ws_err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        }
        other => panic!("expected HTTP 401 on revoked WS connect, got {other:?}"),
    }

    // Calling Blob API with the revoked token MUST also return HTTP 401.
    let blob_resp = srv
        .http
        .head(format!("{}/v1/blobs/icon_0123456789abcdef", srv.http_base))
        .header("Authorization", format!("Bearer {}", mac.cfg.token))
        .send()
        .await
        .unwrap();
    assert_eq!(blob_resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
