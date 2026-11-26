pub mod crypto;
pub mod notifier;
pub mod pairing;
pub mod protocol;
pub mod storage;
pub mod sync;
pub mod tray;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tokio::sync::mpsc;

use crate::crypto::{
    build_pairing_uri_v2, compute_kcv, decode_qr_from_image_bytes, parse_pairing_link,
    render_qr_svg, CredentialManager, KeyringSecretStore, PairingConfig, PairingLink,
};
use crate::notifier::{
    create_platform_notifier, DismissAction, NotificationPermission, PlatformNotifier,
};
use crate::pairing::{
    build_http_client, claim_pairing_code, create_pairing_code, current_desktop_platform,
    fetch_device_me, list_pairing_codes, PairingCodeSummary,
};
use crate::protocol::{is_valid_sha256_hex, mime_for_extension};
use crate::storage::{
    now_unix_ms, prune_stale_dir_files, BlobCache, Database, NotificationRecord, RetentionSettings,
    DEFAULT_MAX_ICONS,
};
use crate::sync::{spawn_sync_loop, ConnectionStatus, SyncHandle, SyncObserver};

const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const STALE_STAGING_AGE: Duration = Duration::from_secs(60 * 60);
const BLUR_TOGGLE_DEBOUNCE: Duration = Duration::from_millis(250);

struct AppState {
    db: Arc<Database>,
    blob_cache: Arc<BlobCache>,
    cache_dir: PathBuf,
    credentials: CredentialManager,
    notifier: Arc<dyn PlatformNotifier>,
    pairing: Mutex<Option<PairingConfig>>,
    status: Mutex<ConnectionStatus>,
    sync_handle: Mutex<Option<SyncHandle>>,
    sync_generation: AtomicU64,
    file_dialog_open: AtomicBool,
    qr_content_protected: AtomicBool,
    last_blur_hide: Mutex<Option<Instant>>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicAppState {
    paired: bool,
    server_url: Option<String>,
    device_id: Option<String>,
    device_name: Option<String>,
    can_add_devices: bool,
    status: ConnectionStatus,
    muted: bool,
    privacy_mode: bool,
    autostart: bool,
    unread_count: usize,
    retention: RetentionSettings,
    notification_permission: NotificationPermission,
}

#[derive(Debug, Clone, Serialize)]
struct AddDeviceQrResult {
    code_id: String,
    name: String,
    platform: String,
    expires_at: i64,
    pairing_uri: String,
    qr_svg: String,
}

struct TauriSyncObserver {
    app: AppHandle,
    generation: u64,
}

impl SyncObserver for TauriSyncObserver {
    fn on_status_changed(&self, status: ConnectionStatus) {
        if let Some(state) = self.app.try_state::<Arc<AppState>>() {
            if state.sync_generation.load(Ordering::SeqCst) != self.generation {
                return;
            }
            *state.status.lock().expect("status mutex") = status;
            refresh_tray_and_emit(&self.app, &state);
            if status == ConnectionStatus::Connected {
                let app = self.app.clone();
                let state_arc = Arc::clone(&state);
                let generation = self.generation;
                tauri::async_runtime::spawn(async move {
                    refresh_device_me(&app, &state_arc, generation).await;
                });
            }
        }
    }

    fn on_notifications_changed(&self) {
        if let Some(state) = self.app.try_state::<Arc<AppState>>() {
            if state.sync_generation.load(Ordering::SeqCst) != self.generation {
                return;
            }
            refresh_tray_and_emit(&self.app, &state);
            let _ = self.app.emit("notifications:updated", ());
        }
    }
}

fn refresh_tray_and_emit(app: &AppHandle, state: &AppState) {
    let status = *state.status.lock().expect("status mutex");
    let unread = state.db.count_active().unwrap_or(0);
    let muted = state.db.is_muted().unwrap_or(false);
    tray::update_tray(app, status, unread, muted);
    let _ = app.emit("sync:status", status);
}

async fn refresh_device_me(app: &AppHandle, state: &Arc<AppState>, generation: u64) {
    let Some(cfg) = state.pairing.lock().expect("pairing mutex").clone() else {
        return;
    };
    let Ok(client) = build_http_client() else {
        return;
    };
    let Ok(me) = fetch_device_me(&client, &cfg.server_url, &cfg.token).await else {
        return;
    };
    if state.sync_generation.load(Ordering::SeqCst) != generation {
        return;
    }
    let updated = {
        let mut guard = state.pairing.lock().expect("pairing mutex");
        if let Some(cur) = guard.as_mut() {
            if cur.device_id == me.device_id
                && (cur.can_add_devices != me.can_add_devices || cur.device_name != me.name)
            {
                cur.can_add_devices = me.can_add_devices;
                cur.device_name = me.name;
                Some(cur.clone())
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some(new_cfg) = updated {
        let _ = state.credentials.save(&new_cfg);
        let _ = app.emit("state:updated", ());
    }
}

fn start_sync(app: &AppHandle, state: &Arc<AppState>, cfg: PairingConfig) {
    let mut guard = state.sync_handle.lock().expect("sync_handle mutex");
    let generation = state.sync_generation.fetch_add(1, Ordering::SeqCst) + 1;
    if let Some(existing) = guard.take() {
        existing.stop();
    }
    let observer: Arc<dyn SyncObserver> = Arc::new(TauriSyncObserver {
        app: app.clone(),
        generation,
    });
    let handle = spawn_sync_loop(
        cfg,
        Arc::clone(&state.db),
        Arc::clone(&state.blob_cache),
        Arc::clone(&state.notifier),
        observer,
    );
    *guard = Some(handle);
}

fn stop_sync(state: &AppState) {
    let mut guard = state.sync_handle.lock().expect("sync_handle mutex");
    state.sync_generation.fetch_add(1, Ordering::SeqCst);
    if let Some(existing) = guard.take() {
        existing.stop();
    }
}

fn run_retention_sweep(db: &Database, cache: &BlobCache, cache_dir: &Path) {
    if let Ok(settings) = db.retention_settings() {
        if let Ok((_deleted, referenced)) =
            db.prune_retention(now_unix_ms(), settings.days, settings.max_rows)
        {
            cache.prune_orphan_attachments(&referenced);
        }
    }
    prune_stale_dir_files(&cache_dir.join("macos_attachments"), STALE_STAGING_AGE);
}

fn dismiss_row_internal(app: &AppHandle, state: &AppState, row_id: i64) -> Result<(), String> {
    let rec = state
        .db
        .mark_dismissed_by_id(row_id, now_unix_ms())
        .map_err(|e| e.to_string())?;
    state.notifier.clear(row_id);
    if let Some(rec) = rec {
        if let Some(handle) = state.sync_handle.lock().expect("sync_handle mutex").as_ref() {
            handle.send_dismiss(rec.notification_uids);
        }
    }
    refresh_tray_and_emit(app, state);
    let _ = app.emit("notifications:updated", ());
    Ok(())
}

fn dismiss_all_internal(app: &AppHandle, state: &AppState) -> Result<(), String> {
    let dismissed_rows = state
        .db
        .mark_all_active_dismissed(now_unix_ms())
        .map_err(|e| e.to_string())?;
    state.notifier.clear_all();
    let mut all_uids = Vec::new();
    for row in dismissed_rows {
        for uid in row.notification_uids {
            if !all_uids.contains(&uid) {
                all_uids.push(uid);
            }
        }
    }
    if !all_uids.is_empty() {
        if let Some(handle) = state.sync_handle.lock().expect("sync_handle mutex").as_ref() {
            handle.send_dismiss(all_uids);
        }
    }
    refresh_tray_and_emit(app, state);
    let _ = app.emit("notifications:updated", ());
    Ok(())
}

pub(crate) fn sync_content_protection_before_show(
    app: &AppHandle,
    window: &tauri::WebviewWindow,
) {
    if let Some(state) = app.try_state::<Arc<AppState>>() {
        let desired = state.qr_content_protected.load(Ordering::SeqCst);
        let _ = window.set_content_protected(desired);
    }
}

fn revoke_local_trust(app: &AppHandle, state: &AppState) {
    let updated = {
        let mut guard = state.pairing.lock().expect("pairing mutex");
        if let Some(cur) = guard.as_mut() {
            if cur.can_add_devices {
                cur.can_add_devices = false;
                Some(cur.clone())
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some(new_cfg) = updated {
        let _ = state.credentials.save(&new_cfg);
        let _ = app.emit("state:updated", ());
    }
}

pub(crate) fn was_recently_hidden_by_blur(app: &AppHandle) -> bool {
    let Some(state) = app.try_state::<Arc<AppState>>() else {
        return false;
    };
    let mut guard = state.last_blur_hide.lock().expect("last_blur_hide mutex");
    if let Some(ts) = *guard {
        if ts.elapsed() <= BLUR_TOGGLE_DEBOUNCE {
            *guard = None;
            return true;
        }
    }
    false
}

pub(crate) fn toggle_mute_from_tray(app: &AppHandle) {
    if let Some(state) = app.try_state::<Arc<AppState>>() {
        let next = !state.db.is_muted().unwrap_or(false);
        let _ = state.db.set_muted(next);
        refresh_tray_and_emit(app, &state);
        let _ = app.emit("state:updated", ());
    }
}

pub(crate) fn dismiss_all_from_tray(app: &AppHandle) {
    if let Some(state) = app.try_state::<Arc<AppState>>() {
        let _ = dismiss_all_internal(app, &state);
    }
}

// ---- Tauri IPC Commands ----

#[tauri::command]
fn get_app_state(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<PublicAppState, String> {
    let pairing = state.pairing.lock().expect("pairing mutex").clone();
    let status = *state.status.lock().expect("status mutex");
    let muted = state.db.is_muted().map_err(|e| e.to_string())?;
    let privacy_mode = state.db.is_privacy_mode().map_err(|e| e.to_string())?;
    let unread_count = state.db.count_active().map_err(|e| e.to_string())?;
    let retention = state.db.retention_settings().map_err(|e| e.to_string())?;
    let autostart = app.autolaunch().is_enabled().unwrap_or(false);
    let notification_permission = state.notifier.permission_status();

    Ok(PublicAppState {
        paired: pairing.is_some(),
        server_url: pairing.as_ref().map(|p| p.server_url.clone()),
        device_id: pairing.as_ref().map(|p| p.device_id.clone()),
        device_name: pairing.as_ref().map(|p| p.device_name.clone()),
        can_add_devices: pairing.as_ref().is_some_and(|p| p.can_add_devices),
        status,
        muted,
        privacy_mode,
        autostart,
        unread_count,
        retention,
        notification_permission,
    })
}

#[tauri::command]
async fn pair_with_uri(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    uri: String,
    force_replace: Option<bool>,
) -> Result<PublicAppState, String> {
    let link = parse_pairing_link(&uri).map_err(|e| e.to_string())?;

    // Confirm before replacing an existing pairing with a different server URL or K_master KCV.
    let existing = state.pairing.lock().expect("pairing mutex").clone();
    if let Some(cur) = existing {
        let same_url = cur.server_url == link.server_url();
        let same_kcv = compute_kcv(&cur.key_bytes).ok() == compute_kcv(link.key_bytes()).ok();
        if (!same_url || !same_kcv) && !force_replace.unwrap_or(false) {
            return Err("CONFIRM_REPLACE".to_string());
        }
    }

    let cfg = match link {
        PairingLink::V1(cfg) => cfg,
        PairingLink::V2 {
            server_url,
            ws_url,
            code,
            key_base64url,
            key_bytes,
            ..
        } => {
            let client = build_http_client().map_err(|e| e.to_string())?;
            let claimed =
                claim_pairing_code(&client, &server_url, &code, current_desktop_platform())
                    .await
                    .map_err(|e| e.to_string())?;
            PairingConfig {
                version: 1,
                server_url,
                ws_url,
                token: claimed.token,
                key_base64url,
                key_bytes,
                device_id: claimed.device_id,
                device_name: claimed.name,
                can_add_devices: claimed.can_add_devices,
            }
        }
    };

    stop_sync(&state);
    state.qr_content_protected.store(false, Ordering::SeqCst);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_content_protected(false);
    }
    state.credentials.save(&cfg).map_err(|e| e.to_string())?;
    let _ = state.db.reset_last_acked_seq();
    let _ = state.db.clear_outbox();
    *state.pairing.lock().expect("pairing mutex") = Some(cfg.clone());
    *state.status.lock().expect("status mutex") = ConnectionStatus::Connecting;
    start_sync(&app, &state, cfg);
    refresh_tray_and_emit(&app, &state);
    get_app_state(app, state)
}

#[tauri::command]
async fn create_add_device_qr(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    name: String,
    platform: String,
) -> Result<AddDeviceQrResult, String> {
    let cfg = state
        .pairing
        .lock()
        .expect("pairing mutex")
        .clone()
        .ok_or_else(|| "Not paired".to_string())?;
    if !cfg.can_add_devices {
        return Err("This device is not trusted to add devices.".to_string());
    }
    let clean_name = name.trim().to_string();
    if clean_name.is_empty() || clean_name.chars().count() > 128 {
        return Err("Enter a device name (1-128 characters).".to_string());
    }
    let client = build_http_client().map_err(|e| e.to_string())?;
    let created = create_pairing_code(
        &client,
        &cfg.server_url,
        &cfg.token,
        &clean_name,
        platform.trim(),
    )
    .await
    .map_err(|e| {
        if e.status == 403 {
            revoke_local_trust(&app, &state);
        }
        e.to_string()
    })?;

    let pairing_uri = build_pairing_uri_v2(
        &cfg.server_url,
        &created.code,
        &cfg.key_base64url,
        &created.name,
    );
    let qr_svg = render_qr_svg(&pairing_uri).map_err(|e| e.to_string())?;

    Ok(AddDeviceQrResult {
        code_id: created.code_id,
        name: created.name,
        platform: created.platform,
        expires_at: created.expires_at,
        pairing_uri,
        qr_svg,
    })
}

#[tauri::command]
async fn list_my_pairing_codes(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<PairingCodeSummary>, String> {
    let cfg = state
        .pairing
        .lock()
        .expect("pairing mutex")
        .clone()
        .ok_or_else(|| "Not paired".to_string())?;
    if !cfg.can_add_devices {
        return Err("This device is not trusted to add devices.".to_string());
    }
    let client = build_http_client().map_err(|e| e.to_string())?;
    list_pairing_codes(&client, &cfg.server_url, &cfg.token)
        .await
        .map_err(|e| {
            if e.status == 403 {
                revoke_local_trust(&app, &state);
            }
            e.to_string()
        })
}

#[tauri::command]
fn set_content_protected(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    protected: bool,
) -> Result<(), String> {
    state.qr_content_protected.store(protected, Ordering::SeqCst);
    if let Some(window) = app.get_webview_window("main") {
        window
            .set_content_protected(protected)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn decode_qr_image(bytes: Vec<u8>) -> Result<String, String> {
    decode_qr_from_image_bytes(&bytes).map_err(|e| e.to_string())
}

#[tauri::command]
fn unpair(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<PublicAppState, String> {
    stop_sync(&state);
    state.qr_content_protected.store(false, Ordering::SeqCst);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_content_protected(false);
    }
    state.credentials.clear().map_err(|e| e.to_string())?;
    state.notifier.clear_all();
    let _ = state.db.clear_history();
    let _ = state.db.clear_outbox();
    let _ = state.db.reset_last_acked_seq();
    state.blob_cache.clear_attachments();
    *state.pairing.lock().expect("pairing mutex") = None;
    *state.status.lock().expect("status mutex") = ConnectionStatus::Unpaired;
    refresh_tray_and_emit(&app, &state);
    let _ = app.emit("notifications:updated", ());
    get_app_state(app, state)
}

#[tauri::command]
fn list_notifications(
    state: State<'_, Arc<AppState>>,
    query: Option<String>,
) -> Result<Vec<NotificationRecord>, String> {
    state
        .db
        .list_notifications(query.as_deref(), 500)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn dismiss_notification(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    row_id: i64,
) -> Result<(), String> {
    dismiss_row_internal(&app, &state, row_id)
}

#[tauri::command]
fn dismiss_all_active(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<(), String> {
    dismiss_all_internal(&app, &state)
}

#[tauri::command]
fn clear_history(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<(), String> {
    state.notifier.clear_all();
    state.db.clear_history().map_err(|e| e.to_string())?;
    state.blob_cache.clear_attachments();
    refresh_tray_and_emit(&app, &state);
    let _ = app.emit("notifications:updated", ());
    Ok(())
}

#[tauri::command]
fn set_muted(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    muted: bool,
) -> Result<bool, String> {
    state.db.set_muted(muted).map_err(|e| e.to_string())?;
    refresh_tray_and_emit(&app, &state);
    Ok(muted)
}

#[tauri::command]
fn set_privacy_mode(
    state: State<'_, Arc<AppState>>,
    enabled: bool,
) -> Result<bool, String> {
    state
        .db
        .set_privacy_mode(enabled)
        .map_err(|e| e.to_string())?;
    Ok(enabled)
}

#[tauri::command]
fn set_retention(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    days: i64,
    max_rows: i64,
) -> Result<RetentionSettings, String> {
    state
        .db
        .set_retention_settings(days, max_rows)
        .map_err(|e| e.to_string())?;
    run_retention_sweep(&state.db, &state.blob_cache, &state.cache_dir);
    refresh_tray_and_emit(&app, &state);
    let _ = app.emit("notifications:updated", ());
    state.db.retention_settings().map_err(|e| e.to_string())
}

#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, String> {
    let mgr = app.autolaunch();
    if enabled {
        mgr.enable().map_err(|e| e.to_string())?;
    } else {
        mgr.disable().map_err(|e| e.to_string())?;
    }
    Ok(mgr.is_enabled().unwrap_or(enabled))
}

#[tauri::command]
fn set_file_dialog_open(state: State<'_, Arc<AppState>>, open: bool) {
    state.file_dialog_open.store(open, Ordering::SeqCst);
}

#[tauri::command]
async fn request_notification_permission(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<NotificationPermission, String> {
    let notifier = Arc::clone(&state.notifier);
    let perm = tokio::task::spawn_blocking(move || notifier.request_permission_or_open_settings())
        .await
        .map_err(|e| e.to_string())?;
    let _ = app.emit("state:updated", ());
    Ok(perm)
}

#[tauri::command]
fn send_test_notification(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    match state.notifier.permission_status() {
        NotificationPermission::Denied => {
            return Err(
                "System notifications are disabled for All-Notify. Enable them in System Settings → Notifications."
                    .to_string(),
            );
        }
        NotificationPermission::Unavailable => {
            return Err(
                "System notifications are unavailable (app is not running from a signed .app bundle)."
                    .to_string(),
            );
        }
        NotificationPermission::NotDetermined => {
            return Err(
                "Grant notification permission first by clicking Allow notifications.".to_string(),
            );
        }
        NotificationPermission::Authorized => {}
    }
    state.notifier.show_test();
    Ok(())
}

#[tauri::command]
fn read_icon_data_url(
    state: State<'_, Arc<AppState>>,
    sha256: String,
) -> Result<Option<String>, String> {
    if !is_valid_sha256_hex(&sha256) {
        return Ok(None);
    }
    let Some(path) = state.blob_cache.get_icon_path(&sha256) else {
        return Ok(None);
    };
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    Ok(Some(format!(
        "data:image/webp;base64,{}",
        STANDARD.encode(bytes)
    )))
}

#[tauri::command]
fn read_attachment_data_url(
    state: State<'_, Arc<AppState>>,
    row_id: i64,
) -> Result<Option<String>, String> {
    let Some(rec) = state.db.get_by_id(row_id).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let Some(raw_path) = rec.attachment_path else {
        return Ok(None);
    };
    let path = PathBuf::from(&raw_path);
    // Defense-in-depth: only allow reading files inside our attachments cache directory.
    let Ok(canon_dir) = state.blob_cache.attachments_dir().canonicalize() else {
        return Ok(None);
    };
    let Ok(canon_file) = path.canonicalize() else {
        return Ok(None);
    };
    if !canon_file.starts_with(&canon_dir) || !canon_file.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(&canon_file).map_err(|e| e.to_string())?;
    let mime = match rec.attachment_mime.as_deref() {
        Some(m @ ("image/webp" | "image/jpeg" | "image/png")) => m,
        _ => {
            let ext = canon_file
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("webp");
            mime_for_extension(ext)
        }
    };
    Ok(Some(format!("data:{mime};base64,{}", STANDARD.encode(bytes))))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let data_dir = app.path().app_data_dir()?;
            let cache_dir = app.path().app_cache_dir()?;
            fs::create_dir_all(&data_dir)?;
            fs::create_dir_all(&cache_dir)?;

            let db = Arc::new(
                Database::open(&data_dir.join("all-notify.db"))
                    .map_err(|e| std::io::Error::other(e.to_string()))?,
            );
            let blob_cache = Arc::new(
                BlobCache::new(&cache_dir, DEFAULT_MAX_ICONS)
                    .map_err(|e| std::io::Error::other(e.to_string()))?,
            );

            // Startup retention sweep.
            run_retention_sweep(&db, &blob_cache, &cache_dir);

            let (dismiss_tx, mut dismiss_rx) = mpsc::unbounded_channel::<DismissAction>();
            let notifier: Arc<dyn PlatformNotifier> =
                Arc::from(create_platform_notifier(cache_dir.clone(), dismiss_tx));
            let app_for_perm = app.handle().clone();
            notifier.set_on_permission_changed(Arc::new(move || {
                let _ = app_for_perm.emit("state:updated", ());
            }));
            // Re-check in case permission changed before callback was registered.
            notifier.refresh_permission();

            let credentials =
                CredentialManager::new(&data_dir, Box::new(KeyringSecretStore::default()));
            let existing_pairing = credentials.load().ok().flatten();
            let initial_status = if existing_pairing.is_some() {
                ConnectionStatus::Connecting
            } else {
                ConnectionStatus::Unpaired
            };

            let app_state = Arc::new(AppState {
                db: Arc::clone(&db),
                blob_cache: Arc::clone(&blob_cache),
                cache_dir: cache_dir.clone(),
                credentials,
                notifier,
                pairing: Mutex::new(existing_pairing.clone()),
                status: Mutex::new(initial_status),
                sync_handle: Mutex::new(None),
                sync_generation: AtomicU64::new(0),
                file_dialog_open: AtomicBool::new(false),
                qr_content_protected: AtomicBool::new(false),
                last_blur_hide: Mutex::new(None),
            });
            app.manage(Arc::clone(&app_state));

            tray::setup_tray(app.handle())?;
            refresh_tray_and_emit(app.handle(), &app_state);

            // Auto-hide popover when focus leaves (unless a native file picker is open),
            // and intercept Cmd+W / Alt+F4 so closing the popover hides it instead of exiting the tray app.
            if let Some(window) = app.get_webview_window("main") {
                let win_clone = window.clone();
                let state_clone = Arc::clone(&app_state);
                window.on_window_event(move |event| match event {
                    WindowEvent::CloseRequested { api, .. } => {
                        api.prevent_close();
                        let _ = win_clone.set_content_protected(false);
                        let _ = win_clone.hide();
                    }
                    WindowEvent::Focused(true) => {
                        state_clone.file_dialog_open.store(false, Ordering::SeqCst);
                        state_clone.notifier.refresh_permission();
                    }
                    WindowEvent::Focused(false)
                        if !state_clone.file_dialog_open.load(Ordering::SeqCst) =>
                    {
                        *state_clone
                            .last_blur_hide
                            .lock()
                            .expect("last_blur_hide mutex") = Some(Instant::now());
                        let _ = win_clone.set_content_protected(false);
                        let _ = win_clone.hide();
                    }
                    _ => {}
                });
            }

            // Consume OS notification Dismiss callbacks (macOS Dismiss button / Windows Toast dismiss).
            let handle_for_dismiss = app.handle().clone();
            let state_for_dismiss = Arc::clone(&app_state);
            tauri::async_runtime::spawn(async move {
                while let Some(action) = dismiss_rx.recv().await {
                    let _ = dismiss_row_internal(&handle_for_dismiss, &state_for_dismiss, action.row_id);
                }
            });

            // 24-hour background retention sweeper.
            let db_for_sweep = Arc::clone(&db);
            let cache_for_sweep = Arc::clone(&blob_cache);
            let cache_dir_for_sweep = cache_dir.clone();
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(RETENTION_SWEEP_INTERVAL);
                interval.tick().await; // skip immediate tick (already ran at startup)
                loop {
                    interval.tick().await;
                    run_retention_sweep(&db_for_sweep, &cache_for_sweep, &cache_dir_for_sweep);
                }
            });

            // Start sync automatically if already paired.
            if let Some(cfg) = existing_pairing {
                start_sync(app.handle(), &app_state, cfg);
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_state,
            pair_with_uri,
            create_add_device_qr,
            list_my_pairing_codes,
            set_content_protected,
            decode_qr_image,
            unpair,
            list_notifications,
            dismiss_notification,
            dismiss_all_active,
            clear_history,
            set_muted,
            set_privacy_mode,
            set_retention,
            set_autostart,
            set_file_dialog_open,
            request_notification_permission,
            send_test_notification,
            read_icon_data_url,
            read_attachment_data_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running All-Notify desktop app");
}
