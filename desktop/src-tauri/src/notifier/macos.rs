use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::time::Duration;

use block2::{DynBlock, RcBlock};
use objc2::rc::Retained;
use objc2::runtime::{Bool, NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{define_class, msg_send, AnyThread, DeclaredClass};
use objc2_foundation::{NSArray, NSBundle, NSError, NSSet, NSString, NSURL};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNAuthorizationStatus, UNMutableNotificationContent, UNNotification,
    UNNotificationAction, UNNotificationActionOptions, UNNotificationAttachment,
    UNNotificationCategory, UNNotificationCategoryOptions, UNNotificationPresentationOptions,
    UNNotificationRequest, UNNotificationResponse, UNNotificationSettings, UNNotificationSound,
    UNUserNotificationCenter, UNUserNotificationCenterDelegate,
};
use tokio::sync::mpsc;

use super::{
    notification_id_for_row, parse_row_id_from_notification_id, DismissAction,
    NotificationPermission, OsNotification, PlatformNotifier, DISMISS_ACTION_ID,
    NOTIFICATION_CATEGORY_ID, SUMMARY_NOTIFICATION_ID, TEST_NOTIFICATION_ID,
};

const PERM_NOT_DETERMINED: u8 = 0;
const PERM_DENIED: u8 = 1;
const PERM_AUTHORIZED: u8 = 2;
const PERM_UNAVAILABLE: u8 = 3;

const MACOS_NOTIFICATIONS_SETTINGS_URL: &str =
    "x-apple.systempreferences:com.apple.Notifications-Settings.extension";

fn perm_to_u8(perm: NotificationPermission) -> u8 {
    match perm {
        NotificationPermission::NotDetermined => PERM_NOT_DETERMINED,
        NotificationPermission::Denied => PERM_DENIED,
        NotificationPermission::Authorized => PERM_AUTHORIZED,
        NotificationPermission::Unavailable => PERM_UNAVAILABLE,
    }
}

fn u8_to_perm(raw: u8) -> NotificationPermission {
    match raw {
        PERM_DENIED => NotificationPermission::Denied,
        PERM_AUTHORIZED => NotificationPermission::Authorized,
        PERM_UNAVAILABLE => NotificationPermission::Unavailable,
        _ => NotificationPermission::NotDetermined,
    }
}

pub(crate) fn map_un_auth_status(status: UNAuthorizationStatus) -> NotificationPermission {
    match status {
        UNAuthorizationStatus::Authorized
        | UNAuthorizationStatus::Provisional
        | UNAuthorizationStatus::Ephemeral => NotificationPermission::Authorized,
        UNAuthorizationStatus::Denied => NotificationPermission::Denied,
        UNAuthorizationStatus::NotDetermined => NotificationPermission::NotDetermined,
        _ => NotificationPermission::NotDetermined,
    }
}

struct PermissionState {
    status: AtomicU8,
    on_change: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl PermissionState {
    fn new(initial: NotificationPermission) -> Self {
        Self {
            status: AtomicU8::new(perm_to_u8(initial)),
            on_change: Mutex::new(None),
        }
    }

    fn get(&self) -> NotificationPermission {
        u8_to_perm(self.status.load(Ordering::SeqCst))
    }

    fn set(&self, next: NotificationPermission) {
        let next_raw = perm_to_u8(next);
        let prev = self.status.swap(next_raw, Ordering::SeqCst);
        if prev != next_raw {
            let cb = self.on_change.lock().ok().and_then(|g| g.clone());
            if let Some(cb) = cb {
                cb();
            }
        }
    }

    fn set_on_change(&self, cb: Arc<dyn Fn() + Send + Sync>) {
        if let Ok(mut guard) = self.on_change.lock() {
            *guard = Some(cb);
        }
    }
}

fn open_macos_notification_settings() {
    if let Err(err) = Command::new("open")
        .arg(MACOS_NOTIFICATIONS_SETTINGS_URL)
        .spawn()
    {
        eprintln!("[all-notify] failed to open macOS Notification Settings: {err}");
    }
}

fn query_settings_async(perm: Arc<PermissionState>, auto_request_if_not_determined: bool) {
    let center = UNUserNotificationCenter::currentNotificationCenter();
    let block = RcBlock::new(move |settings_ptr: NonNull<UNNotificationSettings>| {
        let status = unsafe { settings_ptr.as_ref() }.authorizationStatus();
        let mapped = map_un_auth_status(status);
        perm.set(mapped);
        if auto_request_if_not_determined && mapped == NotificationPermission::NotDetermined {
            request_authorization_async(Arc::clone(&perm));
        }
    });
    center.getNotificationSettingsWithCompletionHandler(&block);
}

fn request_authorization_async(perm: Arc<PermissionState>) {
    let center = UNUserNotificationCenter::currentNotificationCenter();
    let auth_opts = UNAuthorizationOptions::Alert
        | UNAuthorizationOptions::Sound
        | UNAuthorizationOptions::Badge;
    let auth_block = RcBlock::new(move |granted: Bool, err: *mut NSError| {
        if !err.is_null() {
            let err_ref = unsafe { &*err };
            eprintln!(
                "[all-notify] macOS notification authorization failed ({} code {}): {}",
                err_ref.domain(),
                err_ref.code(),
                err_ref.localizedDescription()
            );
        }
        let next = if granted.as_bool() {
            NotificationPermission::Authorized
        } else {
            NotificationPermission::Denied
        };
        perm.set(next);
        query_settings_async(Arc::clone(&perm), false);
    });
    center.requestAuthorizationWithOptions_completionHandler(auth_opts, &auth_block);
}

struct DelegateIvars {
    dismiss_tx: mpsc::UnboundedSender<DismissAction>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "AllNotifyUNDelegate"]
    #[ivars = DelegateIvars]
    struct AllNotifyUNDelegate;

    unsafe impl NSObjectProtocol for AllNotifyUNDelegate {}

    unsafe impl UNUserNotificationCenterDelegate for AllNotifyUNDelegate {
        #[unsafe(method(userNotificationCenter:willPresentNotification:withCompletionHandler:))]
        fn will_present(
            &self,
            _center: &UNUserNotificationCenter,
            notification: &UNNotification,
            completion_handler: &DynBlock<dyn Fn(UNNotificationPresentationOptions)>,
        ) {
            // Silent merged updates omit sound; update Notification Center list without popping a second banner.
            let opts = if notification.request().content().sound().is_some() {
                UNNotificationPresentationOptions::Banner
                    | UNNotificationPresentationOptions::List
                    | UNNotificationPresentationOptions::Sound
            } else {
                UNNotificationPresentationOptions::List
            };
            completion_handler.call((opts,));
        }

        #[unsafe(method(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:))]
        fn did_receive_response(
            &self,
            _center: &UNUserNotificationCenter,
            response: &UNNotificationResponse,
            completion_handler: &DynBlock<dyn Fn()>,
        ) {
            let action_id = response.actionIdentifier().to_string();
            if action_id == DISMISS_ACTION_ID {
                let req_id = response.notification().request().identifier().to_string();
                if let Some(row_id) = parse_row_id_from_notification_id(&req_id) {
                    let _ = self.ivars().dismiss_tx.send(DismissAction { row_id });
                }
            }
            completion_handler.call(());
        }
    }
);

impl AllNotifyUNDelegate {
    fn new(dismiss_tx: mpsc::UnboundedSender<DismissAction>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(DelegateIvars { dismiss_tx });
        unsafe { msg_send![super(this), init] }
    }
}

/// Retains the ObjC delegate strongly because `UNUserNotificationCenter.delegate` is weak.
struct RetainedDelegate(#[allow(dead_code)] Retained<AllNotifyUNDelegate>);

// Safety: UNUserNotificationCenter invokes delegate methods thread-safely and our ivar
// (`UnboundedSender`) is Send + Sync.
unsafe impl Send for RetainedDelegate {}
unsafe impl Sync for RetainedDelegate {}

pub struct MacOsNotifier {
    enabled: bool,
    staging_dir: PathBuf,
    permission: Arc<PermissionState>,
    _delegate: Option<RetainedDelegate>,
}

impl MacOsNotifier {
    pub fn new(cache_dir: PathBuf, dismiss_tx: mpsc::UnboundedSender<DismissAction>) -> Self {
        let staging_dir = cache_dir.join("macos_attachments");
        let _ = fs::create_dir_all(&staging_dir);

        // UNUserNotificationCenter throws an ObjC exception if called without a valid bundle ID
        // (e.g. during `cargo test` or running an unbundled binary).
        let has_bundle = NSBundle::mainBundle().bundleIdentifier().is_some();
        if !has_bundle {
            eprintln!("[all-notify] macOS notifications unavailable: missing app bundle identifier");
            return Self {
                enabled: false,
                staging_dir,
                permission: Arc::new(PermissionState::new(NotificationPermission::Unavailable)),
                _delegate: None,
            };
        }

        let center = UNUserNotificationCenter::currentNotificationCenter();

        let delegate = AllNotifyUNDelegate::new(dismiss_tx);
        let proto: &ProtocolObject<dyn UNUserNotificationCenterDelegate> =
            ProtocolObject::from_ref(&*delegate);
        center.setDelegate(Some(proto));

        // Register category ALL_NOTIFY_MSG with background "Dismiss" action (options = empty).
        let dismiss_action = UNNotificationAction::actionWithIdentifier_title_options(
            &NSString::from_str(DISMISS_ACTION_ID),
            &NSString::from_str("Dismiss"),
            UNNotificationActionOptions::empty(),
        );
        let actions = NSArray::from_retained_slice(&[dismiss_action]);
        let intents: Retained<NSArray<NSString>> = NSArray::new();
        let category = UNNotificationCategory::categoryWithIdentifier_actions_intentIdentifiers_options(
            &NSString::from_str(NOTIFICATION_CATEGORY_ID),
            &actions,
            &intents,
            UNNotificationCategoryOptions::empty(),
        );
        let categories = NSSet::from_retained_slice(&[category]);
        center.setNotificationCategories(&categories);

        let permission = Arc::new(PermissionState::new(NotificationPermission::NotDetermined));
        // Inspect current authorization state and request permission if not yet determined
        // (macOS Focus / DND is respected automatically by UNUserNotificationCenter).
        query_settings_async(Arc::clone(&permission), true);

        Self {
            enabled: true,
            staging_dir,
            permission,
            _delegate: Some(RetainedDelegate(delegate)),
        }
    }

    fn post_request(&self, id: &str, content: &UNMutableNotificationContent) {
        if !self.enabled {
            return;
        }
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let req = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &NSString::from_str(id),
            content,
            None,
        );
        let perm = Arc::clone(&self.permission);
        let block = RcBlock::new(move |err: *mut NSError| {
            if !err.is_null() {
                let err_ref = unsafe { &*err };
                eprintln!(
                    "[all-notify] macOS notification delivery failed ({} code {}): {}",
                    err_ref.domain(),
                    err_ref.code(),
                    err_ref.localizedDescription()
                );
                query_settings_async(Arc::clone(&perm), false);
            }
        });
        center.addNotificationRequest_withCompletionHandler(&req, Some(&block));
    }

    fn query_settings_blocking(&self) -> NotificationPermission {
        if !self.enabled {
            return NotificationPermission::Unavailable;
        }
        let (tx, rx) = std_mpsc::sync_channel(1);
        let tx = Mutex::new(Some(tx));
        let perm = Arc::clone(&self.permission);
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let block = RcBlock::new(move |settings_ptr: NonNull<UNNotificationSettings>| {
            let status = unsafe { settings_ptr.as_ref() }.authorizationStatus();
            let mapped = map_un_auth_status(status);
            perm.set(mapped);
            if let Ok(mut guard) = tx.lock() {
                if let Some(sender) = guard.take() {
                    let _ = sender.try_send(mapped);
                }
            }
        });
        center.getNotificationSettingsWithCompletionHandler(&block);
        rx.recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|_| self.permission.get())
    }
}

impl PlatformNotifier for MacOsNotifier {
    fn show(&self, notif: &OsNotification) {
        if !self.enabled {
            return;
        }
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str(&notif.title));
        content.setSubtitle(&NSString::from_str(&format!(
            "{} • {}",
            notif.app_name, notif.sender_label
        )));
        content.setBody(&NSString::from_str(&notif.body));
        content.setCategoryIdentifier(&NSString::from_str(NOTIFICATION_CATEGORY_ID));
        if !notif.silent_update {
            content.setSound(Some(&UNNotificationSound::defaultSound()));
        }

        // Prefer image attachment if present, otherwise attach the app icon.
        let media_src = notif
            .attachment_path
            .as_deref()
            .or(notif.icon_path.as_deref());
        if let Some(src) = media_src {
            if let Some(staged) =
                prepare_macos_attachment_file(src, &self.staging_dir, &notif.id)
            {
                let url = NSURL::fileURLWithPath(&NSString::from_str(&staged.to_string_lossy()));
                let att_res = unsafe {
                    UNNotificationAttachment::attachmentWithIdentifier_URL_options_error(
                        &NSString::from_str("media"),
                        &url,
                        None,
                    )
                };
                if let Ok(att) = att_res {
                    let list = NSArray::from_retained_slice(&[att]);
                    content.setAttachments(&list);
                } else {
                    if let Err(err) = att_res {
                        eprintln!(
                            "[all-notify] macOS attachment staging failed ({} code {}): {}",
                            err.domain(),
                            err.code(),
                            err.localizedDescription()
                        );
                    }
                    let _ = fs::remove_file(&staged);
                }
            }
        }

        self.post_request(&notif.id, &content);
    }

    fn show_summary(&self, unread_count: usize) {
        if !self.enabled {
            return;
        }
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str("All-Notify"));
        content.setBody(&NSString::from_str(&format!(
            "{unread_count} unread notifications from your phones"
        )));
        content.setSound(Some(&UNNotificationSound::defaultSound()));
        self.post_request(SUMMARY_NOTIFICATION_ID, &content);
    }

    fn clear(&self, row_id: i64) {
        if !self.enabled {
            return;
        }
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let id = NSString::from_str(&notification_id_for_row(row_id));
        let ids = NSArray::from_retained_slice(&[id]);
        center.removeDeliveredNotificationsWithIdentifiers(&ids);
        center.removePendingNotificationRequestsWithIdentifiers(&ids);
    }

    fn clear_all(&self) {
        if !self.enabled {
            return;
        }
        let center = UNUserNotificationCenter::currentNotificationCenter();
        center.removeAllDeliveredNotifications();
        center.removeAllPendingNotificationRequests();
    }

    fn show_test(&self) {
        if !self.enabled {
            return;
        }
        let content = UNMutableNotificationContent::new();
        content.setTitle(&NSString::from_str("All-Notify Test"));
        content.setBody(&NSString::from_str(
            "Native macOS notifications are working.",
        ));
        content.setSound(Some(&UNNotificationSound::defaultSound()));
        self.post_request(TEST_NOTIFICATION_ID, &content);
    }

    fn permission_status(&self) -> NotificationPermission {
        self.permission.get()
    }

    fn refresh_permission(&self) {
        if !self.enabled {
            return;
        }
        query_settings_async(Arc::clone(&self.permission), false);
    }

    fn request_permission_or_open_settings(&self) -> NotificationPermission {
        let current = self.query_settings_blocking();
        match current {
            NotificationPermission::Authorized | NotificationPermission::Unavailable => current,
            NotificationPermission::Denied => {
                open_macos_notification_settings();
                NotificationPermission::Denied
            }
            NotificationPermission::NotDetermined => {
                let (tx, rx) = std_mpsc::sync_channel(1);
                let tx = Mutex::new(Some(tx));
                let perm = Arc::clone(&self.permission);
                let center = UNUserNotificationCenter::currentNotificationCenter();
                let auth_opts = UNAuthorizationOptions::Alert
                    | UNAuthorizationOptions::Sound
                    | UNAuthorizationOptions::Badge;
                let auth_block = RcBlock::new(move |granted: Bool, err: *mut NSError| {
                    let has_err = !err.is_null();
                    if has_err {
                        let err_ref = unsafe { &*err };
                        eprintln!(
                            "[all-notify] macOS notification authorization failed ({} code {}): {}",
                            err_ref.domain(),
                            err_ref.code(),
                            err_ref.localizedDescription()
                        );
                    }
                    let next = if granted.as_bool() {
                        NotificationPermission::Authorized
                    } else {
                        NotificationPermission::Denied
                    };
                    perm.set(next);
                    if let Ok(mut guard) = tx.lock() {
                        if let Some(sender) = guard.take() {
                            let _ = sender.try_send((granted.as_bool(), has_err));
                        }
                    }
                    query_settings_async(Arc::clone(&perm), false);
                });
                center.requestAuthorizationWithOptions_completionHandler(auth_opts, &auth_block);

                match rx.recv_timeout(Duration::from_millis(1500)) {
                    Ok((true, _)) => NotificationPermission::Authorized,
                    Ok((false, _)) => {
                        open_macos_notification_settings();
                        NotificationPermission::Denied
                    }
                    // Timed out while macOS is showing the interactive prompt; callback updates state when answered.
                    Err(_) => NotificationPermission::NotDetermined,
                }
            }
        }
    }

    fn set_on_permission_changed(&self, cb: Arc<dyn Fn() + Send + Sync>) {
        self.permission.set_on_change(cb);
    }
}

static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

/// Prepares a temporary PNG/JPEG copy for `UNNotificationAttachment`, which moves the source file
/// into Apple's notification store and does not natively accept WebP on all macOS versions.
pub(crate) fn prepare_macos_attachment_file(
    src: &Path,
    staging_dir: &Path,
    key: &str,
) -> Option<PathBuf> {
    if !src.is_file() {
        return None;
    }
    fs::create_dir_all(staging_dir).ok()?;
    let safe_key: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    let nonce = crate::storage::now_unix_ms();
    let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);

    let ext = src
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext == "png" || ext == "jpg" || ext == "jpeg" {
        let dest = staging_dir.join(format!("{safe_key}_{nonce}_{seq}.{ext}"));
        fs::copy(src, &dest).ok()?;
        return Some(dest);
    }

    // Convert WebP (or any other supported format) to PNG for UNNotificationAttachment compatibility.
    let img = image::open(src).ok()?;
    let dest = staging_dir.join(format!("{safe_key}_{nonce}_{seq}.png"));
    img.save_with_format(&dest, image::ImageFormat::Png).ok()?;
    Some(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageFormat, Rgba, RgbaImage};

    #[test]
    fn converts_webp_icon_to_staged_png_for_macos_attachment() {
        let dir = tempfile::tempdir().unwrap();
        let webp_path = dir.path().join("icon.webp");
        let img = RgbaImage::from_pixel(16, 16, Rgba([37, 99, 235, 255]));
        img.save_with_format(&webp_path, ImageFormat::WebP).unwrap();

        let staging = dir.path().join("staging");
        let staged1 = prepare_macos_attachment_file(&webp_path, &staging, "allnotify_42")
            .expect("staged png 1");
        let staged2 = prepare_macos_attachment_file(&webp_path, &staging, "allnotify_42")
            .expect("staged png 2");
        assert!(staged1.exists());
        assert!(staged2.exists());
        assert_ne!(staged1, staged2, "same-ms staging calls must not collide");
        assert_eq!(staged1.extension().and_then(|e| e.to_str()), Some("png"));
        // Original cache file must remain untouched.
        assert!(webp_path.exists());
    }

    #[test]
    fn unbundled_test_process_constructs_notifier_safely() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();
        let notifier = MacOsNotifier::new(dir.path().to_path_buf(), tx);
        // Should gracefully disable instead of throwing an ObjC exception in unbundled cargo test.
        assert_eq!(notifier.permission_status(), NotificationPermission::Unavailable);
        assert_eq!(
            notifier.request_permission_or_open_settings(),
            NotificationPermission::Unavailable
        );
        notifier.show_test();
        notifier.show_summary(3);
        notifier.clear(1);
    }

    #[test]
    fn maps_un_authorization_statuses_and_fires_change_callback_once_per_transition() {
        assert_eq!(
            map_un_auth_status(UNAuthorizationStatus::Authorized),
            NotificationPermission::Authorized
        );
        assert_eq!(
            map_un_auth_status(UNAuthorizationStatus::Provisional),
            NotificationPermission::Authorized
        );
        assert_eq!(
            map_un_auth_status(UNAuthorizationStatus::Ephemeral),
            NotificationPermission::Authorized
        );
        assert_eq!(
            map_un_auth_status(UNAuthorizationStatus::Denied),
            NotificationPermission::Denied
        );
        assert_eq!(
            map_un_auth_status(UNAuthorizationStatus::NotDetermined),
            NotificationPermission::NotDetermined
        );

        let perm = PermissionState::new(NotificationPermission::NotDetermined);
        let calls = Arc::new(AtomicU64::new(0));
        let calls_clone = Arc::clone(&calls);
        perm.set_on_change(Arc::new(move || {
            calls_clone.fetch_add(1, Ordering::SeqCst);
        }));

        perm.set(NotificationPermission::NotDetermined);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        perm.set(NotificationPermission::Denied);
        assert_eq!(perm.get(), NotificationPermission::Denied);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        perm.set(NotificationPermission::Denied);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        perm.set(NotificationPermission::Authorized);
        assert_eq!(perm.get(), NotificationPermission::Authorized);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
