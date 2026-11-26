use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use windows::core::{Interface, HSTRING, IInspectable};
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{
    ToastActivatedEventArgs, ToastDismissalReason, ToastDismissedEventArgs, ToastNotification,
    ToastNotificationManager,
};

use super::{
    build_windows_test_toast_xml, build_windows_toast_xml, xml_escape, DismissAction,
    OsNotification, PlatformNotifier,
};

const WINDOWS_AUMID: &str = "com.allnotify.desktop";
const TOAST_GROUP: &str = "allnotify";
const SUMMARY_TAG: &str = "summary";
const MAX_RETAINED_TOASTS: usize = 64;
static WINDOWS_TEST_SEQ: AtomicU64 = AtomicU64::new(1);

pub struct WindowsNotifier {
    dismiss_tx: mpsc::UnboundedSender<DismissAction>,
    // Retain active ToastNotification instances so WinRT Activated/Dismissed handlers stay alive.
    active_toasts: Arc<Mutex<HashMap<i64, ToastNotification>>>,
}

impl WindowsNotifier {
    pub fn new(dismiss_tx: mpsc::UnboundedSender<DismissAction>) -> Self {
        Self {
            dismiss_tx,
            active_toasts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn tag_for_row(row_id: i64) -> String {
        format!("n_{row_id}")
    }

    fn show_toast_xml(&self, xml_str: &str, tag: &str, row_id: Option<i64>, silent: bool) {
        let _ = self.show_toast_xml_result(xml_str, tag, row_id, silent);
    }

    fn show_toast_xml_result(
        &self,
        xml_str: &str,
        tag: &str,
        row_id: Option<i64>,
        silent: bool,
    ) -> Result<(), String> {
        let doc = XmlDocument::new().map_err(|e| format!("Failed to create toast XML: {e}"))?;
        doc.LoadXml(&HSTRING::from(xml_str))
            .map_err(|e| format!("Failed to parse toast XML: {e}"))?;
        let toast = ToastNotification::CreateToastNotification(&doc)
            .map_err(|e| format!("Failed to create Windows toast: {e}"))?;
        let _ = toast.SetTag(&HSTRING::from(tag));
        let _ = toast.SetGroup(&HSTRING::from(TOAST_GROUP));
        if silent {
            let _ = toast.SetSuppressPopup(true);
        }

        if let Some(id) = row_id {
            // 1. Explicit Dismiss button click (Activated event).
            let tx_act = self.dismiss_tx.clone();
            let toasts_act = Arc::clone(&self.active_toasts);
            let _ = toast.Activated(&TypedEventHandler::<ToastNotification, IInspectable>::new(
                move |_sender, args| {
                    if let Some(args) = args.as_ref() {
                        if let Ok(activated) = args.cast::<ToastActivatedEventArgs>() {
                            if let Ok(arg_str) = activated.Arguments() {
                                if arg_str.to_string().starts_with("dismiss:") {
                                    let _ = tx_act.send(DismissAction { row_id: id });
                                    if let Ok(mut map) = toasts_act.lock() {
                                        map.remove(&id);
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
                },
            ));

            // 2. Native swipe-dismiss / X button (Dismissed event with UserCanceled).
            let tx_dis = self.dismiss_tx.clone();
            let toasts_dis = Arc::clone(&self.active_toasts);
            let _ = toast.Dismissed(
                &TypedEventHandler::<ToastNotification, ToastDismissedEventArgs>::new(
                    move |_sender, args| {
                        if let Some(args) = args.as_ref() {
                            if let Ok(reason) = args.Reason() {
                                if reason == ToastDismissalReason::UserCanceled {
                                    let _ = tx_dis.send(DismissAction { row_id: id });
                                }
                            }
                        }
                        if let Ok(mut map) = toasts_dis.lock() {
                            map.remove(&id);
                        }
                        Ok(())
                    },
                ),
            );
        }

        let notifier =
            ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(WINDOWS_AUMID))
                .map_err(|e| format!("Failed to initialize Windows toast notifier: {e}"))?;
        notifier
            .Show(&toast)
            .map_err(|e| format!("Windows failed to show toast notification: {e}"))?;
        if let Some(id) = row_id {
            if let Ok(mut map) = self.active_toasts.lock() {
                if map.len() >= MAX_RETAINED_TOASTS {
                    if let Some(&oldest_id) = map.keys().min() {
                        map.remove(&oldest_id);
                    }
                }
                map.insert(id, toast);
            }
        }
        Ok(())
    }
}

impl PlatformNotifier for WindowsNotifier {
    fn show(&self, notif: &OsNotification) {
        let xml = build_windows_toast_xml(notif);
        self.show_toast_xml(
            &xml,
            &Self::tag_for_row(notif.row_id),
            Some(notif.row_id),
            notif.silent_update,
        );
    }

    fn show_summary(&self, unread_count: usize) {
        let title = xml_escape("All-Notify");
        let body = xml_escape(&format!(
            "{unread_count} unread notifications from your phones"
        ));
        let xml = format!(
            r#"<toast><visual><binding template="ToastGeneric"><text>{title}</text><text>{body}</text></binding></visual></toast>"#
        );
        self.show_toast_xml(&xml, SUMMARY_TAG, None, false);
    }

    fn clear(&self, row_id: i64) {
        if let Ok(mut map) = self.active_toasts.lock() {
            map.remove(&row_id);
        }
        if let Ok(history) = ToastNotificationManager::History() {
            let _ = history.RemoveGroupedTagWithId(
                &HSTRING::from(Self::tag_for_row(row_id)),
                &HSTRING::from(TOAST_GROUP),
                &HSTRING::from(WINDOWS_AUMID),
            );
        }
    }

    fn clear_all(&self) {
        if let Ok(mut map) = self.active_toasts.lock() {
            map.clear();
        }
        if let Ok(history) = ToastNotificationManager::History() {
            let _ = history.RemoveGroupWithId(
                &HSTRING::from(TOAST_GROUP),
                &HSTRING::from(WINDOWS_AUMID),
            );
        }
    }

    fn send_test(&self) -> Result<String, String> {
        let xml = build_windows_test_toast_xml();
        let seq = WINDOWS_TEST_SEQ.fetch_add(1, Ordering::Relaxed) % 1_000_000;
        let tag = format!("test_{seq}");
        self.show_toast_xml_result(&xml, &tag, None, false)?;
        Ok("Test notification sent.".to_string())
    }
}
