use std::path::PathBuf;

use tokio::sync::mpsc;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub const DISMISS_ACTION_ID: &str = "DISMISS_ACTION";
pub const NOTIFICATION_CATEGORY_ID: &str = "ALL_NOTIFY_MSG";
pub const SUMMARY_NOTIFICATION_ID: &str = "allnotify_replay_summary";

#[derive(Debug, Clone)]
pub struct OsNotification {
    pub id: String,
    pub row_id: i64,
    pub app_name: String,
    pub sender_label: String,
    pub title: String,
    pub body: String,
    pub icon_path: Option<PathBuf>,
    pub attachment_path: Option<PathBuf>,
    pub silent_update: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DismissAction {
    pub row_id: i64,
}

pub fn notification_id_for_row(row_id: i64) -> String {
    format!("allnotify_{row_id}")
}

pub fn parse_row_id_from_notification_id(id: &str) -> Option<i64> {
    id.strip_prefix("allnotify_")?.parse::<i64>().ok()
}

pub fn build_windows_toast_xml(notif: &OsNotification) -> String {
    let title = xml_escape(&notif.title);
    let body = xml_escape(&notif.body);
    let attribution = xml_escape(&format!("{} • {}", notif.app_name, notif.sender_label));

    let logo_xml = notif
        .icon_path
        .as_deref()
        .and_then(|p| url::Url::from_file_path(p).ok())
        .map(|uri| {
            format!(
                r#"<image placement="appLogoOverride" hint-crop="circle" src="{}"/>"#,
                xml_escape(uri.as_str())
            )
        })
        .unwrap_or_default();

    let hero_xml = notif
        .attachment_path
        .as_deref()
        .and_then(|p| url::Url::from_file_path(p).ok())
        .map(|uri| {
            format!(
                r#"<image placement="hero" src="{}"/>"#,
                xml_escape(uri.as_str())
            )
        })
        .unwrap_or_default();

    let dismiss_arg = format!("dismiss:{}", notif.row_id);
    format!(
        r#"<toast launch="open:{row_id}"><visual><binding template="ToastGeneric">{logo_xml}{hero_xml}<text>{title}</text><text>{body}</text><text placement="attribution">{attribution}</text></binding></visual><actions><action content="Dismiss" arguments="{dismiss_arg}" activationType="background"/></actions></toast>"#,
        row_id = notif.row_id
    )
}

pub fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_id_round_trip() {
        let id = notification_id_for_row(123);
        assert_eq!(id, "allnotify_123");
        assert_eq!(parse_row_id_from_notification_id(&id), Some(123));
        assert_eq!(parse_row_id_from_notification_id("other_123"), None);
    }

    #[test]
    fn windows_toast_xml_escapes_content_and_includes_dismiss_action() {
        let tmp = std::env::temp_dir();
        let notif = OsNotification {
            id: "allnotify_7".into(),
            row_id: 7,
            app_name: "WhatsApp".into(),
            sender_label: "Pixel 9, Galaxy".into(),
            title: "Alice & Bob".into(),
            body: "Dinner <7pm> \"tonight\"".into(),
            icon_path: Some(tmp.join("icon.webp")),
            attachment_path: Some(tmp.join("photo.jpg")),
            silent_update: false,
        };
        let xml = build_windows_toast_xml(&notif);
        assert!(xml.contains("Alice &amp; Bob"));
        assert!(xml.contains("Dinner &lt;7pm&gt; &quot;tonight&quot;"));
        assert!(xml.contains(r#"placement="appLogoOverride""#));
        assert!(xml.contains(r#"placement="hero""#));
        assert!(xml.contains(r#"arguments="dismiss:7" activationType="background""#));
    }
}

pub trait PlatformNotifier: Send + Sync {
    fn show(&self, notif: &OsNotification);
    fn show_summary(&self, unread_count: usize);
    fn clear(&self, row_id: i64);
    fn clear_all(&self);
}

/// Headless/fallback notifier used in unit tests and non-macOS/non-Windows environments.
#[derive(Default)]
pub struct NoopNotifier;

impl PlatformNotifier for NoopNotifier {
    fn show(&self, _notif: &OsNotification) {}
    fn show_summary(&self, _unread_count: usize) {}
    fn clear(&self, _row_id: i64) {}
    fn clear_all(&self) {}
}

pub fn create_platform_notifier(
    cache_dir: PathBuf,
    dismiss_tx: mpsc::UnboundedSender<DismissAction>,
) -> Box<dyn PlatformNotifier> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsNotifier::new(cache_dir, dismiss_tx))
    }
    #[cfg(target_os = "windows")]
    {
        let _ = cache_dir;
        Box::new(windows::WindowsNotifier::new(dismiss_tx))
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        let _ = (cache_dir, dismiss_tx);
        Box::new(NoopNotifier)
    }
}
