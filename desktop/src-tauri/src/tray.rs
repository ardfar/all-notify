use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, PhysicalPosition, Rect,
};

use crate::sync::ConnectionStatus;

pub const TRAY_ID: &str = "all-notify-tray";
pub const MENU_OPEN: &str = "open";
pub const MENU_TOGGLE_MUTE: &str = "toggle_mute";
pub const MENU_CLEAR_ALL: &str = "clear_all";
pub const MENU_QUIT: &str = "quit";

const ICON_CONNECTED: &[u8] = include_bytes!("../icons/tray_connected.png");
const ICON_UNREAD: &[u8] = include_bytes!("../icons/tray_unread.png");
const ICON_MUTED: &[u8] = include_bytes!("../icons/tray_muted.png");
const ICON_DISCONNECTED: &[u8] = include_bytes!("../icons/tray_disconnected.png");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayVisualState {
    Connected,
    Unread,
    Muted,
    Disconnected,
}

pub fn resolve_visual_state(
    status: ConnectionStatus,
    unread_count: usize,
    muted: bool,
) -> TrayVisualState {
    if status == ConnectionStatus::Unauthorized {
        TrayVisualState::Disconnected
    } else if muted {
        TrayVisualState::Muted
    } else if status != ConnectionStatus::Connected {
        TrayVisualState::Disconnected
    } else if unread_count > 0 {
        TrayVisualState::Unread
    } else {
        TrayVisualState::Connected
    }
}

fn icon_bytes(state: TrayVisualState) -> &'static [u8] {
    match state {
        TrayVisualState::Connected => ICON_CONNECTED,
        TrayVisualState::Unread => ICON_UNREAD,
        TrayVisualState::Muted => ICON_MUTED,
        TrayVisualState::Disconnected => ICON_DISCONNECTED,
    }
}

pub fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let open_item = MenuItem::with_id(app, MENU_OPEN, "Open All-Notify", true, None::<&str>)?;
    let mute_item = MenuItem::with_id(
        app,
        MENU_TOGGLE_MUTE,
        "Toggle Pause / Mute",
        true,
        None::<&str>,
    )?;
    let clear_item = MenuItem::with_id(
        app,
        MENU_CLEAR_ALL,
        "Dismiss All Active",
        true,
        None::<&str>,
    )?;
    let quit_item = MenuItem::with_id(app, MENU_QUIT, "Quit All-Notify", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open_item, &mute_item, &clear_item, &quit_item])?;

    let initial_icon = Image::from_bytes(ICON_DISCONNECTED)?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(initial_icon)
        .tooltip("All-Notify")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            MENU_OPEN => toggle_popover(app, None, true),
            MENU_TOGGLE_MUTE => crate::toggle_mute_from_tray(app),
            MENU_CLEAR_ALL => crate::dismiss_all_from_tray(app),
            MENU_QUIT => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                rect,
                ..
            } = event
            {
                toggle_popover(tray.app_handle(), Some(rect), false);
            }
        })
        .build(app)?;

    Ok(())
}

pub fn update_tray(
    app: &AppHandle,
    status: ConnectionStatus,
    unread_count: usize,
    muted: bool,
) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let state = resolve_visual_state(status, unread_count, muted);
    if let Ok(img) = Image::from_bytes(icon_bytes(state)) {
        let _ = tray.set_icon(Some(img));
    }
    let status_label = match (status, muted) {
        (ConnectionStatus::Unauthorized, _) => "Access revoked — re-pair required".to_string(),
        (_, true) => "Paused / Muted".to_string(),
        (ConnectionStatus::Connected, false) if unread_count > 0 => {
            format!("Connected • {unread_count} unread")
        }
        (ConnectionStatus::Connected, false) => "Connected".to_string(),
        (ConnectionStatus::Connecting, false) => "Connecting...".to_string(),
        (ConnectionStatus::Reconnecting, false) => "Reconnecting...".to_string(),
        (ConnectionStatus::Unpaired, false) => "Not paired".to_string(),
        (ConnectionStatus::Disconnected, false) => "Disconnected".to_string(),
    };
    let _ = tray.set_tooltip(Some(format!("All-Notify — {status_label}")));
}

pub fn toggle_popover(app: &AppHandle, tray_rect: Option<Rect>, force_show: bool) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let is_visible = window.is_visible().unwrap_or(false);
    if is_visible && !force_show {
        let _ = window.hide();
        return;
    }
    // On macOS/Windows, clicking the tray icon while the popover is visible first fires
    // WindowEvent::Focused(false) (which hides the popover) and milliseconds later fires
    // TrayIconEvent::Click(Up). Suppress immediate re-open so tray click cleanly toggles closed.
    if !force_show && crate::was_recently_hidden_by_blur(app) {
        return;
    }

    if let Some(rect) = tray_rect {
        position_window_near_tray(&window, rect);
    }
    crate::sync_content_protection_before_show(app, &window);
    let _ = window.show();
    let _ = window.set_focus();
}

fn find_monitor_for_tray(window: &tauri::WebviewWindow, rect: &Rect) -> Option<tauri::Monitor> {
    if let Ok(monitors) = window.available_monitors() {
        for monitor in monitors {
            let mon_scale = monitor.scale_factor();
            let (tx, ty) = match rect.position {
                tauri::Position::Physical(p) => (p.x, p.y),
                tauri::Position::Logical(l) => ((l.x * mon_scale) as i32, (l.y * mon_scale) as i32),
            };
            let pos = monitor.position();
            let size = monitor.size();
            let in_x = tx >= pos.x && tx < pos.x + size.width as i32;
            let in_y = ty >= pos.y && ty < pos.y + size.height as i32;
            if in_x && in_y {
                return Some(monitor);
            }
        }
    }
    window
        .current_monitor()
        .ok()
        .flatten()
        .or_else(|| window.primary_monitor().ok().flatten())
}

fn position_window_near_tray(window: &tauri::WebviewWindow, rect: Rect) {
    let monitor = find_monitor_for_tray(window, &rect);
    let scale = monitor
        .as_ref()
        .map(|m| m.scale_factor())
        .or_else(|| window.scale_factor().ok())
        .unwrap_or(1.0);
    let win_size = window
        .outer_size()
        .unwrap_or(tauri::PhysicalSize::new((380.0 * scale) as u32, (540.0 * scale) as u32));

    let (tray_x, tray_y) = match rect.position {
        tauri::Position::Physical(p) => (p.x, p.y),
        tauri::Position::Logical(l) => ((l.x * scale) as i32, (l.y * scale) as i32),
    };
    let (tray_w, tray_h) = match rect.size {
        tauri::Size::Physical(s) => (s.width as i32, s.height as i32),
        tauri::Size::Logical(l) => ((l.width * scale) as i32, (l.height * scale) as i32),
    };

    let mut x = tray_x + (tray_w / 2) - (win_size.width as i32 / 2);
    let mut y = tray_y + tray_h + (6.0 * scale) as i32;

    if let Some(monitor) = monitor {
        let mon_pos = monitor.position();
        let mon_size = monitor.size();
        let min_x = mon_pos.x + (8.0 * scale) as i32;
        let max_x = mon_pos.x + mon_size.width as i32 - win_size.width as i32 - (8.0 * scale) as i32;
        let min_y = mon_pos.y + (8.0 * scale) as i32;
        let max_y = mon_pos.y + mon_size.height as i32 - win_size.height as i32 - (8.0 * scale) as i32;

        // On Windows bottom taskbar, tray_y is near the bottom; flip popover above the taskbar.
        if y > max_y {
            y = tray_y - win_size.height as i32 - (6.0 * scale) as i32;
        }
        x = x.clamp(min_x, max_x.max(min_x));
        y = y.clamp(min_y, max_y.max(min_y));
    }

    let _ = window.set_position(PhysicalPosition::new(x, y));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_visual_state_priority() {
        assert_eq!(
            resolve_visual_state(ConnectionStatus::Connected, 5, true),
            TrayVisualState::Muted
        );
        assert_eq!(
            resolve_visual_state(ConnectionStatus::Reconnecting, 5, false),
            TrayVisualState::Disconnected
        );
        assert_eq!(
            resolve_visual_state(ConnectionStatus::Connected, 2, false),
            TrayVisualState::Unread
        );
        assert_eq!(
            resolve_visual_state(ConnectionStatus::Connected, 0, false),
            TrayVisualState::Connected
        );
        assert_eq!(
            resolve_visual_state(ConnectionStatus::Unauthorized, 0, true),
            TrayVisualState::Disconnected
        );
    }
}
