"""T01: Preflight checks across VPS, MacBook, Phone A, and Phone B."""

from __future__ import annotations

from helpers import adb, admin_api, macos
from helpers.report import SkipCheck, TestContext


def run(ctx: TestContext) -> None:
    print("\n=== T01: Preflight Health Checks ===")

    def check_vps_health():
        resp = admin_api.http_request("GET", f"{ctx.server_url}/healthz")
        assert resp.status == 200, f"expected 200 from /healthz, got {resp.status}: {resp.body}"
        data = resp.json()
        assert data.get("status") == "ok", f"unexpected /healthz body: {data}"
        return ("PASS", f"GET {ctx.server_url}/healthz -> 200 ok", {"status": resp.status})

    ctx.record("T01.1", "preflight", "VPS /healthz reachable", check_vps_health)

    def check_mac_codesign():
        cs = macos.check_codesign()
        assert cs["exists"], f"missing {macos.MAC_APP_PATH}"
        assert cs["valid"], f"codesign verify failed: {cs.get('verify_stderr')}"
        assert cs["identifier"] == macos.MAC_BUNDLE_ID, (
            f"codesign Identifier={cs['identifier']!r}, expected {macos.MAC_BUNDLE_ID!r} "
            "(linker-signed bundles are rejected by macOS usernotificationsd)"
        )
        assert cs["info_plist_bound"], "Info.plist is not bound in code signature"
        return (
            "PASS",
            f"signed OK (Identifier={cs['identifier']}, Info.plist entries={cs['info_plist_entries']})",
            cs,
        )

    ctx.record("T01.2", "preflight", "MacBook All-Notify.app code signature", check_mac_codesign)

    def check_mac_runtime():
        running, pids = macos.is_desktop_running()
        assert running, "all-notify-desktop is not running; open /Applications/All-Notify.app first"
        meta = macos.read_pairing_meta()
        assert meta and meta.get("device_id"), "MacBook pairing.json missing or unpaired"
        ctx.meta["mac_device_id"] = meta["device_id"]
        ctx.meta["mac_device_name"] = meta.get("device_name", "")
        kv = macos.get_kv_state()
        muted = kv.get("muted", "0") in ("1", "true", "True")
        assert not muted, "MacBook All-Notify is currently Muted — unmute in tray popover before testing"
        nc = macos.check_macos_notification_permission_prefs()
        warn_note = "" if nc.get("found") else " (not yet in ncprefs.plist; verify Allow Notifications ON)"
        return (
            "PASS" if nc.get("found") else "WARN",
            f"running pid={pids[0]}, device={meta.get('device_name')} ({meta['device_id']}){warn_note}",
            {"pids": pids, "ncprefs": nc},
        )

    ctx.record("T01.3", "preflight", "MacBook app running, paired, unmuted, notifications registered", check_mac_runtime)

    def _check_phone(label: str, serial: str | None):
        if not serial:
            raise SkipCheck(f"{label} not connected via ADB")
        h = adb.get_device_health(serial)
        assert h["installed"], f"{adb.ALLNOTIFY_PKG} not installed on {label} ({serial})"
        assert h["listener_enabled"], (
            f"Notification Access not enabled for {adb.ALLNOTIFY_PKG} on {label} ({serial})"
        )
        assert h["listener_bound"], (
            f"AllNotifyListenerService is enabled but NOT bound by Android on {label} ({serial}) "
            "(OEM battery saver likely unbound it; needs requestRebind or toggling Notification Access)"
        )
        assert h["foreground_service_running"], (
            f"RelayForegroundService not running on {label} ({serial}) — open All-Notify app once"
        )
        assert h["post_notifications_granted"], (
            f"POST_NOTIFICATIONS permission not granted on {label} ({serial})"
        )
        dnd_on = h.get("zen_mode", 0) != 0
        status = "PASS" if (h["battery_unrestricted"] and not dnd_on) else "WARN"
        batt_note = "battery unrestricted" if h["battery_unrestricted"] else "battery optimization NOT whitelisted"
        dnd_note = "; DND ON (mirrored popups suppressed by design)" if dnd_on else ""
        return (
            status,
            f"{serial}: listener={'bound' if h['listener_bound'] else 'enabled'}, FGS running, {batt_note}{dnd_note}",
            h,
        )

    ctx.record("T01.4", "preflight", "Phone A ADB & All-Notify health", lambda: _check_phone("Phone A", ctx.phone_a))
    ctx.record("T01.5", "preflight", "Phone B ADB & All-Notify health", lambda: _check_phone("Phone B", ctx.phone_b))
