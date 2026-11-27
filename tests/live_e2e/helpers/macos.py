"""macOS helpers for verifying the live All-Notify.app, SQLite WAL DB, caches, and usernotificationsd."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

MAC_APP_PATH = Path("/Applications/All-Notify.app")
MAC_BUNDLE_ID = "com.allnotify.desktop"
MAC_DATA_DIR = Path.home() / "Library" / "Application Support" / MAC_BUNDLE_ID
MAC_CACHE_DIR = Path.home() / "Library" / "Caches" / MAC_BUNDLE_ID
MAC_DB_PATH = MAC_DATA_DIR / "all-notify.db"
MAC_PAIRING_JSON = MAC_DATA_DIR / "pairing.json"


@dataclass
class DesktopNotifRow:
    id: int
    notification_uids: list[str]
    sender_devices: list[str]
    sender_device_ids: list[str]
    package_name: str
    app_name: str
    icon_sha256: str | None
    title: str
    body: str
    attachment_path: str | None
    attachment_mime: str | None
    posted_at: int
    dismissed_at: int | None


def read_pairing_meta() -> dict | None:
    if not MAC_PAIRING_JSON.is_file():
        return None
    return json.loads(MAC_PAIRING_JSON.read_text(encoding="utf-8"))


def check_codesign(app_path: Path = MAC_APP_PATH) -> dict:
    if not app_path.exists():
        return {"exists": False, "valid": False, "error": f"{app_path} does not exist"}
    verify = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app_path)],
        capture_output=True,
        text=True,
    )
    info = subprocess.run(
        ["codesign", "-dv", "--verbose=4", str(app_path)],
        capture_output=True,
        text=True,
    )
    combined = info.stdout + "\n" + info.stderr
    ident_m = re.search(r"Identifier=([^\s]+)", combined)
    plist_m = re.search(r"Info\.plist entries=(\d+)", combined)
    return {
        "exists": True,
        "valid": verify.returncode == 0,
        "identifier": ident_m.group(1) if ident_m else "",
        "info_plist_bound": plist_m is not None,
        "info_plist_entries": int(plist_m.group(1)) if plist_m else 0,
        "verify_stderr": verify.stderr.strip(),
    }


def is_desktop_running() -> tuple[bool, list[int]]:
    cp = subprocess.run(["pgrep", "-x", "all-notify-desktop"], capture_output=True, text=True)
    pids = [int(x) for x in cp.stdout.split() if x.isdigit()]
    return bool(pids), pids


def stop_desktop_app() -> None:
    subprocess.run(["pkill", "-x", "all-notify-desktop"], capture_output=True)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        running, _ = is_desktop_running()
        if not running:
            return
        time.sleep(0.2)


def start_desktop_app(app_path: Path = MAC_APP_PATH) -> None:
    subprocess.run(["open", str(app_path)], check=True)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        running, _ = is_desktop_running()
        if running:
            time.sleep(1.5)  # allow WebSocket handshake & replay
            return
        time.sleep(0.25)
    raise RuntimeError("All-Notify.app did not start within 10s")


def _open_db_ro() -> sqlite3.Connection:
    if not MAC_DB_PATH.is_file():
        raise FileNotFoundError(f"Desktop DB not found: {MAC_DB_PATH}")
    uri = f"file:{MAC_DB_PATH}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def get_kv_state() -> dict[str, str]:
    with _open_db_ro() as conn:
        rows = conn.execute("SELECT key, value FROM kv_state").fetchall()
        return {r["key"]: r["value"] for r in rows}


def query_notifications(
    *,
    contains: str | None = None,
    since_ms: int | None = None,
    limit: int = 50,
) -> list[DesktopNotifRow]:
    clauses: list[str] = []
    params: list[object] = []
    if contains:
        clauses.append("(title LIKE ? OR body LIKE ?)")
        like = f"%{contains}%"
        params.extend([like, like])
    if since_ms is not None:
        clauses.append("posted_at >= ?")
        params.append(since_ms)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
        SELECT id, notification_uids_json, sender_devices_json, sender_device_ids_json,
               package_name, app_name, icon_sha256, title, body,
               attachment_path, attachment_mime, posted_at, dismissed_at
        FROM notifications
        {where}
        ORDER BY id DESC
        LIMIT ?
    """
    params.append(limit)
    with _open_db_ro() as conn:
        rows = conn.execute(sql, params).fetchall()

    out: list[DesktopNotifRow] = []
    for r in rows:
        out.append(
            DesktopNotifRow(
                id=r["id"],
                notification_uids=json.loads(r["notification_uids_json"]),
                sender_devices=json.loads(r["sender_devices_json"]),
                sender_device_ids=json.loads(r["sender_device_ids_json"]),
                package_name=r["package_name"],
                app_name=r["app_name"],
                icon_sha256=r["icon_sha256"],
                title=r["title"],
                body=r["body"],
                attachment_path=r["attachment_path"],
                attachment_mime=r["attachment_mime"],
                posted_at=r["posted_at"],
                dismissed_at=r["dismissed_at"],
            )
        )
    return out


def get_row_by_id(row_id: int) -> DesktopNotifRow | None:
    with _open_db_ro() as conn:
        r = conn.execute(
            """
            SELECT id, notification_uids_json, sender_devices_json, sender_device_ids_json,
                   package_name, app_name, icon_sha256, title, body,
                   attachment_path, attachment_mime, posted_at, dismissed_at
            FROM notifications WHERE id = ?
            """,
            (row_id,),
        ).fetchone()
    if not r:
        return None
    return DesktopNotifRow(
        id=r["id"],
        notification_uids=json.loads(r["notification_uids_json"]),
        sender_devices=json.loads(r["sender_devices_json"]),
        sender_device_ids=json.loads(r["sender_device_ids_json"]),
        package_name=r["package_name"],
        app_name=r["app_name"],
        icon_sha256=r["icon_sha256"],
        title=r["title"],
        body=r["body"],
        attachment_path=r["attachment_path"],
        attachment_mime=r["attachment_mime"],
        posted_at=r["posted_at"],
        dismissed_at=r["dismissed_at"],
    )


def icon_cache_file(sha256: str) -> Path:
    return MAC_CACHE_DIR / "icons" / f"{sha256}.webp"


def query_macos_notification_logs(start_dt: datetime) -> dict:
    """Query macOS unified log since `start_dt` for All-Notify UNUserNotificationCenter activity."""
    start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    predicate = (
        'process == "all-notify-desktop" OR '
        '(process == "usernotificationsd" AND eventMessage CONTAINS[c] "com.allnotify.desktop")'
    )
    cp = subprocess.run(
        ["/usr/bin/log", "show", "--start", start_str, "--predicate", predicate, "--info"],
        capture_output=True,
        text=True,
        timeout=20.0,
    )
    lines = cp.stdout.splitlines()
    added_ok = 0
    added_err = 0
    removed = 0
    entitlement_errors: list[str] = []
    add_lines: list[str] = []
    for line in lines:
        if "Added notification request: [ hasError: 0" in line:
            added_ok += 1
            add_lines.append(line)
        elif "Added notification request: [ hasError: 1" in line:
            added_err += 1
            add_lines.append(line)
        elif "Removing delivered notifications" in line or "removeDeliveredNotifications" in line:
            removed += 1
        elif "Entitlement" in line and "required" in line:
            entitlement_errors.append(line)
    return {
        "added_ok": added_ok,
        "added_err": added_err,
        "removed": removed,
        "entitlement_errors": entitlement_errors,
        "raw_lines_count": len(lines),
        "raw_stdout": cp.stdout,
    }


def check_macos_notification_permission_prefs() -> dict:
    """Inspect ~/Library/Preferences/com.apple.ncprefs.plist for com.allnotify.desktop flags."""
    import plistlib

    p = Path.home() / "Library" / "Preferences" / "com.apple.ncprefs.plist"
    if not p.is_file():
        return {"found": False}
    data = plistlib.loads(p.read_bytes())
    for app in data.get("apps", []):
        if app.get("bundle-id") == MAC_BUNDLE_ID:
            return {
                "found": True,
                "flags": app.get("flags"),
                "auth": app.get("auth"),
                "content_visibility": app.get("content_visibility"),
            }
    return {"found": False}
