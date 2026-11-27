"""ADB helpers for controlling and inspecting physical Android phones."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass
from pathlib import Path

ALLNOTIFY_PKG = "com.allnotify.app"
LISTENER_COMPONENT = f"{ALLNOTIFY_PKG}/{ALLNOTIFY_PKG}.service.AllNotifyListenerService"


@dataclass
class AdbDevice:
    serial: str
    state: str
    model: str
    android_release: str = ""
    sdk_int: int = 0


@dataclass
class AndroidNotification:
    key: str
    pkg: str
    title: str
    text: str
    sub_text: str
    has_picture: bool
    raw_block: str


def find_adb() -> str:
    candidates = [
        shutil.which("adb"),
        os.path.expanduser("~/Library/Android/sdk/platform-tools/adb"),
        "/opt/homebrew/bin/adb",
        "/usr/local/bin/adb",
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise FileNotFoundError(
        "adb not found in PATH or ~/Library/Android/sdk/platform-tools/adb"
    )


def run_adb(
    serial: str | None,
    args: list[str],
    *,
    timeout: float = 15.0,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    adb = find_adb()
    cmd = [adb]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def list_devices() -> list[AdbDevice]:
    cp = run_adb(None, ["devices", "-l"], check=True)
    devices: list[AdbDevice] = []
    for line in cp.stdout.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        model = ""
        for tok in parts[2:]:
            if tok.startswith("model:"):
                model = tok.split(":", 1)[1]
        dev = AdbDevice(serial=serial, state=state, model=model or serial)
        if state == "device":
            rel = run_adb(serial, ["shell", "getprop", "ro.build.version.release"], check=False)
            sdk = run_adb(serial, ["shell", "getprop", "ro.build.version.sdk"], check=False)
            dev.android_release = rel.stdout.strip()
            try:
                dev.sdk_int = int(sdk.stdout.strip())
            except ValueError:
                dev.sdk_int = 0
        devices.append(dev)
    return devices


def get_device_health(serial: str) -> dict:
    """Inspect All-Notify installation, notification listener, battery exemption, and services."""
    pkg_cp = run_adb(serial, ["shell", "pm", "path", ALLNOTIFY_PKG], check=False)
    installed = pkg_cp.returncode == 0 and "package:" in pkg_cp.stdout

    listeners_cp = run_adb(
        serial, ["shell", "settings", "get", "secure", "enabled_notification_listeners"], check=False
    )
    listener_enabled = (
        ALLNOTIFY_PKG in listeners_cp.stdout
        and "AllNotifyListenerService" in listeners_cp.stdout
    )

    svc_cp = run_adb(serial, ["shell", "dumpsys", "activity", "services", ALLNOTIFY_PKG], check=False)
    foreground_running = "RelayForegroundService" in svc_cp.stdout
    listener_bound = "AllNotifyListenerService" in svc_cp.stdout

    batt_cp = run_adb(serial, ["shell", "dumpsys", "deviceidle", "whitelist"], check=False)
    battery_unrestricted = ALLNOTIFY_PKG in batt_cp.stdout

    post_perm_cp = run_adb(
        serial,
        ["shell", "dumpsys", "package", ALLNOTIFY_PKG],
        check=False,
    )
    post_notif_granted = (
        "android.permission.POST_NOTIFICATIONS: granted=true" in post_perm_cp.stdout
    )

    zen_cp = run_adb(serial, ["shell", "settings", "get", "global", "zen_mode"], check=False)
    try:
        zen_mode = int(zen_cp.stdout.strip())
    except ValueError:
        zen_mode = 0

    return {
        "installed": installed,
        "listener_enabled": listener_enabled,
        "listener_bound": listener_bound,
        "foreground_service_running": foreground_running,
        "battery_unrestricted": battery_unrestricted,
        "post_notifications_granted": post_notif_granted,
        "zen_mode": zen_mode,
    }


def wake_device(serial: str) -> None:
    run_adb(serial, ["shell", "input", "keyevent", "KEYCODE_WAKEUP"], check=False)


def dump_notifications(serial: str) -> list[AndroidNotification]:
    """Parse active notifications from `dumpsys notification --noredact`."""
    cp = run_adb(serial, ["shell", "dumpsys", "notification", "--noredact"], timeout=20.0, check=True)
    text = cp.stdout
    # Split on NotificationRecord( entries
    blocks = re.split(r"(?=\s*NotificationRecord\()", text)
    records: list[AndroidNotification] = []
    for blk in blocks[1:]:
        m_hdr = re.search(r"NotificationRecord\([^)]*pkg=([^\s]+).*?key=([^\s)]+)", blk)
        if not m_hdr:
            continue
        pkg = m_hdr.group(1)
        key = m_hdr.group(2)

        def _extract_extra(name: str) -> str:
            # Matches lines like: android.title=String (Hello World) or SpannableString (...)
            pat = rf"{re.escape(name)}=[^\n(]*\(([^\n]*)\)"
            m = re.search(pat, blk)
            return m.group(1).strip() if m else ""

        title = _extract_extra("android.title")
        body = _extract_extra("android.bigText") or _extract_extra("android.text")
        sub_text = _extract_extra("android.subText")
        has_picture = "android.picture=" in blk and "android.picture=null" not in blk
        records.append(
            AndroidNotification(
                key=key,
                pkg=pkg,
                title=title,
                text=body,
                sub_text=sub_text,
                has_picture=has_picture,
                raw_block=blk,
            )
        )
    return records


def find_notifications(
    serial: str,
    *,
    pkg: str | None = None,
    contains: str | None = None,
) -> list[AndroidNotification]:
    out = []
    for n in dump_notifications(serial):
        if pkg and n.pkg != pkg:
            continue
        if contains:
            hay = f"{n.title}\n{n.text}\n{n.sub_text}"
            if contains not in hay:
                continue
        out.append(n)
    return out


def post_shell_notification(
    serial: str,
    *,
    tag: str,
    title: str,
    body: str,
    style: str = "bigtext",
    big_picture_png: bytes | None = None,
) -> subprocess.CompletedProcess[str]:
    """Post a real Android OS notification via `cmd notification post` (owned by com.android.shell)."""
    import base64

    parts = ["cmd", "notification", "post"]
    if style == "bigpicture":
        png = big_picture_png or _make_solid_png(128, 96)
        b64 = base64.b64encode(png).decode("ascii")
        parts.extend(["-S", "bigpicture", "--picture", f"data:base64,{b64}"])
    elif style == "media":
        parts.extend(["-S", "media"])
    else:
        parts.extend(["-S", "bigtext"])
    parts.extend(["-t", title, tag, body])
    # adb shell concatenates args with spaces before invoking /system/bin/sh, so quote each token.
    shell_cmd = " ".join(shlex.quote(p) for p in parts)
    cp = run_adb(serial, ["shell", shell_cmd], check=False)
    combined = (cp.stdout or "") + "\n" + (cp.stderr or "")
    if cp.returncode == 0 and ("Error occurred" in combined or "usage: cmd notification" in combined):
        return subprocess.CompletedProcess(cp.args, 1, cp.stdout, combined.strip())
    return cp


def _make_solid_png(width: int = 320, height: int = 240, rgb: tuple[int, int, int] = (37, 99, 235)) -> bytes:
    """Create a valid RGB PNG purely with stdlib zlib (zero external image deps)."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    row = b"\x00" + bytes(rgb) * width
    idat = zlib.compress(row * height, level=6)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def push_test_png(serial: str, remote_path: str = "/data/local/tmp/allnotify_e2e_test.png") -> str:
    """Generate a test PNG and push it to the device with world-readable perms."""
    png_bytes = _make_solid_png()
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
        tf.write(png_bytes)
        local_path = tf.name
    try:
        run_adb(serial, ["push", local_path, remote_path], check=True)
        run_adb(serial, ["shell", "chmod", "644", remote_path], check=False)
    finally:
        Path(local_path).unlink(missing_ok=True)
    return remote_path


def _screen_width(serial: str) -> int:
    cp = run_adb(serial, ["shell", "wm", "size"], check=False)
    m = re.search(r"(\d+)x(\d+)", cp.stdout)
    return int(m.group(1)) if m else 1080


def dismiss_notification_via_shade(
    serial: str,
    match_text: str,
    *,
    pkg: str | None = None,
) -> tuple[bool, str]:
    """Expand Android notification shade, locate notification containing `match_text`, swipe it away,
    and verify via `dumpsys notification` that it was actually removed."""
    wake_device(serial)
    width = _screen_width(serial)
    run_adb(serial, ["shell", "cmd", "statusbar", "expand-notifications"], check=False)
    time.sleep(0.8)

    try:
        def _dump_root():
            dump_cp = run_adb(serial, ["shell", "uiautomator", "dump", "/sdcard/an_ui.xml"], timeout=15.0, check=False)
            if dump_cp.returncode != 0:
                return None, f"uiautomator dump failed: {dump_cp.stderr.strip() or dump_cp.stdout.strip()}"
            xml_cp = run_adb(serial, ["shell", "cat", "/sdcard/an_ui.xml"], timeout=10.0, check=False)
            run_adb(serial, ["shell", "rm", "-f", "/sdcard/an_ui.xml"], check=False)
            if not xml_cp.stdout.strip():
                return None, "empty uiautomator XML"
            return ET.fromstring(xml_cp.stdout), ""

        def _find_bounds(root, needle: str) -> str | None:
            for node in root.iter("node"):
                txt = node.attrib.get("text", "")
                desc = node.attrib.get("content-desc", "")
                if needle in txt or needle in desc:
                    return node.attrib.get("bounds")
            return None

        def _expand_group(root, group_label: str) -> bool:
            gb = _find_bounds(root, group_label)
            if not gb:
                return False
            gm = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", gb)
            if not gm:
                return False
            gx1, gy1, gx2, gy2 = map(int, gm.groups())
            cx = (gx1 + gx2) // 2
            cy = (gy1 + gy2) // 2
            # Tap right-side expand chevron or drag down slightly to expand grouped notifications
            run_adb(
                serial,
                ["shell", "input", "swipe", str(cx), str(cy), str(cx), str(gy2 + 320), "250"],
                check=False,
            )
            time.sleep(0.5)
            return True

        def _still_present() -> bool:
            return len(find_notifications(serial, pkg=pkg, contains=match_text)) > 0

        for attempt in range(3):
            root, err = _dump_root()
            if root is None:
                return False, err
            bounds_str = _find_bounds(root, match_text)
            if not bounds_str:
                # Expand grouped Shell or All-Notify bundles if collapsed
                expanded = _expand_group(root, "Shell") or _expand_group(root, "All-Notify")
                if expanded:
                    root2, _ = _dump_root()
                    if root2 is not None:
                        bounds_str = _find_bounds(root2, match_text)
            if not bounds_str:
                return False, f"text '{match_text}' not visible in notification shade (is phone unlocked?)"

            m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds_str)
            if not m:
                return False, f"unparseable bounds: {bounds_str}"
            _x1, y1, _x2, y2 = map(int, m.groups())
            cy = (y1 + y2) // 2
            # Swipe cleanly across 12% -> 92% of screen width (or reverse on retry)
            if attempt % 2 == 0:
                sx, ex = int(width * 0.15), int(width * 0.92)
            else:
                sx, ex = int(width * 0.85), int(width * 0.08)
            run_adb(serial, ["shell", "input", "swipe", str(sx), str(cy), str(ex), str(cy), "220"], check=True)
            time.sleep(0.8)
            if not _still_present():
                return True, f"swiped node at y={cy} ({sx}->{ex}, attempt={attempt + 1})"

        return False, f"swiped '{match_text}' 3 times but notification remained active in dumpsys"
    finally:
        run_adb(serial, ["shell", "cmd", "statusbar", "collapse"], check=False)


def check_logcat_for_leaks(serial: str, forbidden_substrings: list[str], lines: int = 800) -> list[str]:
    """Scan recent All-Notify logcat lines for any forbidden plaintext or secrets."""
    cp = run_adb(serial, ["logcat", "-d", "-t", str(lines)], timeout=15.0, check=False)
    hits: list[str] = []
    for line in cp.stdout.splitlines():
        if ALLNOTIFY_PKG not in line and "AllNotify" not in line and "Relay" not in line:
            continue
        for sub in forbidden_substrings:
            if sub and sub in line:
                hits.append(f"matched forbidden token len={len(sub)}")
    return hits
