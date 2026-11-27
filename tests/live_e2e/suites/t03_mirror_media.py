"""T03: Real-time Mirror, macOS Native Delivery, Loop Guard, Noise Filters, Icon Cache & Image Attachment."""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from helpers import adb, macos
from helpers.report import SkipCheck, TestContext, wait_until


def run(ctx: TestContext) -> None:
    print("\n=== T03: Real-Time Mirror, Native macOS Delivery, Loop Guard, Filters & Media ===")

    if not ctx.phone_a:
        ctx.record(
            "T03.1",
            "mirror",
            "Mirror, loop guard, filters & media",
            lambda: (_ for _ in ()).throw(SkipCheck("Phone A not connected via ADB")),
        )
        return

    def check_basic_mirror():
        marker = f"AN-E2E-{ctx.run_id}-MIRROR"
        ctx.posted_markers.append(marker)
        tag = f"an_mirror_{ctx.run_id}"
        t_start_dt = datetime.now()
        t0 = time.monotonic()

        cp = adb.post_shell_notification(
            ctx.phone_a,
            tag=tag,
            title=f"Mirror Test {marker}",
            body=f"Live mirror payload {marker}",
        )
        assert cp.returncode == 0, f"cmd notification post failed: {cp.stderr or cp.stdout}"

        # 1. Wait for arrival in MacBook SQLite DB
        row = wait_until(
            lambda: (macos.query_notifications(contains=marker, limit=5) or [None])[0],
            timeout_sec=ctx.timeout_sec,
        )
        assert row is not None, f"notification {marker} did not arrive on MacBook within {ctx.timeout_sec}s"
        latency_ms = int((time.monotonic() - t0) * 1000)

        # 2. Verify icon cached on MacBook disk if icon_sha256 present
        icon_ok = False
        if row.icon_sha256:
            icon_file = macos.icon_cache_file(row.icon_sha256)
            icon_ok = icon_file.is_file() and icon_file.stat().st_size > 0
            assert icon_ok, f"icon_sha256={row.icon_sha256} set in DB, but cache file missing at {icon_file}"

        # 3. Verify macOS native UNUserNotificationCenter delivery (hasError: 0, no entitlement errors)
        time.sleep(0.8)
        mac_logs = macos.query_macos_notification_logs(t_start_dt)
        assert not mac_logs["entitlement_errors"], (
            f"macOS usernotificationsd entitlement error: {mac_logs['entitlement_errors'][0]}"
        )
        assert mac_logs["added_err"] == 0, (
            f"macOS UNUserNotificationCenter returned hasError: 1 ({mac_logs['added_err']} error(s))"
        )
        assert mac_logs["added_ok"] >= 1, (
            "notification reached Mac SQLite, but no UNUserNotificationCenter addNotificationRequest succeeded"
        )

        # 4. If Phone B connected, verify mirrored notification under com.allnotify.app
        phone_b_note = "Phone B skipped (not connected)"
        if ctx.phone_b:
            b_matches = wait_until(
                lambda: adb.find_notifications(ctx.phone_b, pkg=adb.ALLNOTIFY_PKG, contains=marker),
                timeout_sec=ctx.timeout_sec,
            )
            assert b_matches, f"mirrored notification {marker} did not appear on Phone B ({ctx.phone_b})"
            phone_b_note = f"Phone B mirrored OK (key={b_matches[0].key})"

        status = "PASS" if latency_ms <= 3000 else "WARN"
        return (
            status,
            f"Mac arrived in {latency_ms}ms (id={row.id}, icon_cached={icon_ok}, macOS banner OK); {phone_b_note}",
            {"latency_ms": latency_ms, "mac_row_id": row.id, "added_ok": mac_logs["added_ok"]},
        )

    ctx.record("T03.1", "mirror", "Phone A -> MacBook (native UNCenter) + Phone B real-time mirror", check_basic_mirror)

    def check_loop_guard():
        marker = f"AN-E2E-{ctx.run_id}-MIRROR"
        # Give any bogus echo 1.5s to show up
        time.sleep(1.5)
        echoes = adb.find_notifications(ctx.phone_a, pkg=adb.ALLNOTIFY_PKG, contains=marker)
        assert not echoes, f"LOOP BUG: Phone A mirrored its own notification back! {echoes[0].key}"
        return ("PASS", "Phone A has zero self-mirrored notifications under com.allnotify.app", {})

    ctx.record("T03.2", "mirror", "Anti-loop guard (Phone A never mirrors its own notifications)", check_loop_guard)

    def check_noise_filter():
        marker = f"AN-E2E-{ctx.run_id}-NOISE"
        ctx.posted_markers.append(marker)
        cp = adb.post_shell_notification(
            ctx.phone_a,
            tag=f"an_noise_{ctx.run_id}",
            title=f"Media Transport {marker}",
            body=f"Should be dropped {marker}",
            style="media",
        )
        assert cp.returncode == 0, f"cmd notification post (-S media) failed: {cp.stderr or cp.stdout}"
        # Prove it actually posted on Phone A before asserting All-Notify filtered it out.
        posted_on_a = wait_until(
            lambda: adb.find_notifications(ctx.phone_a, pkg="com.android.shell", contains=marker),
            timeout_sec=5.0,
        )
        assert posted_on_a, "media notification was not posted on Phone A"
        time.sleep(3.5)
        leaked_mac = macos.query_notifications(contains=marker, limit=5)
        assert not leaked_mac, f"CATEGORY_TRANSPORT/MediaStyle notification leaked to MacBook! row={leaked_mac[0].id}"
        if ctx.phone_b:
            leaked_b = adb.find_notifications(ctx.phone_b, pkg=adb.ALLNOTIFY_PKG, contains=marker)
            assert not leaked_b, "CATEGORY_TRANSPORT/MediaStyle notification leaked to Phone B!"
        return ("PASS", "MediaStyle/CATEGORY_TRANSPORT posted on Phone A and dropped by NotificationFilter", {})

    ctx.record("T03.3", "mirror", "Noise filter drops MediaStyle / CATEGORY_TRANSPORT notifications", check_noise_filter)

    def check_image_attachment():
        marker = f"AN-E2E-{ctx.run_id}-IMG"
        ctx.posted_markers.append(marker)
        cp = adb.post_shell_notification(
            ctx.phone_a,
            tag=f"an_img_{ctx.run_id}",
            title=f"Photo Test {marker}",
            body=f"BigPicture payload {marker}",
            style="bigpicture",
        )
        assert cp.returncode == 0, f"BigPicture post failed: {cp.stderr or cp.stdout}"

        row = wait_until(
            lambda: (macos.query_notifications(contains=marker, limit=5) or [None])[0],
            timeout_sec=ctx.timeout_sec,
        )
        assert row is not None, f"image notification {marker} did not arrive on MacBook"
        assert row.attachment_path, (
            f"notification arrived (id={row.id}) but attachment_path is NULL "
            "(OEM shell cmd may not have attached EXTRA_PICTURE)"
        )
        att_file = Path(row.attachment_path)
        assert att_file.is_file() and att_file.stat().st_size > 0, (
            f"decrypted attachment file missing or empty: {att_file}"
        )
        size_kb = round(att_file.stat().st_size / 1024, 1)
        b_note = ""
        if ctx.phone_b:
            b_matches = wait_until(
                lambda: adb.find_notifications(ctx.phone_b, pkg=adb.ALLNOTIFY_PKG, contains=marker),
                timeout_sec=ctx.timeout_sec,
            )
            assert b_matches, f"image notification {marker} did not arrive on Phone B"
            b_note = f"; Phone B mirrored (has_picture={b_matches[0].has_picture})"
        return (
            "PASS",
            f"Mac decrypted attachment saved ({size_kb} KB, mime={row.attachment_mime}){b_note}",
            {"attachment_path": str(att_file), "size_bytes": att_file.stat().st_size},
        )

    ctx.record("T03.4", "mirror", "BigPicture image attachment E2EE upload & decryption", check_image_attachment)
