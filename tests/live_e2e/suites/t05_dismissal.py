"""T05: Two-Way Dismissal Sync across Phone A, Phone B, and MacBook."""

from __future__ import annotations

import time
from datetime import datetime

from helpers import adb, macos
from helpers.report import SkipCheck, TestContext, wait_until


def _dismiss_on_phone(ctx: TestContext, serial: str, label: str, marker: str) -> str:
    ok, detail = adb.dismiss_notification_via_shade(serial, marker)
    if ok:
        return detail
    if ctx.interactive:
        input(
            f"\n    [Action needed on {label} ({serial})]: "
            f"Auto-swipe could not locate '{marker}' ({detail}).\n"
            f"    Please swipe away '{marker}' on {label}, then press Enter..."
        )
        return "dismissed interactively by user"
    raise AssertionError(f"could not auto-dismiss '{marker}' on {label}: {detail} (unlock screen or pass --interactive)")


def run(ctx: TestContext) -> None:
    print("\n=== T05: Two-Way Dismissal Sync ===")

    if not ctx.phone_a:
        ctx.record(
            "T05.1",
            "dismissal",
            "Two-way dismissal sync",
            lambda: (_ for _ in ()).throw(SkipCheck("Phone A not connected via ADB")),
        )
        return

    def check_dismiss_from_phone_a():
        marker = f"AN-E2E-{ctx.run_id}-DISMA"
        ctx.posted_markers.append(marker)
        cp = adb.post_shell_notification(
            ctx.phone_a,
            tag=f"an_disma_{ctx.run_id}",
            title=f"Dismiss A {marker}",
            body=f"Swipe on Phone A {marker}",
        )
        assert cp.returncode == 0, f"post failed: {cp.stderr}"

        mac_row = wait_until(
            lambda: (macos.query_notifications(contains=marker, limit=5) or [None])[0],
            timeout_sec=ctx.timeout_sec,
        )
        assert mac_row is not None, f"{marker} did not arrive on MacBook"
        if ctx.phone_b:
            b_arrived = wait_until(
                lambda: adb.find_notifications(ctx.phone_b, pkg=adb.ALLNOTIFY_PKG, contains=marker),
                timeout_sec=ctx.timeout_sec,
            )
            assert b_arrived, f"{marker} did not arrive on Phone B before dismissal"

        t_dismiss = datetime.now()
        swipe_info = _dismiss_on_phone(ctx, ctx.phone_a, "Phone A", marker)

        # Verify MacBook marks row dismissed
        dismissed_mac = wait_until(
            lambda: (
                r if (r := macos.get_row_by_id(mac_row.id)) and r.dismissed_at is not None else None
            ),
            timeout_sec=ctx.timeout_sec,
        )
        assert dismissed_mac is not None, f"MacBook row {mac_row.id} was not marked dismissed after Phone A swipe"

        b_note = "Phone B skipped"
        if ctx.phone_b:
            b_cleared = wait_until(
                lambda: len(adb.find_notifications(ctx.phone_b, pkg=adb.ALLNOTIFY_PKG, contains=marker)) == 0,
                timeout_sec=ctx.timeout_sec,
            )
            assert b_cleared, f"Phone B mirrored notification {marker} did not clear after Phone A swipe"
            b_note = "Phone B cleared OK"

        time.sleep(0.5)
        mac_logs = macos.query_macos_notification_logs(t_dismiss)
        return (
            "PASS",
            f"Phone A ({swipe_info}) -> Mac dismissed (id={mac_row.id}, UNCenter removals={mac_logs['removed']}); {b_note}",
            {"mac_row_id": mac_row.id, "macos_removals": mac_logs["removed"]},
        )

    ctx.record("T05.1", "dismissal", "Dismiss on Phone A clears MacBook & Phone B", check_dismiss_from_phone_a)

    def check_dismiss_from_phone_b():
        if not ctx.phone_b:
            raise SkipCheck("Phone B not connected via ADB")

        marker = f"AN-E2E-{ctx.run_id}-DISMB"
        ctx.posted_markers.append(marker)
        cp = adb.post_shell_notification(
            ctx.phone_a,
            tag=f"an_dismb_{ctx.run_id}",
            title=f"Dismiss B {marker}",
            body=f"Swipe mirrored on Phone B {marker}",
        )
        assert cp.returncode == 0, f"post failed: {cp.stderr}"

        mac_row = wait_until(
            lambda: (macos.query_notifications(contains=marker, limit=5) or [None])[0],
            timeout_sec=ctx.timeout_sec,
        )
        assert mac_row is not None, f"{marker} did not arrive on MacBook"
        b_arrived = wait_until(
            lambda: adb.find_notifications(ctx.phone_b, pkg=adb.ALLNOTIFY_PKG, contains=marker),
            timeout_sec=ctx.timeout_sec,
        )
        assert b_arrived, f"{marker} did not arrive on Phone B"

        swipe_info = _dismiss_on_phone(ctx, ctx.phone_b, "Phone B", marker)

        # Verify Phone A's ORIGINAL shell notification is cancelled remotely
        a_cleared = wait_until(
            lambda: len(adb.find_notifications(ctx.phone_a, pkg="com.android.shell", contains=marker)) == 0,
            timeout_sec=ctx.timeout_sec,
        )
        assert a_cleared, (
            f"Phone A original notification {marker} was NOT remotely cancelled after Phone B dismissal"
        )

        # Verify MacBook also marks dismissed
        mac_dism = wait_until(
            lambda: (
                r if (r := macos.get_row_by_id(mac_row.id)) and r.dismissed_at is not None else None
            ),
            timeout_sec=ctx.timeout_sec,
        )
        assert mac_dism is not None, f"MacBook row {mac_row.id} not marked dismissed after Phone B swipe"
        return (
            "PASS",
            f"Phone B ({swipe_info}) -> Phone A original cancelled + Mac dismissed (id={mac_row.id})",
            {"mac_row_id": mac_row.id},
        )

    ctx.record("T05.2", "dismissal", "Dismiss mirrored on Phone B cancels Phone A & clears MacBook", check_dismiss_from_phone_b)

    def check_dismiss_from_mac_interactive():
        if not ctx.interactive:
            raise SkipCheck("Interactive Mac banner/tray click test (pass --interactive to run)")
        marker = f"AN-E2E-{ctx.run_id}-DISMMAC"
        ctx.posted_markers.append(marker)
        cp = adb.post_shell_notification(
            ctx.phone_a,
            tag=f"an_dismmac_{ctx.run_id}",
            title=f"Dismiss Mac {marker}",
            body=f"Click Dismiss on Mac banner or tray popover ({marker})",
        )
        assert cp.returncode == 0, f"post failed: {cp.stderr}"
        mac_row = wait_until(
            lambda: (macos.query_notifications(contains=marker, limit=5) or [None])[0],
            timeout_sec=ctx.timeout_sec,
        )
        assert mac_row is not None, f"{marker} did not arrive on MacBook"
        input(
            f"\n    [Action needed on MacBook]: Click 'Dismiss' on the macOS banner (or tray popover) "
            f"for '{marker}', then press Enter..."
        )
        a_cleared = wait_until(
            lambda: len(adb.find_notifications(ctx.phone_a, pkg="com.android.shell", contains=marker)) == 0,
            timeout_sec=ctx.timeout_sec,
        )
        assert a_cleared, f"Phone A original notification {marker} did not cancel after Mac Dismiss"
        b_note = ""
        if ctx.phone_b:
            b_cleared = wait_until(
                lambda: len(adb.find_notifications(ctx.phone_b, pkg=adb.ALLNOTIFY_PKG, contains=marker)) == 0,
                timeout_sec=ctx.timeout_sec,
            )
            assert b_cleared, f"Phone B mirrored notification {marker} did not clear after Mac Dismiss"
            b_note = " & Phone B cleared"
        return ("PASS", f"Mac Dismiss -> Phone A cancelled{b_note}", {"mac_row_id": mac_row.id})

    ctx.record("T05.3", "dismissal", "Dismiss on MacBook cancels Phone A & Phone B (interactive)", check_dismiss_from_mac_interactive)
