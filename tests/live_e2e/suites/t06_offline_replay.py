"""T06: MacBook Offline Replay & Anti-Popup-Storm Verification."""

from __future__ import annotations

import time
from datetime import datetime

from helpers import adb, macos
from helpers.report import SkipCheck, TestContext, wait_until


def run(ctx: TestContext) -> None:
    print("\n=== T06: MacBook Offline Replay & Anti-Popup-Storm ===")

    if not ctx.phone_a:
        ctx.record(
            "T06.1",
            "replay",
            "Offline replay suppresses already-dismissed popups and shows only still-active",
            lambda: (_ for _ in ()).throw(SkipCheck("Phone A not connected via ADB")),
        )
        return

    def check_offline_replay():
        m_dism = f"AN-E2E-{ctx.run_id}-OFF-DISM"
        m_act = f"AN-E2E-{ctx.run_id}-OFF-ACT"
        ctx.posted_markers.extend([m_dism, m_act])

        # 1. Stop MacBook app cleanly so VPS queues events for it
        macos.stop_desktop_app()
        try:
            # 2. Post first notification on Phone A while MacBook is offline, wait for VPS ingest,
            #    then dismiss it before posting the second (avoids Android shade auto-grouping hiding it).
            cp1 = adb.post_shell_notification(
                ctx.phone_a,
                tag=f"an_off1_{ctx.run_id}",
                title=f"Offline Dismissed {m_dism}",
                body=f"Dismissed before Mac wakes {m_dism}",
            )
            assert cp1.returncode == 0, f"post 1 failed: {cp1.stderr or cp1.stdout}"
            time.sleep(1.5)  # allow Phone A to upload posted event to VPS

            # 3. Dismiss the first one on Phone A while MacBook is still offline
            ok, detail = adb.dismiss_notification_via_shade(ctx.phone_a, m_dism)
            if not ok:
                if ctx.interactive:
                    input(
                        f"\n    [Action needed on Phone A]: Swipe away '{m_dism}' while MacBook is offline, "
                        f"then press Enter..."
                    )
                else:
                    raise AssertionError(
                        f"could not auto-dismiss '{m_dism}' on Phone A ({detail}); unlock screen or pass --interactive"
                    )
            time.sleep(1.5)  # ensure dismissal reaches VPS queue

            # 4. Post second notification that stays active until MacBook wakes
            cp2 = adb.post_shell_notification(
                ctx.phone_a,
                tag=f"an_off2_{ctx.run_id}",
                title=f"Offline Active {m_act}",
                body=f"Still active when Mac wakes {m_act}",
            )
            assert cp2.returncode == 0, f"post 2 failed: {cp2.stderr or cp2.stdout}"
            time.sleep(1.5)  # allow Phone A to upload active event to VPS

            # 4. Relaunch MacBook app and capture UNUserNotificationCenter log count
            t_relaunch = datetime.now()
            macos.start_desktop_app()

            row_dism = wait_until(
                lambda: (macos.query_notifications(contains=m_dism, limit=5) or [None])[0],
                timeout_sec=ctx.timeout_sec,
            )
            row_act = wait_until(
                lambda: (macos.query_notifications(contains=m_act, limit=5) or [None])[0],
                timeout_sec=ctx.timeout_sec,
            )
            assert row_dism is not None, f"dismissed offline item {m_dism} missing from Mac SQLite history"
            assert row_act is not None, f"active offline item {m_act} missing from Mac SQLite history"
            assert row_dism.dismissed_at is not None, (
                f"expected {m_dism} to be silently archived with dismissed_at != NULL, got None"
            )
            assert row_act.dismissed_at is None, (
                f"expected {m_act} to remain active (dismissed_at IS NULL), got {row_act.dismissed_at}"
            )

            time.sleep(1.0)
            logs = macos.query_macos_notification_logs(t_relaunch)
            assert logs["added_err"] == 0, f"macOS UNCenter errors on replay: {logs['added_err']}"
            assert logs["added_ok"] == 1, (
                f"expected exactly 1 macOS popup on replay (only {m_act}), saw added_ok={logs['added_ok']}"
            )
            return (
                "PASS",
                f"both saved to SQLite (dismissed silently archived, active popped once; added_ok={logs['added_ok']})",
                {"row_dism": row_dism.id, "row_act": row_act.id, "added_ok": logs["added_ok"]},
            )
        finally:
            running, _ = macos.is_desktop_running()
            if not running:
                macos.start_desktop_app()

    ctx.record(
        "T06.1",
        "replay",
        "MacBook offline replay archives dismissed silently & pops only still-active",
        check_offline_replay,
    )
