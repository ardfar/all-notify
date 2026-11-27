"""T04: 5-Second Cross-Device Deduplication across Phone A + Phone B -> MacBook."""

from __future__ import annotations

import time

from helpers import adb, macos
from helpers.report import SkipCheck, TestContext, wait_until


def run(ctx: TestContext) -> None:
    print("\n=== T04: 5-Second Cross-Device Deduplication ===")

    if not (ctx.phone_a and ctx.phone_b):
        ctx.record(
            "T04.1",
            "dedup",
            "5-second dedup merges identical notifications from Phone A & Phone B",
            lambda: (_ for _ in ()).throw(SkipCheck("Requires both Phone A and Phone B connected via ADB")),
        )
        return

    def check_dedup():
        marker = f"AN-E2E-{ctx.run_id}-DEDUP"
        ctx.posted_markers.append(marker)
        title = f"Shared Alert {marker}"
        body = f"Same message received on two phones {marker}"

        # Post identical notification on both phones within ~0.5s (well inside 5s dedup window)
        cp_a = adb.post_shell_notification(ctx.phone_a, tag=f"an_dedup_a_{ctx.run_id}", title=title, body=body)
        assert cp_a.returncode == 0, f"Phone A post failed: {cp_a.stderr}"
        time.sleep(0.4)
        cp_b = adb.post_shell_notification(ctx.phone_b, tag=f"an_dedup_b_{ctx.run_id}", title=title, body=body)
        assert cp_b.returncode == 0, f"Phone B post failed: {cp_b.stderr}"

        # Wait until the merged row has 2 distinct sender_device_ids
        def _merged():
            rows = macos.query_notifications(contains=marker, limit=10)
            if len(rows) == 1 and len(rows[0].sender_device_ids) >= 2:
                return rows
            return None

        rows = wait_until(_merged, timeout_sec=ctx.timeout_sec)
        all_rows = macos.query_notifications(contains=marker, limit=10)
        assert len(all_rows) == 1, (
            f"expected 1 merged row on MacBook, found {len(all_rows)} rows: "
            f"{[(r.id, r.sender_devices) for r in all_rows]}"
        )
        row = all_rows[0]
        assert len(row.sender_device_ids) == 2 and len(row.notification_uids) == 2, (
            f"expected 2 merged senders & 2 UIDs, got senders={row.sender_devices} uids={len(row.notification_uids)}"
        )
        return (
            "PASS",
            f"merged into 1 Mac row (id={row.id}, senders={row.sender_devices}, uids={len(row.notification_uids)})",
            {"row_id": row.id, "senders": row.sender_devices, "uid_count": len(row.notification_uids)},
        )

    ctx.record("T04.1", "dedup", "5-second cross-device dedup merges Phone A + Phone B on MacBook", check_dedup)
