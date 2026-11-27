#!/usr/bin/env python3
"""All-Notify Live Hardware-in-the-Loop (HIL) Full System Verification Suite.

Verifies the real production/deployed stack end-to-end across:
  - 2 physical Android phones (USB/Wi-Fi ADB)
  - 1 MacBook (installed /Applications/All-Notify.app + macOS usernotificationsd)
  - Live VPS relay & /admin web panel (Playwright Chromium + HTTP API)

Usage:
  python3 tests/live_e2e/run_live_suite.py
  python3 tests/live_e2e/run_live_suite.py --suite preflight,admin
  ALLNOTIFY_ADMIN_PASSWORD=... python3 tests/live_e2e/run_live_suite.py --interactive
"""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
import time
from pathlib import Path

# Allow running directly from repo root or tests/live_e2e
SUITE_ROOT = Path(__file__).resolve().parent
if str(SUITE_ROOT) not in sys.path:
    sys.path.insert(0, str(SUITE_ROOT))

from helpers import adb, macos  # noqa: E402
from helpers.report import TestContext  # noqa: E402
from suites import (  # noqa: E402
    t01_preflight,
    t02_admin_web,
    t03_mirror_media,
    t04_dedup,
    t05_dismissal,
    t06_offline_replay,
    t07_zero_knowledge,
)

SUITES = {
    "preflight": t01_preflight.run,
    "admin": t02_admin_web.run,
    "mirror": t03_mirror_media.run,
    "dedup": t04_dedup.run,
    "dismissal": t05_dismissal.run,
    "replay": t06_offline_replay.run,
    "security": t07_zero_knowledge.run,
}


def resolve_phones(arg_a: str | None, arg_b: str | None) -> tuple[str | None, str | None, list[adb.AdbDevice]]:
    try:
        attached = [d for d in adb.list_devices() if d.state == "device"]
    except FileNotFoundError:
        attached = []

    phone_a = arg_a or os.environ.get("ALLNOTIFY_PHONE_A") or (attached[0].serial if len(attached) >= 1 else None)
    phone_b = arg_b or os.environ.get("ALLNOTIFY_PHONE_B") or (attached[1].serial if len(attached) >= 2 else None)
    return phone_a, phone_b, attached


def main() -> int:
    parser = argparse.ArgumentParser(description="All-Notify Live HIL E2E Verification Suite")
    parser.add_argument(
        "--suite",
        default="all",
        help=f"Comma-separated suites to run ({','.join(SUITES.keys())}, or 'all')",
    )
    parser.add_argument("--server-url", default=os.environ.get("ALLNOTIFY_URL"), help="VPS relay base URL")
    parser.add_argument("--phone-a", default=None, help="ADB serial for Phone A (auto-detected if omitted)")
    parser.add_argument("--phone-b", default=None, help="ADB serial for Phone B (auto-detected if omitted)")
    parser.add_argument(
        "--vps-ssh",
        default=os.environ.get("ALLNOTIFY_VPS_SSH"),
        help="Optional SSH target (e.g. user@your-vps.example.com) for T07.3 VPS zero-knowledge audit",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt for admin password if unset and pause for manual Mac banner dismiss check (T05.3)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Per-check wait timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "--report-dir",
        default=str(SUITE_ROOT / "reports"),
        help="Directory where JSON and Markdown reports are written",
    )
    args = parser.parse_args()

    # Resolve server URL from Mac pairing.json if not explicitly supplied
    server_url = args.server_url
    if not server_url:
        meta = macos.read_pairing_meta()
        server_url = meta.get("server_url") if meta else None
    if not server_url:
        print("ERROR: Could not determine server URL. Pass --server-url or pair All-Notify on this Mac.", file=sys.stderr)
        return 2

    selected = list(SUITES.keys()) if args.suite == "all" else [s.strip() for s in args.suite.split(",") if s.strip()]
    unknown = [s for s in selected if s not in SUITES]
    if unknown:
        print(f"ERROR: Unknown suite(s): {', '.join(unknown)}. Valid: {', '.join(SUITES.keys())}", file=sys.stderr)
        return 2

    admin_pw = os.environ.get("ALLNOTIFY_ADMIN_PASSWORD")
    if not admin_pw and args.interactive and "admin" in selected:
        entered = getpass.getpass("Admin password (leave blank to skip authenticated admin checks): ").strip()
        admin_pw = entered or None

    k_master = os.environ.get("ALLNOTIFY_K_MASTER") or None
    phone_a, phone_b, attached = resolve_phones(args.phone_a, args.phone_b)

    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    print(f"All-Notify Live E2E Suite — Run {run_id}")
    print(f"  Server : {server_url}")
    print(f"  ADB    : {len(attached)} device(s) attached -> Phone A={phone_a or 'none'}, Phone B={phone_b or 'none'}")
    print(f"  Admin  : {'configured' if admin_pw else 'unauthenticated-only'} | K_master: {'set' if k_master else 'not set'}")
    print(f"  Suites : {', '.join(selected)}")

    ctx = TestContext(
        run_id=run_id,
        server_url=server_url,
        phone_a=phone_a,
        phone_b=phone_b,
        admin_password=admin_pw,
        k_master=k_master,
        vps_ssh=args.vps_ssh,
        interactive=args.interactive,
        timeout_sec=args.timeout,
    )

    for name in selected:
        SUITES[name](ctx)

    counts = ctx.summary_counts()
    json_path, md_path = ctx.write_reports(Path(args.report_dir))
    print("\n============================================================")
    print(
        f"Summary: ✅ {counts['PASS']} passed · ❌ {counts['FAIL']} failed · "
        f"⚠️ {counts['WARN']} warn · ⏭️ {counts['SKIP']} skipped"
    )
    print(f"Reports: {md_path}")
    print(f"         {json_path}")
    print("============================================================")
    return 1 if counts["FAIL"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
