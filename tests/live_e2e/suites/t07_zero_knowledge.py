"""T07: Zero-Knowledge & Secret-Leakage Audit across MacBook, Android Phones, and optional VPS SSH."""

from __future__ import annotations

import subprocess
from datetime import datetime, timedelta

from helpers import adb, macos
from helpers.report import SkipCheck, TestContext


def run(ctx: TestContext) -> None:
    print("\n=== T07: Zero-Knowledge & Log Leakage Audit ===")

    forbidden: list[str] = list(ctx.posted_markers)
    if ctx.k_master:
        forbidden.append(ctx.k_master)

    def check_mac_logs_no_leak():
        if not forbidden:
            raise SkipCheck("No test markers or K_master recorded in this run to audit")
        since = datetime.now() - timedelta(minutes=15)
        logs = macos.query_macos_notification_logs(since)
        raw = logs["raw_stdout"]
        leaks = [len(tok) for tok in forbidden if tok in raw]
        assert not leaks, f"SECURITY: {len(leaks)} forbidden plaintext/key token(s) found in Mac unified logs!"
        return ("PASS", f"scanned {logs['raw_lines_count']} Mac log lines; 0 plaintext/key leaks", {})

    ctx.record("T07.1", "security", "MacBook unified logs contain zero plaintext/K_master leaks", check_mac_logs_no_leak)

    def check_android_logcat_no_leak():
        serials = [s for s in (ctx.phone_a, ctx.phone_b) if s]
        if not serials or not forbidden:
            raise SkipCheck("No Android devices or markers available to audit")
        total_hits: list[str] = []
        for s in serials:
            total_hits.extend(adb.check_logcat_for_leaks(s, forbidden))
        assert not total_hits, f"SECURITY: {len(total_hits)} forbidden token(s) found in Android logcat!"
        return ("PASS", f"scanned logcat on {len(serials)} phone(s); 0 plaintext/key leaks", {})

    ctx.record("T07.2", "security", "Android logcat contains zero plaintext/K_master leaks", check_android_logcat_no_leak)

    def check_vps_zero_knowledge():
        if not ctx.vps_ssh:
            raise SkipCheck("ALLNOTIFY_VPS_SSH not set (pass --vps-ssh user@host to audit VPS DB & docker logs)")
        if not forbidden:
            raise SkipCheck("No test markers or K_master to audit against VPS")

        # Pass markers over stdin to avoid putting any token in remote shell argv
        remote_script = (
            "python3 -c '"
            "import sys, glob, subprocess\n"
            "tokens = [l.strip() for l in sys.stdin if l.strip()]\n"
            "hits = 0\n"
            "for p in glob.glob(\"/root/all-notify/data/all-notify.db*\"):\n"
            "    data = open(p, \"rb\").read()\n"
            "    for t in tokens:\n"
            "        if t.encode() in data: hits += 1\n"
            "logs = subprocess.run([\"docker\", \"logs\", \"--tail\", \"500\", \"all-notify-server\"], capture_output=True)\n"
            "blob = logs.stdout + logs.stderr\n"
            "for t in tokens:\n"
            "    if t.encode() in blob: hits += 1\n"
            "print(f\"HITS={hits}\")\n"
            "'"
        )
        cp = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", ctx.vps_ssh, remote_script],
            input="\n".join(forbidden) + "\n",
            capture_output=True,
            text=True,
            timeout=25.0,
        )
        assert cp.returncode == 0, f"SSH VPS audit failed: {cp.stderr.strip()}"
        assert "HITS=0" in cp.stdout, f"SECURITY: VPS DB or container logs contained plaintext/key! ({cp.stdout.strip()})"
        return ("PASS", f"VPS DB (-wal/-shm) & docker logs on {ctx.vps_ssh}: 0 plaintext/key hits", {})

    ctx.record("T07.3", "security", "VPS SQLite DB & Docker logs zero-knowledge audit (SSH)", check_vps_zero_knowledge)
