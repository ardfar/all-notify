# All-Notify Live Hardware-in-the-Loop (HIL) E2E Test Suite

End-to-end verification suite that exercises the **real production/deployed All-Notify stack** across:
- **Two physical Android phones** (USB or Wireless ADB)
- **One MacBook** (installed `/Applications/All-Notify.app` + macOS `usernotificationsd` + local SQLite WAL DB)
- **Live VPS relay & `/admin` web panel** (Playwright Chromium + Admin/Device HTTP APIs)

> **Safety**: Never revokes or modifies your real paired devices. Admin pairing tests create a temporary throwaway device (`e2e-tmp-*`), exercise claim/rename/trust/cancel/revoke, and clean up automatically. Secrets (`ALLNOTIFY_ADMIN_PASSWORD`, `ALLNOTIFY_K_MASTER`) are read from environment variables or hidden prompts and are never printed or written to reports.

---

## Prerequisites

1. **MacBook**:
   - Signed `/Applications/All-Notify.app` installed, running, paired, unmuted, with **Allow Notifications** enabled in macOS System Settings.
   - Python 3 + Playwright Chromium (already installed on this Mac).
2. **Two Android Phones**:
   - USB Debugging enabled and authorized (`~/Library/Android/sdk/platform-tools/adb devices` lists both as `device`).
   - Screens **unlocked** during `dismissal` and `replay` suites so UIAutomator can swipe notifications in the shade (or pass `--interactive` for manual swipe prompts).
   - `com.allnotify.app` installed, paired to the same VPS + `K_master`, Notification Access enabled, `POST_NOTIFICATIONS` granted, and `RelayForegroundService` running.
3. **Admin Panel**:
   - Export `ALLNOTIFY_ADMIN_PASSWORD` (and optionally `ALLNOTIFY_K_MASTER` to also test browser KCV wrong-key rejection + v2 QR rendering + zero browser-storage leakage).

---

## Suites Covered

| Suite | IDs | What It Verifies |
| :--- | :--- | :--- |
| `preflight` | `T01.1–T01.5` | VPS `/healthz`, Mac `codesign` (`Identifier=com.allnotify.desktop`, bound `Info.plist`), Mac runtime/unmuted/`ncprefs.plist`, Phone A & B ADB + NotificationListener + ForegroundService + battery exemption |
| `admin` | `T02.1–T02.5` | `/admin` CSP & security headers, CSRF header rejection, live online device inventory, throwaway v2 pairing code (`claim` → `410` double-claim → `403` untrusted → rename + grant trust → trusted `POST /v1/pairing-codes` → cancel `410` → revoke `401`), Playwright Chromium login + KCV wrong-key rejection + QR render + zero `localStorage`/`sessionStorage`/`cookie` leak |
| `mirror` | `T03.1–T03.4` | Phone A → MacBook (<3s, SQLite + cached WebP icon + macOS `usernotificationsd` `hasError: 0`) & Phone B (`com.allnotify.app`), anti-loop guard on Phone A, `CATEGORY_TRANSPORT` noise filter drop, `BigPictureStyle` image E2EE upload & decryption |
| `dedup` | `T04.1` | 5-second cross-device dedup: identical notification on Phone A + Phone B merges into 1 MacBook SQLite row with 2 senders & 2 UIDs |
| `dismissal` | `T05.1–T05.3` | Phone A swipe clears MacBook (`dismissed_at` + `usernotificationsd` removal) & Phone B; Phone B mirrored swipe remotely cancels original on Phone A & clears MacBook; interactive Mac banner/tray Dismiss (`--interactive`) |
| `replay` | `T06.1` | Quit MacBook app → post 2 notifications on Phone A → dismiss 1 while MacBook offline → relaunch MacBook → both in SQLite, dismissed archived silently, only 1 `Added notification request` fired to macOS |
| `security` | `T07.1–T07.3` | Zero plaintext/key leaks in MacBook unified logs, Android `logcat`, and (if `--vps-ssh` passed) live VPS SQLite DB (`-wal`/`-shm`) + `docker logs` |

---

## Running

```bash
# Run everything (auto-detects server URL from Mac pairing.json and both ADB phones)
ALLNOTIFY_ADMIN_PASSWORD='...' \
ALLNOTIFY_K_MASTER='...' \
python3 tests/live_e2e/run_live_suite.py --interactive --vps-ssh user@your-vps.example.com

# Unattended run (auto-swipes Android shade; skips manual Mac click test T05.3)
ALLNOTIFY_ADMIN_PASSWORD='...' \
python3 tests/live_e2e/run_live_suite.py

# Run specific suites only
python3 tests/live_e2e/run_live_suite.py --suite preflight,admin
python3 tests/live_e2e/run_live_suite.py --suite mirror,dedup,dismissal,replay,security
```

Reports are saved to `tests/live_e2e/reports/live_e2e_<run_id>.{md,json}` (gitignored).
