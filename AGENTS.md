# All-Notify — Agent Guide

Personal, self-hosted, end-to-end encrypted (E2EE) notification hub: **Android** (send + receive) ↔ **Go VPS Relay** ↔ **Windows & macOS** (receive only). Single-user, lightweight, zero cloud/Firebase dependencies.

---

## Shared Memory (`centmem`) — Mandatory Read/Write Protocol

This project uses `centmem` under scope **`project:all-notify`** as the shared brain across separate agent sessions (coordinated by the Project Manager session).

- **Before executing any task (READ)**:
  ```bash
  centmem get --scope project:all-notify --key project.status
  centmem recall "<task summary>" --scope project:all-notify --top 5
  centmem timeline --scope project:all-notify --since 7d --limit 10
  ```
- **After completing a task, decision, bug fix, or milestone (WRITE)**:
  - Log decisions/findings: `centmem put --scope project:all-notify --type note --tags <tags> --content "<summary>"`
  - Log phase/task checkpoints: `centmem put --scope project:all-notify/agent:<role> --type log --tags checkpoint --content "<what finished, tests run, next step>"`
  - Update `project.status` (or other durable facts) via `centmem set --scope project:all-notify --key <key> --value '<json>'` whenever a phase status or shared contract changes.
  - Never store raw `K_master`, bearer tokens, or decrypted notification content in `centmem`.

---

## Documentation Pointers (Read Before Acting)

Reach for the matching doc before designing or editing code; `docs/` is the single source of truth.

| When your task touches... | Read first |
| :--- | :--- |
| System boundaries, data flows, loop guards, 5s dedup, offline replay | `docs/ARCHITECTURE.md` |
| E2EE crypto, AAD, pairing URI, WS frames, JSON schemas, Blob API | `docs/PROTOCOL.md` |
| Go relay server, SQLite queue, CLI (`keygen`/`token`), Docker/Caddy | `docs/SERVER.md` |
| Kotlin Android app, `NotificationListenerService`, Foreground Service, Room | `docs/ANDROID.md` |
| Tauri desktop app, macOS `UNUserNotificationCenter`, Windows Toast, tray UI | `docs/DESKTOP.md` |
| Phase order, milestones, risk mitigations | `docs/ROADMAP.md` |
| Next engineering task, target file paths, phase exit commands | `docs/IMPLEMENTATION_PLAN.md` |

---

## Non-Negotiable Invariants

1. **Zero-knowledge VPS**: `server/` never stores `K_master` and never decrypts events or blobs. Never log raw `K_master`, bearer tokens, or decrypted notification content on any component.
2. **Cross-language crypto parity**: `protocol/test_vectors.json` is the contract for `HKDF-SHA256`, `XChaCha20-Poly1305` (with AAD), and `allnotify://pair` parsing. Every implementation (`server/`, `android/`, `desktop/`) MUST pass all test vectors in its unit test suite.
3. **Loop & echo prevention**:
   - Android unconditionally drops notifications from `BuildConfig.APPLICATION_ID`.
   - Server never echoes a `relay` frame back to `sender_device_id`.
   - Android tracks remotely cancelled `sbn.key`s (10s TTL) so `onNotificationRemoved` never re-emits `notification.dismissed`.
4. **Anti-popup-storm replay**: Receivers buffer all incoming events until `replay_complete`, apply `notification.dismissed` first, archive already-dismissed items silently to local history, and pop up only still-active items (collapsing >5 active into a summary).
5. **Payload & disk budgets**: App icons are `64×64` WebP cached by `(packageName, sha256)`; image attachments are compressed on Android to `≤800px` and `≤512 KB` and uploaded as HTTPS E2EE blobs (server enforces `550 KB` max blob, `64 KB` max WS frame, 24h TTL, `256 MB` total blob cap).
6. **Lightweight discipline**: Keep dependencies minimal (pure-Go `modernc.org/sqlite`, native Kotlin, Tauri v2 + minimal Svelte/vanilla UI). Build only what v1 requires; defer v2 items listed in `docs/ROADMAP.md`.

---

## Skill Routing

Load the matching skill before starting a task (following `using-agent-skills`):

| Task / Situation | Skill to Invoke |
| :--- | :--- |
| Starting any session, recalling context, or logging decisions/checkpoints | `centmem` |
| Designing wire frames, Blob API, or trait/interface boundaries | `api-and-interface-design` |
| Implementing OS-specific APIs (Android `NotificationListenerService` / Foreground Service, macOS `UNUserNotificationCenter`, WinRT Toast, Tauri v2, `XChaCha20-Poly1305`) | `source-driven-development` |
| Stress-testing high-stakes logic (E2EE/AAD/key rotation, auth revocation, loop guards, replay ordering) | `doubt-driven-development` |
| Implementing any phase slice across files | `incremental-implementation` + `karpathy-guidelines` |
| Writing crypto, SQLite queue, dedup, or protocol parser logic | `test-driven-development` |
| Building the Tauri tray popover UI (Svelte/vanilla) | `frontend-ui-engineering` |
| Scaffolding, building, running, or previewing the Android app on AVD/device | `android-cli`, `android-device-hub`, `compose-preview` |
| Auditing E2EE boundaries, token hashing, `blob_id` path safety, Keystore/Keychain, TLS | `security-and-hardening` |
| Investigating cross-device bugs (Doze drops, missed dismissals, replay races) | `diagnosing-bugs` |
| Adding structured server logs or client connection diagnostics | `observability-and-instrumentation` |
| Reviewing or tightening code at the end of a phase | `code-review-and-quality` → `code-simplification` |
| Building GitHub Actions for Linux server, Android APK, macOS `.dmg`, Windows `.msi` | `ci-cd-and-automation` |
| Updating specs or recording architectural changes | `documentation-and-adrs` |
| Running final phase exit checks without expanding scope | `verify-and-stop` |

---

## Working Loop & Verification Gates

1. **Orient**: Query `centmem` (`project:all-notify` status, recall, and timeline), then read the relevant `docs/` pointer and check the current task in `docs/IMPLEMENTATION_PLAN.md`.
2. **Align**: Surface any non-obvious assumptions and stop on spec/code conflicts rather than guessing.
3. **Build thin**: Implement one vertical slice at a time with failing tests first (`test-driven-development`). Keep edits surgical to the active task.
4. **Verify & record before declaring done**: Run the component gate and confirm clean output:
   - **Server**: `cd server && go test -race -v ./...`
   - **Android**: `cd android && ./gradlew testDebugUnitTest assembleDebug`
   - **Desktop**: `cd desktop/src-tauri && cargo test`
   - Update `docs/` whenever a protocol field, CLI flag, or schema changes.
   - Update `centmem` (`project:all-notify`): log a checkpoint, save any new decisions/learnings, and update `project.status` if a phase or milestone advanced.
