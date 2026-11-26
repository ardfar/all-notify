# All-Notify Documentation

**All-Notify** is a personal, self-hosted, end-to-end encrypted (E2EE) notification hub. It mirrors notifications from your Android phones to your other Android phones, Windows PCs, and Macs in real time over the internet, with two-way dismissal sync, app icons, image attachments, and local searchable history.

## Goals (v1)

- **Android (send + receive)**: Capture notifications from all apps, mirror them to other devices, display mirrored notifications from other Android devices, and cancel local notifications when dismissed remotely.
- **Windows & macOS (receive only)**: Lightweight tray/menu-bar app showing native OS notifications with one-click dismissal sync and local searchable history.
- **Works anywhere**: Connects through a lightweight Go relay server hosted on your personal VPS (`wss://` + HTTPS).
- **Zero-knowledge relay (E2EE)**: All notification text, app icons, and image attachments are encrypted end-to-end with a shared symmetric group key (`XChaCha20-Poly1305`). The VPS never sees plaintext.
- **Rich payloads**: Includes cached `64×64` WebP app icons and compressed E2EE image attachments (up to `800px`, `≤512 KB`).
- **Noise control**: Skips ongoing/media/low-priority notifications by default, supports per-app filters on Android, deduplicates identical notifications across phones within 5 seconds, and avoids popup storms when waking from sleep.

## Non-Goals (v1)

- iOS notification capture (blocked by iOS sandbox; BLE ANCS deferred).
- macOS / Windows notification capture (desktop clients are receive-only in v1).
- Inline quick-reply / custom notification action buttons (deferred to v2).
- Multi-user SaaS accounts, billing, or public App Store / Play Store distribution.
- Granular per-app-to-specific-device routing rules (v1 broadcasts to all devices + per-device Pause/Mute toggle).

## Monorepo Layout

```text
all-notify/
├── docs/           # Design & development documentation (this folder)
├── protocol/       # JSON event schemas, E2EE spec, cross-language test vectors
├── server/         # Go VPS relay server (WebSocket + SQLite queue + E2EE blob store)
├── android/        # Native Kotlin Android app (NotificationListener + Foreground Service)
└── desktop/        # Tauri (Rust + minimal Svelte/vanilla UI) tray app for Windows & macOS
```

## Documentation Index

| Document | Contents |
| :--- | :--- |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System overview, component boundaries, data flows, loop prevention, deduplication, and offline replay. |
| [PROTOCOL.md](./PROTOCOL.md) | E2EE cryptography, pairing URI format, WebSocket wire protocol, JSON schemas, and HTTPS blob API. |
| [SERVER.md](./SERVER.md) | Go relay server architecture, SQLite schema, CLI commands, and Docker/Caddy/Nginx deployment. |
| [ANDROID.md](./ANDROID.md) | Kotlin app architecture, permissions, NotificationListener capture, Foreground Service, and Room DB. |
| [DESKTOP.md](./DESKTOP.md) | Tauri tray app architecture, macOS/Windows native notification dismissal, SQLite history, and UI views. |
| [ROADMAP.md](./ROADMAP.md) | Phased delivery roadmap, dependency graph, milestones, risk register, and post-v1 backlog. |
| [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) | Detailed step-by-step engineering tasks, target file paths, and verification commands per phase. |
