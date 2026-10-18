# Changelog

All notable changes to Detour will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-18

### Added
- **Core Engine (M1)**:
  - Userspace packet routing via Wintun virtual network adapter and gVisor netstack.
  - Per-flow network egress pinning using Windows `IP_UNICAST_IF` socket options.
  - Split-default routing (`0.0.0.0/1` and `128.0.0.0/1`) to capture application traffic without overriding physical default routes.
- **Anti-Cheat Safety (M1.5)**:
  - Handle-less process attribution via `GetExtendedTcpTable` and `GetExtendedUdpTable` with module ownership.
  - No DLL injection, no code modification, no memory scanning, and zero handle operations with write privileges.
  - Early UDP flow queueing: holding initial datagrams up to 250 ms to ensure adapter assignment before egress.
- **Windows Service & IPC (M2)**:
  - SYSTEM service (`DetourService`) with rapid SCM auto-recovery restart actions.
  - Length-prefixed JSON-RPC over Windows Named Pipe (`\\.\pipe\DetourControl`) with custom DACL permitting non-admin installing users.
  - Atomic, versioned rule persistence in `%ProgramData%\Detour\rules.json` with automatic backup recovery.
  - Live adapter hot-plug detection via `NotifyIpInterfaceChange` and `NotifyRouteChange2`.
  - Main Connection setting with Automatic fallback and strict Block policies.
- **Fluent UI & Tray (M3)**:
  - Modern Windows 11 Fluent UI built with embedded HTML, CSS, JavaScript, and Microsoft WebView2.
  - Pure Go system tray integration with minimize-to-tray, status indicator, and quick actions.
  - Real-time live throughput metrics delta display per application.
  - Automated DOM preservation across hot-plug and event tick refreshes.
- **Installer & Packaging (M4)**:
  - Inno Setup 6 installer (`DetourSetup-0.1.0.exe`) deploying service, UI, and Wintun driver to `Program Files\Detour`.
  - Seamless in-place upgrades preserving existing rules.json.
  - Clean uninstaller removing all drivers, services, and routing rules.
