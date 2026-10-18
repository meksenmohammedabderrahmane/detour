# Detour v0.1.0 Release Notes

We are excited to announce the initial public release of **Detour (v0.1.0)**, an application-level network egress router designed for Windows 11. Detour allows you to bind specific applications to designated network interfaces (such as Ethernet, Wi-Fi, or LTE cellular connections) without relying on IP addresses, DLL injection, or LSP hooks.

---

## Release Assets

| Asset Name | Description | SHA-256 Checksum |
|---|---|---|
| `DetourSetup-0.1.0.exe` | Windows 11 Inno Setup 6 Graphical Installer | `549f27baa667c0c1f6f4c19693dee9216782281d54573cc626b1d0bf5e0903ca` |
| `detour-v0.1.0-windows-amd64.zip` | Standalone portable binaries, Wintun driver, and docs | `f766fb2dc815538c139376f48578e3238ab27f34f64be10e35dc3408127b11ea` |

---

## Key Highlights

### 1. Game-Safe and Non-Invasive
- **Zero DLL injection**: Unlike legacy tools like ForceBindIP, Detour never injects DLLs into other processes or hooks `WS2_32.dll`.
- **Handle-less Process Attribution**: Uses `NtQuerySystemInformation(SystemProcessIdInformation)` and kernel IP Helper tables. Detour never acquires memory read, write, or thread modification handles.
- **Early UDP Routing**: Outbound UDP packets are queued up to a 250 ms attribution window, preventing the first datagram from leaking onto the wrong adapter.

### 2. Robust Windows Service Architecture
- **DetourService**: Runs as a privileged background Windows service under SYSTEM.
- **SCM Rapid Recovery**: Automatically restarts within 2 seconds upon crash or termination.
- **Named Pipe IPC**: Length-prefixed JSON-RPC over `\\.\pipe\DetourControl` with DACL granting unprivileged access to the installing user account.
- **Atomic Rules Persistence**: Rules are stored in `%ProgramData%\Detour\rules.json` using atomic write-and-replace with automated `.bak` rollback.

### 3. Live Interface Hot-Plug & Down Policy
- **Automatic Fallback**: If an assigned adapter goes offline (e.g. cable unplugged), Detour re-routes new flows to the fallback connection within 1.33 seconds.
- **Strict Block Policy**: Allows users to configure applications to block internet entirely if their designated adapter is unavailable.
- **Dynamic Re-Resolution**: Detects interface changes via `NotifyIpInterfaceChange` and `NotifyRouteChange2` without service restarts.

### 4. Modern Windows 11 Fluent UI
- Built with embedded HTML, CSS, JavaScript, and Microsoft WebView2.
- Pure Go system tray integration with minimize-to-tray and quick engine toggling.
- Real-time live throughput delta metrics per application.
- Select DOM state preserved across 20-tick event updates and hot-plug adapter refreshes.

---

## Installation

### Recommended: Inno Setup Installer
1. Download `DetourSetup-0.1.0.exe`.
2. Run the installer (requires Administrator privileges for service registration).
3. The installer configures `DetourService`, sets permissions, and starts the system tray application.

### Portable / Developer
1. Extract `detour-v0.1.0-windows-amd64.zip` to a local folder.
2. Run `detour.exe service install` from an elevated prompt.
3. Launch `detour-ui.exe` to manage rules visually.
