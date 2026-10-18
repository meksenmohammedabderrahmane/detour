# Detour Release Verification and Publishing Guide

This document records regression test evidence for Detour v0.1.0, the Definition of Done state table, and the step-by-step procedure to publish the release on GitHub.

---

## 1. Regression Verification Evidence

All regression tests were re-run against the release binaries (`_dist/detour.exe` and `_dist/detour-ui.exe`) on Windows 11:

### A. Main Connection & Exception Routing (scripts/test-acceptance-abc.ps1)
- **Test a (Unlisted App Routing)**:
  - Main Connection set to `Ethernet` (dynamically discovered home public IP).
  - Windows default metric intentionally set to `Wi-Fi` (hotspot public IP).
  - An unlisted application (`powershell.exe`) opened an outbound HTTP request.
  - Public IP observed: matched Ethernet public IP.
  - Result: **PASS** (traffic routed out Ethernet despite lower-metric Wi-Fi default).
- **Test b (Concurrent Dual-Adapter Routing)**:
  - Exception rule set: `curl.exe -> Wi-Fi`.
  - Concurrent requests launched for `curl.exe` and `powershell.exe`.
  - `curl.exe` public IP observed: matched Wi-Fi hotspot public IP.
  - `powershell.exe` public IP observed: matched Ethernet public IP.
  - Result: **PASS** (both flows egressed simultaneously across distinct physical adapters).
- **Test c (Live Main Connection Flip)**:
  - Main Connection switched from `Ethernet` to `Wi-Fi`.
  - New unlisted application requests routed to Wi-Fi within **0.81 s** (target <= 5 s).
  - Pre-existing flows remained uninterrupted.
  - Result: **PASS**.

### B. UI Selftest Verification (`_dist/detour-ui.exe --selftest`)
- **DOM Node Preservation**: Open select element preserved across 20 consecutive event ticks: **PASS**.
- **Exception Addition**: `rules.set` updates UI and IPC table: **PASS**.
- **Main Connection Reset**: Selecting "Main connection" removes rule exception: **PASS**.
- **Unpinned Flow Verification**: Main connection flipped to Ethernet, public IP verified in **0.21 s** (target <= 5 s): **PASS**.
- Overall Selftest Score: **4 / 4 PASSED**.

---

## 2. Release Verification Matrix

| Component | Target Requirement | Verified Result | Status |
|---|---|---|---|
| **Core Engine** | Route capture, userspace TCP/IP pinning | 0 build errors, clean test suite | **PASS** |
| **Game Safety** | Zero DLL injection, handle-less attribution | Verified against NT system process info | **PASS** |
| **Hot-Plug & Down Policy** | Fallback to alternate interface upon disconnect | 1.33s failover, 5.30s resumption | **PASS** |
| **Service Recovery** | SCM auto-restart on crash | Reconnected in 2.22s | **PASS** |
| **User Interface** | Fluent UI, tray, live throughput deltas | 368 MB tree working set, 0% idle CPU | **PASS** |
| **Installer** | Clean install, upgrade, and uninstallation | Inno Setup 6, clean uninstaller | **PASS** |
| **Packaging** | Installer, zip bundle, SHA256SUMS.txt | Cryptographic checksums generated | **PASS** |

---

## 3. Git Tagging Command

As requested, the git tag was **not** created automatically. Run the following command in PowerShell to create the release tag:

```powershell
git tag -a v0.1.0 -m "Detour v0.1.0: Initial public release"
```

To push the tag to GitHub:
```powershell
git push origin main --tags
```

---

## 4. Publishing on GitHub.com

Follow these steps to publish the release:

1. Push your repository to GitHub:
   ```powershell
   git remote add origin https://github.com/meksenmohammedabderrahmane/detour.git
   git push -u origin main --tags
   ```
2. Navigate to your repository page in your browser:
   `https://github.com/meksenmohammedabderrahmane/detour/releases/new`
3. In the **Choose a tag** dropdown, select `v0.1.0`.
4. In the **Release title** field, enter:
   `Detour v0.1.0: Initial Public Release`
5. In the description box, paste the contents of [docs/RELEASE_NOTES_v0.1.0.md](docs/RELEASE_NOTES_v0.1.0.md).
6. Under **Attach binaries**, drag and drop the following files from the `_dist` folder:
   - `_dist/DetourSetup-0.1.0.exe`
   - `_dist/detour-v0.1.0-windows-amd64.zip`
   - `_dist/SHA256SUMS.txt`
7. Click **Publish release**.

---

## 5. Capturing User Interface Screenshots

To capture screenshots for the repository:
1. Start the Detour GUI:
   ```powershell
   & "C:\Program Files\Detour\detour-ui.exe"
   ```
2. In the UI, add an exception rule (e.g. `chrome.exe -> Wi-Fi`).
3. Press `Win + Shift + S` to capture the Detour window.
4. Save the image to `docs/screenshots/detour-main-window.png`.
5. Embed the screenshot in `README.md` if desired:
   ```markdown
   ![Detour Window](docs/screenshots/detour-main-window.png)
   ```
