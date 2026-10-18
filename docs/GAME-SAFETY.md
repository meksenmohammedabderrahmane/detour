# GAME-SAFETY: Detour Anti-Cheat & Process Interaction Specification

## 1. Executive Summary & Core Principle

Detour (codename) is an application-level network egress router for Windows 11. It allows users to bind specific applications to specific network adapters (e.g. Ethernet vs. Wi-Fi).

To maintain strict compatibility and safety when running concurrently with modern online games protected by kernel-level anti-cheat solutions (such as Riot Vanguard, Easy Anti-Cheat, BattlEye, and Ricochet), Detour adheres to a strict non-invasive design principle:

> **Core Principle**: Detour **never** injects code, loads DLLs into other processes, hooks functions (inline, IAT, or driver hooks), reads or writes process memory, or alters files of another process. Everything Detour does remains strictly confined to its own userspace process and its standard, signed Wintun virtual network adapter.

---

## 2. Process Interaction Audit

Detour requires application identity to evaluate per-app routing rules (e.g., `game.exe=Ethernet`). The table below documents every call in the codebase that interacts with process metadata:

| API Call | Purpose / Why | Anti-Cheat Risk Analysis | Mitigation / Implementation |
|---|---|---|---|
| `NtQuerySystemInformation(SystemProcessIdInformation)` (Class 88) | **Primary Identification**: Resolves a target process PID to its executable image path. | **Zero Risk**: Queries kernel `EPROCESS` data directly without opening a process handle. Does **not** invoke `ObRegisterCallbacks` object filter routines that anti-cheat drivers monitor. | Fully handle-less. Queries NT image path (`\Device\HarddiskVolume...\...`), converts to DOS path via cached drive mappings. |
| `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` | **Fallback Identification**: Used only if `NtQuerySystemInformation` fails on a legacy or restricted process. | **Minimal**: Token `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION`) grants **zero** memory access (`VM_READ`/`VM_WRITE`), thread creation, or termination capabilities. | Handle is opened, creation time (`GetProcessTimes`) and image name (`QueryFullProcessImageName`) are read, and the handle is **immediately closed** via `defer windows.CloseHandle(h)`. |
| `QueryFullProcessImageNameW` | Reads executable path given an open query-limited handle. | **None**: Standard, passive query of process image name. | Read-only; cached immediately to prevent repeat queries. |
| `OpenProcess(SYNCHRONIZE)` | Watchdog route cleanup helper. | **Zero Risk to External Processes**: Only opens **Detour's own process ID** (`detour.exe`), never third-party game processes. | Detached watchdog waits for Detour engine exit to cleanly remove `/1` Wintun capture routes if the engine crashes. |
| `GetExtendedTcpTable` / `GetExtendedUdpTable` | Obtains kernel socket ownership table (`TCP_TABLE_OWNER_PID_ALL`, `UDP_TABLE_OWNER_PID`). | **Zero Risk**: Reads Windows IP Helper kernel socket tables. Entirely passive; no hooks or filters. | Passive read with buffer-retry loop. Excludes Detour's self PID to prevent routing loops. |

### Caching Architecture

To prevent repeated handle creation or kernel querying:
1. **Handle-less Cache**: Successful lookups are cached in memory.
2. **PID + Start Time Key**: Fallback queries cache results per `(PID, StartTime)` tuple. Because Windows recycles process IDs after termination, binding the cache to the process creation timestamp guarantees stale entries cannot falsely attribute recycled PIDs.

### Service Architecture Audit
The background Windows Service (`DetourService`) and named-pipe IPC (`\\.\pipe\DetourControl`) introduce **zero** new process-touching calls:
- IPC communication occurs strictly over local named pipes with explicit DACL and Medium Integrity labels.
- Hot-plug routing uses IP Helper callbacks (`NotifyIpInterfaceChange`, `NotifyRouteChange2`) for system network interfaces only.
- Attribution continues to rely exclusively on handle-less NT query information and kernel IP Helper tables. Zero handles to client or game processes are opened by the service.

---

## 3. UDP Flow Semantics for Real-Time Gaming

Real-time multiplayer games rely on UDP for game state, tick packets, voice chat, and telemetry. Unstable routing or mid-flow adapter switching causes desynchronization and connection drops.

Detour implements strict game-safe UDP handling:
1. **Decision Before First Datagram**: When netstack intercepts an outbound UDP datagram, `DialUDP` pauses the flow up to a 250 ms attribution cap to identify the owning application before any packet leaves the host.
2. **Per-(PID, Local Port) Decision Caching**: Game clients typically bind a single local ephemeral UDP port for their session. Once attributed, the adapter decision (`selection`) is cached per `(PID, localPort)`. Subsequent datagrams on that port bypass attribution and dispatch with sub-microsecond latency.
3. **Immutable Mid-Flow Egress**: Detour binds the outbound socket via `IP_UNICAST_IF` during initial socket creation. The egress adapter never switches mid-flow.
4. **Deterministic Fallback**: If a UDP flow cannot be attributed within the 250 ms cap (e.g., rapid transient datagrams or obscured processes), it is permanently assigned to `Automatic` (the system's default route) for the remainder of its lifecycle.

---

## 4. Known Risks & Transparent Limitations

Detour does **not** claim to be "ban-safe" or immune to anti-cheat actions. Users and developers must be aware of the following technical realities:

1. **Virtual Network Driver (`wintun.dll`)**:
   Detour loads the official, Microsoft-WHQL signed Wintun driver developed by WireGuard LLC. While Wintun is open source and widely used in VPN and networking products, kernel-level anti-cheat engines monitor all active drivers on the system. If a game's policy forbids virtual network adapters or split-tunneling, Detour may trigger that policy regardless of how cleanly it runs.
2. **Relay Latency**:
   Relaying packets through userspace (TUN driver → gVisor netstack → pinned raw socket) incurs a measurable processing overhead (typically 0.1 to 0.4 ms at median). Under heavy system CPU load, userspace scheduling variance can introduce minor packet jitter.
3. **First-Datagram Delay**:
   The 250 ms attribution window queues the very first UDP datagram while resolving socket ownership in the kernel tables. While subsequent packets experience no delay, sensitive matchmaking handshakes may occasionally observe this initial pause.
4. **Split-Tunneling & Geo-Mismatch**:
   If an application connects its authentication/matchmaking flow over one adapter (e.g. Wi-Fi) and its game server connection over another (e.g. Ethernet), backend servers may detect IP address divergence, potentially triggering fraud or account-security verification challenges.

> **Explicit Disclaimer**:
> Detour provides zero guarantees of immunity from bans, kicks, or suspensions enforced by third-party anti-cheat systems. Anti-cheat software operates using proprietary, constantly changing heuristic engines. Use alongside competitive online games at your own discretion.

---

## 5. Verification & Test Protocol

To independently verify game safety and non-intrusiveness:

1. **Process Handle Audit**:
   - Launch the game alongside Detour.
   - Using **Process Hacker** or **Sysinternals Process Explorer**, inspect handles opened by `detour.exe`.
   - Verify that `detour.exe` maintains **zero** open handles to the game executable.
2. **DLL / Thread Verification**:
   - Inspect the game process modules and threads.
   - Verify that no Detour DLLs or foreign threads exist within the game's address space.
3. **UDP Latency Measurement**:
   - Execute `powershell.exe -ExecutionPolicy Bypass -File .\scripts\test-udp-latency.ps1 -Count 1000`.
   - Measure 1000 UDP round-trips with Detour OFF vs. Detour ON.
   - Verify that median added latency is < 1 ms.
4. **Mid-Flow Integrity**:
   - Inspect active flow logs in `%ProgramData%\Detour\status.json`.
   - Verify that flow IDs, adapter bindings, and byte counters remain consistent throughout a game match.
