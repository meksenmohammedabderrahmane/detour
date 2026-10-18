//go:build windows

// Package engine is the M1 core: a capture TUN whose flows are terminated in
// a userland stack (gVisor via tun2socks), attributed to owning processes via
// IP Helper socket tables, matched against per-app rules, and re-dialed from
// a pinned adapter (IP_UNICAST_IF) so engine sockets never re-enter the TUN.
package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
	gom "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"golang.org/x/sys/windows"

	"detour/internal/adapters"
	"detour/internal/attrib"
	"detour/internal/flowstat"
	"detour/internal/rules"
	"detour/internal/winsys"
)

const tunName = "Detour"

// DefaultMTU: TUN traffic never leaves the machine, so it is not bound by the
// links' 1500. WHY 9000 (not the driver's 65535): tun2socks allocates a
// full-MTU buffer per inbound packet even for a 40-byte ACK; net-merge
// measured ~6x fewer userland trips for bulk TCP at 9000  -  cheap CPU win.
const DefaultMTU = 9000

// Engine owns one `detour run`. M1 deliberately keeps this a foreground
// console process; the SYSTEM service + named-pipe split is M2.
type Engine struct {
	Rules *rules.Set
	Table *adapters.Table
	Stats *flowstat.Registry
	MTU   int
	IPv6  string // clamp | relay | off
	// LogIO receives the engine's human log lines (default os.Stdout).
	// WHY a seam: the M1 tests tee the log to a file so the driver script can
	// show attribution lines without scraping a console window.
	LogIO io.Writer

	// OnEvent receives asynchronous engine events (broadcast to IPC clients).
	OnEvent func(evType string, data interface{})

	mu           sync.Mutex
	on           bool
	dev          device.Device
	stk          *stack.Stack
	tunIdx       uint32
	baseline     map[string][2]uint64 // adapter name -> (in, out) at engine start
	notifyCnl    func() error
	stopCh       chan struct{}
	wdProc       *os.Process
	udpMu        sync.Mutex
	udpDecisions map[udpKey]udpDecision
}

type udpKey struct {
	PID  uint32
	Port uint16
}

type udpDecision struct {
	idx         int
	name        string
	adapterName string
	ruleKey     string
	app         string
	unknown     bool
	blocked     bool
	blockReason string
}

func New(rs *rules.Set, mtu int, ipv6 string) *Engine {
	eng := &Engine{
		Rules:        rs,
		Table:        adapters.New(),
		Stats:        flowstat.New(),
		MTU:          mtu,
		IPv6:         ipv6,
		udpDecisions: make(map[udpKey]udpDecision),
	}
	// WHY exclude our own PID from attribution: the engine dials real sockets
	// too; if they were attributed the status table would show "detour.exe"
	// as an app and a routing-loop failure would hide behind it.
	attrib.SetSelf(uint32(os.Getpid()))
	return eng
}

func (e *Engine) Running() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.on }
func (e *Engine) IsOn() bool    { return e.Running() }

func (e *Engine) SetPolicy(mainConn, mainDownPolicy string) {
	e.Table.SetPolicy(mainConn, mainDownPolicy)
	if e.OnEvent != nil {
		e.OnEvent("automatic", e.Table.Current())
	}
}

func (e *Engine) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	w := e.LogIO
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprintf(w, "%s [detour] %s\n", time.Now().Format("15:04:05.000"), msg)
}

// On brings the engine up. Ordering matters; each step's WHY is inline.
func (e *Engine) On() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.on {
		return nil
	}

	// 0. Clear leftover capture routes from an earlier crash. WHY first:
	// routes are machine-global; everything else is local to this process.
	cleanupStaleRoutes()

	if err := e.Table.Refresh(); err != nil {
		return fmt.Errorf("enumerate adapters: %w", err)
	}

	// 1. Create the Wintun adapter (with retry to allow PnP teardown from prior runs to settle).
	var dev device.Device
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		dev, err = tun.Open(tunName, uint32(e.MTU))
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("open TUN (need admin and wintun.dll next to detour.exe): %w", err)
	}
	e.dev = dev

	// 2. Assign addresses/MTU (active store) and capture the ifindex.
	tunIdx, err := winsys.ConfigureAdapter(dev.Name(), e.MTU)
	if err != nil {
		dev.Close()
		return fmt.Errorf("configure adapter: %w", err)
	}
	e.tunIdx = tunIdx

	// 3. Build the userland stack + our forwarders, and only then install the
	// /1 capture routes. WHY: from the instant the /1s exist, apps' traffic
	// targets the TUN  -  the stack must already be listening, or the first
	// milliseconds of flows blackhole (visible as stalls on connect).
	stk, err := core.CreateStack(&core.Config{
		LinkEndpoint:     dev,
		TransportHandler: tunnel.T(),
		Options:          []option.Option{option.WithTCPModerateReceiveBuffer(true)},
	})
	if err != nil {
		dev.Close()
		return fmt.Errorf("create netstack: %w", err)
	}
	e.stk = stk
	installForwarders(stk, e, e.allowV6)

	if err := winsys.AddCaptureRoutes(tunIdx); err != nil {
		e.teardownLocked()
		return fmt.Errorf("add capture routes: %w", err)
	}

	// 4. Plug the per-flow dialer into the tunnel. Called for every flow.
	tunnel.T().SetProxy(e)
	tunnel.T().SetUDPTimeout(30 * time.Second)

	// 5. Live "Automatic" recomputation: IP Helper notification + 3s backstop.
	changeCh := make(chan struct{}, 16)
	if cancel, err := winsys.NotifyChanged(changeCh); err == nil {
		e.notifyCnl = cancel
	} else {
		e.logf("warning: interface-change notify failed (%v); falling back to the 3s poll only", err)
	}
	e.stopCh = make(chan struct{})
	go e.refreshLoop(changeCh)

	// 6. Kernel counter baselines for the status cross-check.
	e.snapshotBaseline()

	// 7. Status file (M1's stand-in for the M2 named pipeline).
	go e.statusLoop()

	// 8. Watchdog process: rids the machine of our capture routes if this
	// process is hard-killed (taskkill /F kills with no signals at all).
	spawnWatchdog(e)

	e.logf("engine ON  | tun=%s idx=%d mtu=%d | ipv6=%s", tunName, tunIdx, e.MTU, e.IPv6)
	for _, r := range e.Rules.List() {
		e.logf("rule: app=%-28s -> %s", r.Key(), r.Adapter())
	}
	if d := e.Table.Current(); d.Index != 0 {
		e.logf("automatic  | %s (idx %d)  -  %s", d.Name, d.Index, d.Reason)
	}
	e.on = true
	return nil
}

func (e *Engine) allowV6(stack.TransportEndpointID) bool {
	return e.IPv6 == "relay"
}

func (e *Engine) refreshLoop(changeCh chan struct{}) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.stopCh:
			return
	case <-changeCh:
		_ = e.Table.Refresh()
		// WHY the follow-up: one kernel event often precedes the state we
		// actually care about (gateways appear after link-up; DHCP settles
		// tens–hundreds of ms later). A short debounce re-check catches it
		// without waiting for the next 3 s tick.
		delay := time.NewTimer(300 * time.Millisecond)
		select {
		case <-e.stopCh:
			delay.Stop()
			return
		case <-delay.C:
			_ = e.Table.Refresh()
		}
		if e.OnEvent != nil {
			e.OnEvent("adapters", e.Table.All())
			e.OnEvent("automatic", e.Table.Current())
		}
		case <-t.C:
			_ = e.Table.Refresh()
		}
	}
}

// statusLoop writes the snapshot every 300ms so a NON-elevated `detour
// status` console can render it while the privileged engine runs.
func (e *Engine) statusLoop() {
	path := StatusPath()
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-t.C:
			func() {
				// WHY recover: the snapshot is presented to the user; if a stats
				// bug throws, this goroutine must not take down the relay and
				// the machine's internet with it (this actually happened once).
				defer func() {
					if rec := recover(); rec != nil {
						e.logf("status snapshot panic (engine continues): %v\n%s", rec, debug.Stack())
					}
				}()
				s := e.Stats.Snapshot()
				s.Kernel = e.kernelSnapshot()
				_ = flowstat.WriteSnapshot(path, s)
				if e.OnEvent != nil {
					e.OnEvent("status", s)
				}
			}()
		}
	}
}

func StatusPath() string { return filepath.Join(winsys.ProgramDataDir(tunName), "status.json") }

type baseRow = [2]uint64

func (e *Engine) snapshotBaseline() {
	e.baseline = map[string]baseRow{}
	for _, a := range e.Table.All() {
		if a.IsTunnel {
			continue
		}
		var row2 windows.MibIfRow2
		row2.InterfaceIndex = uint32(a.Index)
		if err := windows.GetIfEntry2Ex(0, &row2); err != nil {
			continue
		}
		e.baseline[a.Name] = baseRow{row2.InOctets, row2.OutOctets}
	}
}

// kernelSnapshot computes per-adapter deltas since engine start. WHY deltas:
// the OS counts bytes for the whole machine; only the delta isolates the
// engine's traffic and makes the loop-check measurable.
func (e *Engine) kernelSnapshot() []flowstat.KernelCounters {
	var out []flowstat.KernelCounters
	for _, a := range e.Table.All() {
		base, ok := e.baseline[a.Name]
		if !ok {
			continue
		}
		var row2 windows.MibIfRow2
		row2.InterfaceIndex = uint32(a.Index)
		if err := windows.GetIfEntry2Ex(0, &row2); err != nil {
			continue
		}
		out = append(out, flowstat.KernelCounters{
			Adapter: a.Name,
			In:      row2.InOctets - base[0],
			Out:     row2.OutOctets - base[1],
		})
	}
	if e.tunIdx != 0 {
		var row2 windows.MibIfRow2
		row2.InterfaceIndex = e.tunIdx
		if err := windows.GetIfEntry2Ex(0, &row2); err == nil {
			out = append(out, flowstat.KernelCounters{Adapter: "Detour (TUN)", In: row2.InOctets, Out: row2.OutOctets})
		}
	}
	return out
}

func (e *Engine) teardownLocked() {
	if e.tunIdx != 0 {
		winsys.DelCaptureRoutes(e.tunIdx)
		e.tunIdx = 0
	}
	if e.stk != nil {
		done := make(chan struct{})
		go func() { e.stk.Close(); e.stk.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		e.stk = nil
	}
	if e.dev != nil {
		e.dev.Close()
		e.dev = nil
	}
	if e.notifyCnl != nil {
		_ = e.notifyCnl()
		e.notifyCnl = nil
	}
	if e.stopCh != nil {
		close(e.stopCh)
		e.stopCh = nil
	}
	// WHY: the watchdog waits for THIS *process* to die; with the engine
	// (not the process) stopped it would linger, leaking one detached
	// process per ON/OFF cycle in the long-lived service.
	if e.wdProc != nil {
		_ = e.wdProc.Kill()
		e.wdProc = nil
	}
	e.udpMu.Lock()
	e.udpDecisions = make(map[udpKey]udpDecision)
	e.udpMu.Unlock()
}

// Off tears everything down (Ctrl+C / explicit stop).
func (e *Engine) Off() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.on {
		return
	}
	e.teardownLocked()
	e.on = false
	e.logf("engine OFF  -  capture routes removed, normal routing restored")
}

// cleanupStaleRoutes removes /1 routes left behind by an earlier run.
// WHY the check is by adapter name: the dead engine's routes point at the
// surviving adapter, and the adapter's index is the stable key.
func cleanupStaleRoutes() {
	if a, err := winsys.FindByName(tunName); err == nil && a != nil {
		winsys.DelCaptureRoutes(a.Index)
	}
}

// spawnWatchdog starts a detached helper that waits for this process to die
// and then deletes our capture routes. WHY necessary: taskkill /F provides no
// cleanup hook; without the watchdog a killed engine leaves the machine
// blackholed until the next `detour cleanup`. WHY a separate process: a
// goroutine dies with its process  -  only a different process survives /F.
func spawnWatchdog(e *Engine) {
	exe, err := os.Executable()
	if err != nil {
		e.logf("warning: cannot locate self for watchdog (%v); a kill leaves routes behind until 'detour cleanup'", err)
		return
	}
	cmd := exec.Command(exe, "--watchdog", fmt.Sprint(os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		e.logf("warning: watchdog did not start (%v)", err)
		return
	}
	e.wdProc = cmd.Process // WHY: teardown must reap it (leaked otherwise)
	e.logf("watchdog armed | pid=%d", cmd.Process.Pid)
}

// RunWatchdog is the `detour --watchdog <pid>` entrypoint: wait for the
// engine process to exit, then delete capture routes if the adapter remains.
func RunWatchdog(enginePid int) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(enginePid))
	if err != nil {
		// Engine already gone or PID invalid: still try cleanup, best effort.
		cleanupStaleRoutes()
		return
	}
	const WAIT_OBJECT_0 = 0
	for {
		st, _ := windows.WaitForSingleObject(h, 500)
		if st == uint32(WAIT_OBJECT_0) {
			break
		}
	}
	cleanupStaleRoutes()
}

// ---------------- proxy (the per-flow egress picker) ----------------

type routeDecision struct {
	idx         int
	name        string
	adapterName string
	ruleKey     string
	app         string
	unknown     bool
	blocked     bool
	blockReason string
}

func (e *Engine) decideRoute(proto string, local, remote netip.AddrPort) (routeDecision, attrib.Result) {
	res := attrib.Owner(proto, local, remote)
	app := "unknown"
	if res.Exe != "" {
		app = filepath.Base(res.Exe)
	}

	var r rules.Rule
	var matched bool
	if res.Exe != "" {
		r, matched = e.Rules.Lookup(res.Exe)
	}

	dec := routeDecision{
		app:     app,
		unknown: !res.Attributed,
	}

	if matched {
		dec.ruleKey = r.Key()
		if strings.EqualFold(r.Adapter(), "Block") {
			dec.blocked = true
			dec.blockReason = "rule specifies Block"
			dec.adapterName = "Block"
			return dec, res
		}

		idx, name, isUp := e.Table.Resolve(r.Adapter())
		if isUp {
			dec.idx = idx
			dec.name = name
			dec.adapterName = name
			return dec, res
		}

		// Adapter is down or not found
		if strings.EqualFold(r.DownPolicy(), "block") {
			dec.blocked = true
			dec.blockReason = fmt.Sprintf("adapter %q is down (rule policy: block)", r.Adapter())
			dec.adapterName = "Blocked (down)"
			return dec, res
		}

		// DownPolicy == "automatic" -> fallback to Automatic
		d := e.Table.Current()
		if d.Blocked {
			dec.blocked = true
			dec.blockReason = fmt.Sprintf("adapter %q is down and %s", r.Adapter(), d.Reason)
			dec.adapterName = "Blocked"
			return dec, res
		}
		dec.idx = d.Index
		dec.name = d.Name
		dec.adapterName = fmt.Sprintf("Automatic -> %s (fallback from %s)", d.Name, r.Adapter())
		return dec, res
	}

	// No rule match or unattributed: follow Automatic (mainConnection)
	d := e.Table.Current()
	if d.Blocked {
		dec.blocked = true
		dec.blockReason = d.Reason
		dec.adapterName = "Blocked"
		return dec, res
	}
	dec.idx = d.Index
	dec.name = d.Name
	dec.adapterName = "Automatic -> " + d.Name
	return dec, res
}

// DialContext: tun2socks calls this for every TCP flow that entered the TUN.
func (e *Engine) DialContext(ctx context.Context, m *gom.Metadata) (net.Conn, error) {
	local := netip.AddrPortFrom(m.SrcIP, m.SrcPort)
	remote := netip.AddrPortFrom(m.DstIP, m.DstPort)
	dec, res := e.decideRoute("tcp", local, remote)

	fl := flowstat.Flow{
		Proto: "tcp", App: dec.app, Adapter: dec.adapterName, Rule: dec.ruleKey,
		Local: local, Remote: remote, Started: time.Now(),
		DelayMs: res.Delay.Milliseconds(), Unknown: dec.unknown,
	}
	h := e.Stats.Register(&fl)

	if dec.blocked {
		e.logf("flow #%d %s tcp %-19s -> %-21s pid=%-6d app=%-12s BLOCKED (%s)",
			fl.ID, time.Now().Format("15:04:05"), local, remote, res.PID, dec.app, dec.blockReason)
		if e.OnEvent != nil {
			e.OnEvent("policy_block", map[string]interface{}{
				"proto": "tcp", "app": dec.app, "local": local.String(),
				"remote": remote.String(), "reason": dec.blockReason,
			})
		}
		h.Close()
		return nil, fmt.Errorf("connection blocked: %s", dec.blockReason)
	}

	e.logf("flow #%d %s tcp %-19s -> %-21s pid=%-6d app=%-12s rule=%-16s adapter=%-12s delay=%dms unknown=%v",
		fl.ID, time.Now().Format("15:04:05"), local, remote,
		res.PID, dec.app, ruleKeyOrAuto(dec.ruleKey), dec.adapterName, fl.DelayMs, fl.Unknown)

	v6 := remote.Addr().Is6()
	dialer := net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   winsys.ForceEgress(dec.idx, v6),
	}
	conn, err := dialer.DialContext(ctx, "tcp", remote.String())
	if err != nil {
		h.Close()
		return nil, err
	}
	return &egressConn{Conn: conn, h: h}, nil
}

// DialUDP: called per UDP session (first datagram of a remote:port pair).
func (e *Engine) DialUDP(m *gom.Metadata) (net.PacketConn, error) {
	local := netip.AddrPortFrom(m.SrcIP, m.SrcPort)
	remote := netip.AddrPortFrom(m.DstIP, m.DstPort)

	// Attribution retries up to the 250ms cap BEFORE the first datagram leaves.
	dec, res := e.decideRoute("udp", local, remote)
	key := udpKey{PID: res.PID, Port: local.Port()}

	e.udpMu.Lock()
	cached, ok := e.udpDecisions[key]
	if !ok {
		cached = udpDecision{
			idx:         dec.idx,
			name:        dec.name,
			adapterName: dec.adapterName,
			ruleKey:     dec.ruleKey,
			app:         dec.app,
			unknown:     dec.unknown,
			blocked:     dec.blocked,
			blockReason: dec.blockReason,
		}
		if res.PID != 0 {
			e.udpDecisions[key] = cached
		}
	}
	e.udpMu.Unlock()

	fl := flowstat.Flow{
		Proto: "udp", App: cached.app, Adapter: cached.adapterName, Rule: cached.ruleKey,
		Local: local, Remote: remote, Started: time.Now(),
		DelayMs: res.Delay.Milliseconds(), Unknown: cached.unknown,
	}
	h := e.Stats.Register(&fl)

	if cached.blocked {
		e.logf("flow #%d %s udp %-19s -> %-21s pid=%-6d app=%-12s BLOCKED (%s)",
			fl.ID, time.Now().Format("15:04:05"), local, remote, res.PID, cached.app, cached.blockReason)
		if e.OnEvent != nil {
			e.OnEvent("policy_block", map[string]interface{}{
				"proto": "udp", "app": cached.app, "local": local.String(),
				"remote": remote.String(), "reason": cached.blockReason,
			})
		}
		h.Close()
		return nil, fmt.Errorf("datagram blocked: %s", cached.blockReason)
	}

	e.logf("flow #%d %s udp %-19s -> %-21s pid=%-6d app=%-12s rule=%-16s adapter=%-12s delay=%dms unknown=%v",
		fl.ID, time.Now().Format("15:04:05"), local, remote,
		res.PID, cached.app, ruleKeyOrAuto(cached.ruleKey), cached.adapterName, fl.DelayMs, fl.Unknown)

	v6 := remote.Addr().Is6()
	cfg := net.ListenConfig{Control: winsys.ForceEgress(cached.idx, v6)}
	pc, err := cfg.ListenPacket(context.Background(), udpNet(v6), "")
	if err != nil {
		h.Close()
		return nil, err
	}
	return &egressUDP{PacketConn: pc, h: h}, nil
}

func udpNet(v6 bool) string {
	if v6 {
		return "udp6"
	}
	return "udp"
}

func ruleKeyOrAuto(k string) string {
	if k == "" {
		return "(automatic)"
	}
	return k
}

// ---------------- egress-side counting wrappers ----------------

type egressConn struct {
	net.Conn
	h *flowstat.Handle
}

func (c *egressConn) Close() error {
	err := c.Conn.Close()
	c.h.Close() // counters for the totals survive flow teardown
	return err
}

func (c *egressConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.h.AddUp(int64(n))
	}
	return n, err
}

func (c *egressConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.h.AddDown(int64(n))
	}
	return n, err
}

type egressUDP struct {
	net.PacketConn
	h *flowstat.Handle
}

func (c *egressUDP) Close() error {
	err := c.PacketConn.Close()
	c.h.Close()
	return err
}

func (c *egressUDP) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		c.h.AddUp(int64(n))
	}
	return n, err
}

func (c *egressUDP) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.h.AddDown(int64(n))
	}
	return n, a, err
}

// keep imports honest while M1 wires the pieces
var (
	_ = unsafe.Pointer(nil)
	_ = windows.PROCESS_QUERY_LIMITED_INFORMATION
)
