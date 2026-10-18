//go:build windows

package winsys

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// Routing setup/teardown.
//
// WHY two /1 routes instead of replacing the default route:
//   - they beat any default route (/0) without MODIFYING the real default
//     entry, so a crash cannot leave the machine pointing at a dead gateway
//     (the /1s die with the interface), and
//   - it composes better with third-party tools that touch 0/0.
// This is the net-merge design (MIT, credited in README), reused deliberately.
//
// WHY we drive route/address/MTU changes through netsh/route with arguments
// (never `route print` parsing): these calls are argument→effect only; every
// READ in this project (metrics, gateways, route presence, cleanup detection)
// uses IP Helper structs, so there is no text parsing of Windows output
// anywhere. IP Helper's create/delete route entry functions are not exported
// by x/sys v0.46, and hand-writing raw MIB_*ROW2 setter structs risks ABI
// mismatch crashes that a boring proven CLI call does not have.
//
// WHY store=active: routes live only until the interface is removed  -  a
// reboot cannot leave them behind, and the watchdog/taskkill path removes
// them explicitly anyway.

var v4RouteArgs = [][3]string{
	{"0.0.0.0", "128.0.0.0", "0.0.0.0"},
	{"128.0.0.0", "128.0.0.0", "0.0.0.0"},
}

var v6Routes = []string{"::/1", "8000::/1"}

// ConfigureAdapter assigns the TUN's addresses + MTU (active store) and
// returns the interface index.
func ConfigureAdapter(name string, mtu int) (uint32, error) {
	// IPv4 address: 198.18.0.1/24  -  RFC 2544 benchmark space; nothing real
	// lives there, so it can never collide with a LAN address.
	if err := run("netsh", "interface", "ipv4", "set", "address", "name="+name,
		"source=static", "address=198.18.0.1", "mask=255.255.255.0", "store=active"); err != nil {
		return 0, fmt.Errorf("assign IPv4 address: %w", err)
	}
	// IPv6 address: a ULA on purpose. WHY: the OS source-address policy
	// (RFC 6724) prefers IPv4 when the only IPv6 source is a ULA, so dual-stack
	// apps don't eagerly select IPv6 through the TUN. Nothing is ever sent
	// from this address; IPv6 flows arriving here get refused at the forwarder
	// (see engine forwarders) which pushes apps back to IPv4 instantly.
	if err := run("netsh", "interface", "ipv6", "add", "address", "interface="+name,
		"address=fd6e:6d65:7267::1/64", "store=active"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: IPv6 address on TUN: %v\n", err)
	}
	idx, err := waitIface(name)
	if err != nil {
		return 0, err
	}
	if err := run("netsh", "interface", "ipv4", "set", "subinterface",
		"interface="+fmt.Sprint(idx), "mtu="+fmt.Sprint(mtu), "store=active"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: set TUN IPv4 MTU: %v\n", err)
	}
	if err := run("netsh", "interface", "ipv6", "set", "subinterface",
		"interface="+fmt.Sprint(idx), "mtu="+fmt.Sprint(mtu), "store=active"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: set TUN IPv6 MTU: %v\n", err)
	}
	return idx, nil
}

func waitIface(name string) (uint32, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if a, _ := FindByName(name); a != nil && a.Index != 0 {
			return a.Index, nil
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("adapter %q did not appear", name)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// AddCaptureRoutes installs the /1 capture routes on the TUN interface.
// WHY metric 1: every physical adapter's default route sits at metric 30+;
// 1 wins without touching anything else.
func AddCaptureRoutes(idx uint32) error {
	for _, t := range v4RouteArgs {
		if err := run("route", "add", t[0], "mask", t[1], t[2], "metric", "1",
			"if", fmt.Sprint(idx)); err != nil {
			return err
		}
	}
	for _, p := range v6Routes {
		if err := run("netsh", "interface", "ipv6", "add", "route", "prefix="+p,
			"interface="+fmt.Sprint(idx), "metric=1", "store=active"); err != nil {
			return err
		}
	}
	return nil
}

// DelCaptureRoutes removes them. Idempotent: per-route errors are ignored so
// a partially-installed state still cleans up fully.
func DelCaptureRoutes(idx uint32) {
	for _, t := range v4RouteArgs {
		run("route", "delete", t[0], "mask", t[1], t[2], "if", fmt.Sprint(idx))
	}
	for _, p := range v6Routes {
		run("netsh", "interface", "ipv6", "delete", "route", "prefix="+p,
			"interface="+fmt.Sprint(idx), "store=active")
	}
}

// LeftoverCaptureRoutes reports rows of the form dst=0/1 or 128.0.0.0/1
// (IPv4) whose interface owns a "Detour"-tunnel adapter left by a crash.
// The engine calls this at startup (CleanupStale) and the CLI exposes it as
// `detour cleanup`.
func LeftoverCaptureRoutes() ([]windows.MibIpForwardRow2, error) {
	var tbl *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &tbl); err != nil {
		return nil, err
	}
	var out []windows.MibIpForwardRow2
	for _, r := range tbl.Rows() {
		if r.DestinationPrefix.PrefixLength != 1 {
			continue
		}
		prefix, err := NetipFromRaw(r.DestinationPrefix.Prefix)
		if err != nil {
			continue
		}
		if !prefix.IsValid() || (!prefix.IsUnspecified() && prefix != netip.MustParseAddr("128.0.0.0")) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// NetipFromRaw decodes a RawSockaddrInet union (family + address bytes).
// WHY manual decode: x/sys keeps the union raw; the four IPv4 octets sit at
// the start of the Data words (little-endian DWORDs = address octets in order).
func NetipFromRaw(sa windows.RawSockaddrInet) (netip.Addr, error) {
	switch sa.Family {
	case windows.AF_INET:
		dw := uint32(sa.Data[0])
		return netip.AddrFrom4([4]byte{
			byte(dw), byte(dw >> 8), byte(dw >> 16), byte(dw >> 24),
		}), nil
	default:
		return netip.Addr{}, fmt.Errorf("unsupported family %d", sa.Family)
	}
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	// WHY HideWindow: netsh/route default to attaching a console window when
	// run from a GUI-less service context; hide it so the engine's console
	// stays our log.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err,
			strings.TrimSpace(string(out)))
	}
	return nil
}
