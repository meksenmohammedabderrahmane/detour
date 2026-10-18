//go:build windows

// detour is the Windows per-app network routing CLI and service.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"detour/internal/adapters"
	"detour/internal/config"
	"detour/internal/engine"
	"detour/internal/flowstat"
	"detour/internal/ipc"
	"detour/internal/rules"
	"detour/internal/service"
	"detour/internal/winsys"
)

func main() {
	args := os.Args[1:]
	if len(args) > 1 && args[0] == "--watchdog" {
		p := 0
		fmt.Sscanf(args[1], "%d", &p)
		engine.RunWatchdog(p)
		return
	}
	cmd := "help"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "service":
		if err := cmdService(args[1:]); err != nil {
			fatal(err)
		}
	case "on":
		if err := cmdEngineOn(); err != nil {
			fatal(err)
		}
	case "off":
		if err := cmdEngineOff(); err != nil {
			fatal(err)
		}
	case "rules":
		if err := cmdRules(args[1:]); err != nil {
			fatal(err)
		}
	case "settings":
		if err := cmdSettings(args[1:]); err != nil {
			fatal(err)
		}
	case "adapters":
		if err := cmdAdapters(); err != nil {
			fatal(err)
		}
	case "run":
		if err := cmdRun(args[1:]); err != nil {
			fatal(err)
		}
	case "status":
		if err := cmdStatus(); err != nil {
			fatal(err)
		}
	case "cleanup":
		if err := cmdCleanup(); err != nil {
			fatal(err)
		}
	case "debug-tcp":
		debugTCP()
	case "debug-udp":
		debugUDP()
	default:
		usage()
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "detour: %v\n", err)
	os.Exit(1)
}

func usage() {
	fmt.Println(`detour  -  per-app network routing CLI

Service Management (admin):
  detour service install                install Detour service (auto-start, rapid recovery)
  detour service uninstall              uninstall Detour service (cleans routes/adapters)
  detour service start                  start Detour service
  detour service stop                   stop Detour service
  detour service status                 report service status

Control & Rules (non-admin via IPC):
  detour on                             turn engine ON
  detour off                            turn engine OFF
  detour status                         display live status and counters
  detour rules [list]                   list configured rules
  detour rules set <app> <adapter>      pin app to adapter (--down-policy=automatic|block)
  detour rules delete <app>             remove app rule
  detour settings [get]                 view main connection and fallback policy
  detour settings set [...]             update main connection and fallback policy

Diagnostics & Dev:
  detour adapters                       list adapters and test egress
  detour run --rule "APP=ADAPTER" [...] run engine in foreground for dev (admin)
  detour cleanup                        remove leftover routes and adapters`)
}

func isAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// ---------------- service ----------------

func cmdService(args []string) error {
	action := "status"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "install":
		if err := service.Install(); err != nil {
			return err
		}
		fmt.Println("Detour service installed successfully (Auto-start, SYSTEM, recovery actions armed).")
		return nil
	case "uninstall":
		if err := service.Uninstall(); err != nil {
			return err
		}
		fmt.Println("Detour service uninstalled (all routes and adapters cleaned).")
		return nil
	case "start":
		if err := service.Start(); err != nil {
			return err
		}
		fmt.Println("Detour service started.")
		return nil
	case "stop":
		if err := service.Stop(); err != nil {
			return err
		}
		fmt.Println("Detour service stopped.")
		return nil
	case "status":
		st, err := service.Status()
		if err != nil {
			return err
		}
		fmt.Printf("Service status: %s\n", st)
		return nil
	case "run":
		// Called by Windows SCM
		return service.Run(false)
	default:
		return fmt.Errorf("unknown service action %q (use install, uninstall, start, stop, status)", action)
	}
}

// ---------------- IPC client commands ----------------

func cmdEngineOn() error {
	client := ipc.NewClient("")
	var res map[string]string
	if err := client.Call("engine.on", nil, &res); err != nil {
		return err
	}
	fmt.Println("Detour engine is ON (via service)")
	return nil
}

func cmdEngineOff() error {
	client := ipc.NewClient("")
	var res map[string]string
	if err := client.Call("engine.off", nil, &res); err != nil {
		return err
	}
	fmt.Println("Detour engine is OFF (via service)")
	return nil
}

func cmdRules(args []string) error {
	action := "list"
	if len(args) > 0 {
		action = args[0]
	}

	client := ipc.NewClient("")

	switch action {
	case "list":
		var rulesMap map[string]config.RuleEntry
		if err := client.Call("rules.list", nil, &rulesMap); err != nil {
			return err
		}
		if len(rulesMap) == 0 {
			fmt.Println("no rules configured")
			return nil
		}
		fmt.Printf("%-32s %-16s %-12s\n", "APPLICATION", "ADAPTER", "DOWN POLICY")
		fmt.Printf("%-32s %-16s %-12s\n", strings.Repeat("-", 32), strings.Repeat("-", 16), strings.Repeat("-", 12))
		for app, r := range rulesMap {
			fmt.Printf("%-32s %-16s %-12s\n", app, r.Adapter, r.DownPolicy)
		}
		return nil

	case "set":
		downPolicy := "automatic"
		var posArgs []string
		for i := 1; i < len(args); i++ {
			arg := args[i]
			if strings.HasPrefix(arg, "--down-policy=") {
				downPolicy = strings.TrimPrefix(arg, "--down-policy=")
			} else if strings.HasPrefix(arg, "--down=") {
				downPolicy = strings.TrimPrefix(arg, "--down=")
			} else if arg == "--down-policy" || arg == "--down" {
				if i+1 < len(args) {
					downPolicy = args[i+1]
					i++
				}
			} else if !strings.HasPrefix(arg, "-") {
				posArgs = append(posArgs, arg)
			}
		}
		if len(posArgs) < 2 {
			return fmt.Errorf("usage: detour rules set <app> <adapter> [--down-policy=automatic|block]")
		}
		app := posArgs[0]
		adapter := posArgs[1]

		var res map[string]string
		params := map[string]string{
			"app":         app,
			"adapter":     adapter,
			"down_policy": downPolicy,
		}
		if err := client.Call("rules.set", params, &res); err != nil {
			return err
		}
		fmt.Printf("Rule set: %s -> %s (down: %s)\n", app, adapter, downPolicy)
		return nil

	case "delete", "remove", "del":
		if len(args) < 2 {
			return fmt.Errorf("usage: detour rules delete <app>")
		}
		app := args[1]
		var res map[string]string
		params := map[string]string{"app": app}
		if err := client.Call("rules.delete", params, &res); err != nil {
			return err
		}
		fmt.Printf("Rule deleted for %s\n", app)
		return nil

	default:
		return fmt.Errorf("unknown rules action %q (use list, set, delete)", action)
	}
}

func cmdSettings(args []string) error {
	action := "get"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = args[0]
		args = args[1:]
	}

	client := ipc.NewClient("")

	switch action {
	case "get":
		var res struct {
			Settings config.Settings `json:"settings"`
			EngineOn bool            `json:"engine_on"`
		}
		if err := client.Call("settings.get", nil, &res); err != nil {
			return err
		}
		fmt.Println("Detour Service Settings:")
		fmt.Printf("  Engine State:        %v\n", map[bool]string{true: "ON", false: "OFF"}[res.EngineOn])
		fmt.Printf("  Main Connection:     %s\n", res.Settings.MainConnection)
		if res.Settings.MainConnectionName != "" {
			fmt.Printf("  Main Friendly Name:  %s\n", res.Settings.MainConnectionName)
		}
		if res.Settings.MainConnectionGuid != "" {
			fmt.Printf("  Main Adapter GUID:   %s\n", res.Settings.MainConnectionGuid)
		}
		fmt.Printf("  Main Down Policy:    %s\n", res.Settings.MainDownPolicy)
		fmt.Printf("  IPv6 Mode:           %s\n", res.Settings.IPv6)
		return nil

	case "set":
		fs := flag.NewFlagSet("settings set", flag.ContinueOnError)
		mainConn := fs.String("main-connection", "", "main connection (auto or adapter name/guid)")
		mainPolicy := fs.String("main-down-policy", "", "main down policy (fallback or block)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		params := make(map[string]string)
		if *mainConn != "" {
			params["main_connection"] = *mainConn
		}
		if *mainPolicy != "" {
			params["main_down_policy"] = *mainPolicy
		}
		if len(params) == 0 {
			return fmt.Errorf("specify at least one setting (--main-connection or --main-down-policy)")
		}

		var res map[string]string
		if err := client.Call("settings.set", params, &res); err != nil {
			return err
		}
		fmt.Println("Settings updated.")
		return nil

	default:
		return fmt.Errorf("unknown settings action %q (use get or set)", action)
	}
}

// ---------------- adapters ----------------

func cmdAdapters() error {
	// Try IPC first
	client := ipc.NewClient("")
	var list []adapters.Adapter
	err := client.Call("adapters.list", nil, &list)
	if err != nil {
		// Fall back to direct local enumeration
		intel, iErr := winsys.Enumerate()
		if iErr != nil {
			return iErr
		}
		for _, a := range intel {
			list = append(list, adapters.Adapter{
				Guid:         a.Guid,
				Name:         a.Name,
				Description:  a.Description,
				Index:        int(a.Index),
				Type:         int(a.Type),
				IsTunnel:     !a.IsPhysical(),
				OperUp:       a.OperUp,
				HasV4Gateway: a.HasV4Gateway,
				HasGlobalV6:  a.HasGlobalV6,
				V4Metric:     a.V4Metric,
			})
		}
	}

	fmt.Printf("%-24s %-6s %-7s %-8s %-8s %s\n", "ADAPTER", "INDEX", "STATUS", "GATEWAY", "METRIC", "GUID")
	fmt.Printf("%-24s %-6s %-7s %-8s %-8s %s\n", strings.Repeat("-", 24), strings.Repeat("-", 6),
		strings.Repeat("-", 7), strings.Repeat("-", 8), strings.Repeat("-", 8), strings.Repeat("-", 38))
	for _, a := range list {
		st := "DOWN"
		if a.OperUp {
			st = "UP"
		}
		gw := "NO"
		if a.HasV4Gateway {
			gw = "YES"
		}
		fmt.Printf("%-24s %-6d %-7s %-8s %-8d %s\n",
			truncate(a.Name, 24), a.Index, st, gw, a.V4Metric, a.Guid)
	}
	return nil
}

// ---------------- status ----------------

func cmdStatus() error {
	// Try IPC status.get first
	client := ipc.NewClient("")
	var res struct {
		On        bool              `json:"on"`
		Automatic adapters.Default  `json:"automatic"`
		Stats     flowstat.Snapshot `json:"stats"`
	}
	err := client.Call("status.get", nil, &res)
	if err == nil {
		fmt.Printf("ENGINE STATUS: %s\n", map[bool]string{true: "ON", false: "OFF"}[res.On])
		if res.Automatic.Blocked {
			fmt.Printf("AUTOMATIC:     BLOCKED (%s)\n", res.Automatic.Reason)
		} else if res.Automatic.Name != "" {
			fmt.Printf("AUTOMATIC:     %s (idx %d)  -  %s\n", res.Automatic.Name, res.Automatic.Index, res.Automatic.Reason)
		}
		renderSnapshot(&res.Stats)
		return nil
	}

	// Fallback to reading ProgramData status.json file
	path := engine.StatusPath()
	s, err := flowstat.ReadSnapshot(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Detour engine is not running (service stopped or idle).")
			return nil
		}
		return fmt.Errorf("read status: %w", err)
	}
	renderSnapshot(s)
	return nil
}

func renderSnapshot(s *flowstat.Snapshot) {
	if s == nil || (len(s.Group) == 0 && len(s.Kernel) == 0) {
		fmt.Println("no active or recent flows recorded")
		return
	}

	fmt.Println("\nAPPLICATION TRAFFIC (per-app egress counters):")
	fmt.Printf("%-20s %-20s %10s %12s %6s\n", "APPLICATION", "ADAPTER", "UPLOAD", "DOWNLOAD", "FLOWS")
	fmt.Printf("%-20s %-20s %10s %12s %6s\n", strings.Repeat("-", 20), strings.Repeat("-", 20),
		strings.Repeat("-", 10), strings.Repeat("-", 12), strings.Repeat("-", 6))
	for _, g := range s.Group {
		fmt.Printf("%-20s %-20s %10s %12s %6d\n",
			truncate(g.App, 20), truncate(g.Adapter, 20),
			formatBytes(uint64(g.Up)), formatBytes(uint64(g.Down)), g.Flows)
	}

	if len(s.Kernel) > 0 {
		fmt.Println("\nKERNEL DELTAS (since engine start):")
		for _, k := range s.Kernel {
			fmt.Printf("  ADAPTER=%-18s IN=%12s OUT=%12s\n", k.Adapter, formatBytes(k.In), formatBytes(k.Out))
		}
	}
}

func formatBytes(b uint64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// ---------------- run (dev standalone runner) ----------------

type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("detour run", flag.ContinueOnError)
	var ruleFlags stringSlice
	fs.Var(&ruleFlags, "rule", "app=adapter rule (repeatable; e.g. --rule curl.exe=Ethernet)")
	runFor := fs.Duration("run-for", 0, "run for this duration then exit cleanly (e.g. 30s); 0 = until Ctrl+C")
	ipv6 := fs.String("ipv6", "clamp", "IPv6 policy: clamp | relay | off")
	mtu := fs.Int("mtu", engine.DefaultMTU, "TUN adapter MTU")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !isAdmin() {
		return fmt.Errorf("detour run needs an elevated console (right-click -> Run as administrator)")
	}

	rs, err := rules.New(ruleFlags)
	if err != nil {
		return fmt.Errorf("parse rules: %w", err)
	}

	eng := engine.New(rs, *mtu, *ipv6)
	if err := eng.On(); err != nil {
		return err
	}
	defer eng.Off()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	if *runFor > 0 {
		fmt.Printf("running (auto-stop after %v). ctrl+C stops cleanly now.\n", *runFor)
		select {
		case <-sigCh:
			fmt.Println("\nreceived interrupt  -  stopping cleanly...")
		case <-time.After(*runFor):
			fmt.Println("\nauto-stop duration reached  -  stopping cleanly...")
		}
	} else {
		fmt.Println("running. press ctrl+C to stop cleanly.")
		<-sigCh
		fmt.Println("\nreceived interrupt  -  stopping cleanly...")
	}
	return nil
}

// ---------------- cleanup ----------------

func cmdCleanup() error {
	rows, err := winsys.LeftoverCaptureRoutes()
	if err != nil {
		return err
	}
	a, _ := winsys.FindByName("Detour")
	if a == nil && len(rows) == 0 {
		fmt.Println("nothing to clean  -  no leftover capture routes found")
		return nil
	}
	if !isAdmin() {
		return fmt.Errorf("detour cleanup needs an elevated console")
	}
	if a != nil {
		winsys.DelCaptureRoutes(a.Index)
		fmt.Printf("removed capture routes on adapter \"Detour\" (idx %d)\n", a.Index)
	}
	for _, r := range rows {
		prefix, err := winsys.NetipFromRaw(r.DestinationPrefix.Prefix)
		if err == nil {
			_ = exec.Command("route", "delete", prefix.String(), "mask", "128.0.0.0", "if", fmt.Sprint(r.InterfaceIndex)).Run()
		}
	}
	return nil
}

// ---------------- debug tools ----------------

func debugTCP() {
	fmt.Println("streaming TCP owner rows for 6 seconds...")
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := winsys.TCPSnapshot()
		if err != nil {
			fmt.Println("read error:", err)
			return
		}
		for _, r := range rows {
			if r.Remote.Port() == 80 || r.Remote.Port() == 443 {
				path, _ := winsys.ExePath(r.PID)
				fmt.Printf("  local=%-21s remote=%-21s state=%d pid=%-6d exe=%s\n",
					r.Local, r.Remote, r.State, r.PID, truncate(path, 48))
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func debugUDP() {
	fmt.Println("streaming UDP owner rows for 5 seconds...")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := winsys.UDPSnapshot()
		if err != nil {
			fmt.Println("read error:", err)
			return
		}
		for i, r := range rows {
			if i == 12 {
				fmt.Println("  ... (truncated)")
				break
			}
			path, _ := winsys.ExePath(r.PID)
			fmt.Printf("  local=%-22s pid=%-7d exe=%s\n", r.Local, r.PID, truncate(path, 46))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "..."
}

var _ = io.Discard
var _ = bufio.NewReader
var _ = context.Background
var _ = sort.Strings
var _ = net.Dial
var _ = http.Get
var _ = errors.New
var _ = json.Marshal
