//go:build windows

package service

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"detour/internal/config"
	"detour/internal/engine"
	"detour/internal/ipc"
	"detour/internal/rules"
	"detour/internal/winsys"
)

const (
	ServiceName        = "DetourService"
	ServiceDisplayName = "Detour Network Engine Service"
	ServiceDescription = "Per-application network connection routing engine."
)

// Install installs the service with auto-start and rapid recovery actions.
func Install() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("abs executable path: %w", err)
	}

	// Capture installing user SID to authorize in named pipe DACL
	sid, err := ipc.CurrentUserSID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not determine user SID (%v)\n", err)
	} else {
		store, sErr := config.NewStore("")
		if sErr == nil {
			_ = store.Mutate(func(cfg *config.Config) error {
				cfg.InstallingUserSID = sid
				return nil
			})
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM (need Administrator privileges): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s is already installed", ServiceName)
	}

	cfg := mgr.Config{
		DisplayName: ServiceDisplayName,
		Description: ServiceDescription,
		StartType:   mgr.StartAutomatic,
	}

	s, err = m.CreateService(ServiceName, exePath, cfg, "service", "run")
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// SCM rapid recovery: restart after 2s on 1st, 2nd, and subsequent failures
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
	}
	_ = s.SetRecoveryActions(actions, 60)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)

	return nil
}

// Uninstall stops and removes the service, leaving no leftover routes or adapter.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()

	// Stop if running
	st, err := s.Query()
	if err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(10 * time.Second)
		for {
			st, err = s.Query()
			if err != nil || st.State == svc.Stopped || time.Now().After(deadline) {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	// Ensure no leftover adapter or routes remain
	cleanupLeftovers()
	return nil
}

// Start starts the service via SCM.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", ServiceName, err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

// Stop stops the service via SCM.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", ServiceName, err)
	}
	defer s.Close()

	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	return nil
}

// Status reports the current service state.
func Status() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "SCM_DISCONNECTED", err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return "NOT_INSTALLED", nil
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return "UNKNOWN", err
	}
	switch st.State {
	case svc.Stopped:
		return "STOPPED", nil
	case svc.StartPending:
		return "START_PENDING", nil
	case svc.StopPending:
		return "STOP_PENDING", nil
	case svc.Running:
		return "RUNNING", nil
	case svc.ContinuePending:
		return "CONTINUE_PENDING", nil
	case svc.PausePending:
		return "PAUSE_PENDING", nil
	case svc.Paused:
		return "PAUSED", nil
	default:
		return fmt.Sprintf("STATE_%d", st.State), nil
	}
}

// Run is the main service worker invoked by SCM or debug runner.
func Run(debug bool) error {
	h := &serviceHandler{debug: debug}
	if debug {
		return runInteractive(h)
	}
	return svc.Run(ServiceName, h)
}

type serviceHandler struct {
	debug bool
}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// 1. Load config
	store, err := config.NewStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "detour service: failed to initialize config store: %v\n", err)
		return true, 1
	}
	cfg := store.Config()

	// 2. Initialize Rules Set
	rs, _ := rules.New(nil)
	for k, r := range cfg.Rules {
		rs.SetRule(k, r.Adapter, r.AdapterGuid, r.DownPolicy)
	}

	// 3. Initialize Engine
	eng := engine.New(rs, engine.DefaultMTU, cfg.Settings.IPv6)
	_ = eng.Table.Refresh()
	eng.SetPolicy(cfg.Settings.MainConnection, cfg.Settings.MainDownPolicy)

	// 4. Create Named Pipe Listener & Server
	listener, err := ipc.Listen(ipc.DefaultPipeName, cfg.InstallingUserSID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "detour service: failed to create named pipe listener: %v\n", err)
		return true, 2
	}
	ipcServer := ipc.NewServer(listener)

	// 5. Wire engine events to IPC broadcast
	eng.OnEvent = func(evType string, data interface{}) {
		ipcServer.Broadcast(ipc.Event{Type: evType, Data: data})
	}

	// 6. Register RPC Handlers
	registerHandlers(ipcServer, store, eng)

	// 7. Start IPC server
	go func() {
		_ = ipcServer.Serve()
	}()

	// 8. If config EngineOn is true, start engine immediately
	if cfg.EngineOn {
		if err := eng.On(); err != nil {
			fmt.Fprintf(os.Stderr, "detour service: engine.On failed: %v\n", err)
		}
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// 9. Main service control loop
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				if eng.IsOn() {
					eng.Off()
				}
				_ = ipcServer.Stop()
				cleanupLeftovers()
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		}
	}
}

func registerHandlers(srv *ipc.Server, store *config.Store, eng *engine.Engine) {
	// adapters.list
	srv.Handle("adapters.list", func(_ json.RawMessage) (interface{}, error) {
		// WHY refresh every call: the table is a boot-time/enumerate-time
		// snapshot (OperStatus, gateway, metric all change without any
		// service restart); serving the stale cache made UI/CLI report
		// Up adapters as DOWN. GAA enumeration is ~1 ms, so per-call cost
		// is negligible.
		if err := eng.Table.Refresh(); err != nil {
			return nil, fmt.Errorf("refresh adapters: %w", err)
		}
		return eng.Table.All(), nil
	})

	// rules.list
	srv.Handle("rules.list", func(_ json.RawMessage) (interface{}, error) {
		return store.Config().Rules, nil
	})

	// rules.set
	type RuleSetParams struct {
		App         string `json:"app"`
		Adapter     string `json:"adapter"`
		AdapterGuid string `json:"adapter_guid,omitempty"`
		DownPolicy  string `json:"down_policy,omitempty"`
	}
	srv.Handle("rules.set", func(params json.RawMessage) (interface{}, error) {
		var p RuleSetParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		if p.App == "" || p.Adapter == "" {
			return nil, fmt.Errorf("app and adapter are required")
		}
		if p.DownPolicy == "" {
			p.DownPolicy = config.DownPolicyAutomatic
		}
		err := store.Mutate(func(cfg *config.Config) error {
			cfg.Rules[p.App] = config.RuleEntry{
				Adapter:     p.Adapter,
				AdapterGuid: p.AdapterGuid,
				DownPolicy:  p.DownPolicy,
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		eng.Rules.SetRule(p.App, p.Adapter, p.AdapterGuid, p.DownPolicy)
		srv.Broadcast(ipc.Event{Type: "rules", Data: store.Config().Rules})
		return map[string]string{"status": "ok"}, nil
	})

	// rules.delete
	type RuleDeleteParams struct {
		App string `json:"app"`
	}
	srv.Handle("rules.delete", func(params json.RawMessage) (interface{}, error) {
		var p RuleDeleteParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		err := store.Mutate(func(cfg *config.Config) error {
			delete(cfg.Rules, p.App)
			return nil
		})
		if err != nil {
			return nil, err
		}
		eng.Rules.Delete(p.App)
		srv.Broadcast(ipc.Event{Type: "rules", Data: store.Config().Rules})
		return map[string]string{"status": "ok"}, nil
	})

	// settings.get
	srv.Handle("settings.get", func(_ json.RawMessage) (interface{}, error) {
		cfg := store.Config()
		return map[string]interface{}{
			"settings":  cfg.Settings,
			"engine_on": cfg.EngineOn,
		}, nil
	})

	// settings.set
	type SettingsSetParams struct {
		MainConnection     *string `json:"main_connection,omitempty"`
		MainConnectionName *string `json:"main_connection_name,omitempty"`
		MainConnectionGuid *string `json:"main_connection_guid,omitempty"`
		MainDownPolicy     *string `json:"main_down_policy,omitempty"`
	}
	srv.Handle("settings.set", func(params json.RawMessage) (interface{}, error) {
		var p SettingsSetParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		err := store.Mutate(func(cfg *config.Config) error {
			if p.MainConnection != nil {
				cfg.Settings.MainConnection = *p.MainConnection
			}
			if p.MainConnectionName != nil {
				cfg.Settings.MainConnectionName = *p.MainConnectionName
			}
			if p.MainConnectionGuid != nil {
				cfg.Settings.MainConnectionGuid = *p.MainConnectionGuid
			}
			if p.MainDownPolicy != nil {
				cfg.Settings.MainDownPolicy = *p.MainDownPolicy
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		cur := store.Config()
		eng.SetPolicy(cur.Settings.MainConnection, cur.Settings.MainDownPolicy)
		srv.Broadcast(ipc.Event{Type: "settings", Data: cur.Settings})
		return map[string]string{"status": "ok"}, nil
	})

	// engine.on
	srv.Handle("engine.on", func(_ json.RawMessage) (interface{}, error) {
		if !eng.IsOn() {
			if err := eng.On(); err != nil {
				return nil, err
			}
		}
		_ = store.Mutate(func(cfg *config.Config) error {
			cfg.EngineOn = true
			return nil
		})
		srv.Broadcast(ipc.Event{Type: "engine_state", Data: map[string]bool{"on": true}})
		return map[string]string{"status": "on"}, nil
	})

	// engine.off
	srv.Handle("engine.off", func(_ json.RawMessage) (interface{}, error) {
		if eng.IsOn() {
			eng.Off()
		}
		_ = store.Mutate(func(cfg *config.Config) error {
			cfg.EngineOn = false
			return nil
		})
		srv.Broadcast(ipc.Event{Type: "engine_state", Data: map[string]bool{"on": false}})
		return map[string]string{"status": "off"}, nil
	})

	// status.get
	srv.Handle("status.get", func(_ json.RawMessage) (interface{}, error) {
		snap := eng.Stats.Snapshot()
		return map[string]interface{}{
			"on":        eng.IsOn(),
			"automatic": eng.Table.Current(),
			"stats":     snap,
		}, nil
	})
}

func cleanupLeftovers() {
	if a, err := winsys.FindByName("Detour"); err == nil && a != nil {
		winsys.DelCaptureRoutes(a.Index)
	}
	rows, err := winsys.LeftoverCaptureRoutes()
	if err == nil {
		for _, r := range rows {
			prefix, err := winsys.NetipFromRaw(r.DestinationPrefix.Prefix)
			if err == nil {
				var mask string
				if prefix.IsUnspecified() {
					mask = "128.0.0.0"
				} else {
					mask = "128.0.0.0"
				}
				_ = runCmd("route", "delete", prefix.String(), "mask", mask, "if", fmt.Sprint(r.InterfaceIndex))
			}
		}
	}
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func runInteractive(h *serviceHandler) error {
	changes := make(chan svc.Status, 10)
	requests := make(chan svc.ChangeRequest, 10)
	go func() {
		for st := range changes {
			if h.debug {
				fmt.Printf("[service status] %+v\n", st)
			}
		}
	}()
	_, _ = h.Execute(nil, requests, changes)
	return nil
}
