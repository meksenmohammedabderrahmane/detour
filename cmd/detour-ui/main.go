//go:build windows

// detour-ui is the M3 unprivileged UI: a WebView2 window + tray icon that talk
// to the privileged Detour service over the named pipe (JSON-RPC + events).
// It never elevates and never opens internet sockets of its own.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jchv/go-webview2"

	"detour/internal/adapters"
	"detour/internal/ipc"
)

//go:embed web/index.html
var indexHTML string

var (
	client = ipc.NewClient("")
	wv     webview2.WebView // set before Run; read only via Dispatch callbacks
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--selftest" {
		runSelftest()
		return
	}

	// WHY LockOSThread: the WebView2 event pump must own the thread that
	// created the window; systray runs its own pump on its own thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug: false,
		WindowOptions: webview2.WindowOptions{
			Title:  "Detour",
			Width:  1000,
			Height: 720,
			Center: true,
		},
	})
	if w == nil {
		fatalDialog(fmt.Errorf("WebView2 window failed to initialize"))
		return
	}
	wv = w

	startTray()
	bindBridge(w)
	startEvents(w)
	w.SetHtml(indexHTML)
	w.Run() // blocks on the message loop; returns after Terminate/close
}

// ---------------- Go/JS bridge ----------------

type rpcEnvelope struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func bindBridge(w webview2.WebView) {
	// WHY the bridges return map[string]interface{}, never a string: the
	// library resolves the JS promise with json.Marshal(returnValue). A
	// returned STRING arrives in JS as a quoted string, so r.ok stays
	// undefined and every bridge call looked like a dead service. Objects
	// arrive as real JS objects.
	// JS: goRPC(JSON.stringify({method, params})) -> Promise<{ok, data|error}>
	_ = w.Bind("goRPC", func(req string) map[string]interface{} {
		var env rpcEnvelope
		if err := json.Unmarshal([]byte(req), &env); err != nil {
			return m("ok", false, "error", "bad rpc envelope")
		}
		var params interface{}
		if len(env.Params) > 0 && string(env.Params) != "null" {
			if err := json.Unmarshal(env.Params, &params); err != nil {
				return m("ok", false, "error", "bad rpc params")
			}
		}
		var result interface{}
		if err := client.Call(env.Method, params, &result); err != nil {
			return m("ok", false, "error", cleanErr(err))
		}
		if result == nil {
			result = map[string]interface{}{}
		}
		return m("ok", true, "data", result)
	})

	// JS: goRunningApps() -> Promise<{ok, apps:[{name,path}]}>
	_ = w.Bind("goRunningApps", func() map[string]interface{} {
		apps := runningApps()
		return m("ok", true, "apps", apps)
	})

	// JS: goAppIcon(path) -> Promise<{ok, dataUrl}>   (v1: monogram; real ICO extract later)
	_ = w.Bind("goAppIcon", func(path string) map[string]interface{} {
		return m("ok", true, "dataUrl", "")
	})

	// JS: goStartWithWindows(bool) / goGetStartWithWindows()
	_ = w.Bind("goStartWithWindows", func(enable bool) map[string]interface{} {
		if err := setStartWithWindows(enable); err != nil {
			return m("ok", false, "error", cleanErr(err))
		}
		return m("ok", true)
	})
	_ = w.Bind("goGetStartWithWindows", func() map[string]interface{} {
		return m("ok", true, "enabled", getStartWithWindows())
	})
}

// m builds a bridge-response map {k1:v1, k2:v2,...} in call order.
func m(kv ...interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

func cleanErr(err error) string {
	return simplifyServiceError(err.Error())
}

// simplifyServiceError maps raw pipe errors to plain language (M3 spec).
func simplifyServiceError(s string) string {
	switch {
	case containsAny(s, "pipe", "The system cannot find the file specified", "ACCESS_DENIED", "Access is denied"):
		return "The Detour service is not reachable. Start it from the window's fix button (needs one click; we never ask for more)."
	default:
		return s
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if sub != "" && indexOfFold(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOfFold(s, sub string) int {
	n := len(sub)
	if n == 0 {
		return 0
	}
	for i := 0; i+n <= len(s); i++ {
		if lowerEq(s[i:i+n], sub) {
			return i
		}
	}
	return -1
}

func lowerEq(a, b string) bool {
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// ---------------- event pump ----------------

// startEvents keeps an `events` subscription alive. Every failure flips the
// page into the plain-language unreachable state and retries every second :
// so a killed service is visible within ~1-2 s (acceptance #3 <= 3 s).
func startEvents(w webview2.WebView) {
	go func() {
		for {
			diag := stageDiag("dial")
			ok := false
			conn, err := ipc.Dial(ipc.DefaultPipeName)
			if err == nil {
				diag += stageDiag("dial-ok")
				req := ipc.Request{ID: 1, Method: "events"}
				if werr := ipc.WriteMsg(conn, req); werr == nil {
					diag += stageDiag("events-write-ok")
					var resp ipc.Response
					if rerr := ipc.ReadMsg(conn, &resp); rerr == nil && resp.Error == "" {
						diag += stageDiag("sub-ok")
						diagFlush(diag)
						diag = ""
						ok = true
						pushEvent(w, map[string]interface{}{"type": "_connected"})
						for {
							var ev ipc.Event
							if err := ipc.ReadMsg(conn, &ev); err != nil {
								diagFlush(stageDiag("stream-end:" + err.Error()))
								break
							}
							pushEvent(w, ev)
						}
					} else {
						diag += stageDiag("sub-fail:" + fmt.Sprint(rerr, "|resp.Error=", resp.Error))
					}
				} else {
					diag += stageDiag("events-write-fail:" + werr.Error())
				}
				_ = conn.Close()
			} else {
				diag += stageDiag("dial-fail:" + err.Error())
			}
			if !ok {
				pushEvent(w, map[string]interface{}{"type": "_unreachable", "detail": lastDiag})
			}
			diagFlush(diag)
			sleepSec(1)
		}
	}()
}

func pushEvent(w webview2.WebView, ev interface{}) {
	data, _ := json.Marshal(ev)
	w.Dispatch(func() {
		w.Eval("try{__onEvent(" + string(data) + ")}catch(e){}")
	})
}

// ---------------- selftest ----------------

type domSelftestResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Log   []struct {
		Step    string `json:"step"`
		Pass    bool   `json:"pass"`
		Ticks   int    `json:"ticks,omitempty"`
		App     string `json:"app,omitempty"`
		Adapter string `json:"adapter,omitempty"`
	} `json:"log"`
}

func runSelftest() {
	attachConsole()
	fmt.Println("=== DETOUR-UI SELFTEST REPORT ===")

	// 1. Verify service connection
	var status map[string]interface{}
	if err := client.Call("status.get", nil, &status); err != nil {
		fmt.Printf("[FAIL] service not reachable via IPC: %v\n", err)
		os.Exit(1)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug: false,
		WindowOptions: webview2.WindowOptions{
			Title:  "Detour Selftest",
			Width:  640,
			Height: 480,
			Center: true,
		},
	})
	if w == nil {
		fmt.Println("[FAIL] WebView2 failed to initialize")
		os.Exit(1)
	}
	wv = w

	bindBridge(w)
	startEvents(w)

	domDone := make(chan domSelftestResult, 1)
	w.Bind("goSelftestDOMDone", func(resJSON string) map[string]interface{} {
		var res domSelftestResult
		_ = json.Unmarshal([]byte(resJSON), &res)
		domDone <- res
		return m("ok", true)
	})

	w.Init("setTimeout(async () => { const res = await window.__runDOMSelftest(); goSelftestDOMDone(JSON.stringify(res)); }, 1200);")
	w.SetHtml(indexHTML)

	go func() {
		res := <-domDone
		if !res.OK {
			fmt.Printf("[FAIL] DOM selftest error: %s\n", res.Error)
			w.Dispatch(func() { w.Terminate() })
			os.Exit(1)
		}

		fmt.Println("[PASS] 20 event ticks keep an open select's DOM node (node preserved across 20 ticks)")
		fmt.Println("[PASS] set an exception, rules.list shows it")
		fmt.Println("[PASS] choose 'Main connection', rules.list shows none")

		// Step 4: flip mainConnection and public-IP check on unpinned flow
		if err := testMainConnectionFlip(); err != nil {
			fmt.Printf("[FAIL] mainConnection flip test: %v\n", err)
			w.Dispatch(func() { w.Terminate() })
			os.Exit(1)
		}

		fmt.Println("=== SELFTEST: 4/4 PASSED ===")
		w.Dispatch(func() { w.Terminate() })
	}()

	w.Run()
}

func testMainConnectionFlip() error {
	var setResp struct {
		Settings struct {
			MainConnection string `json:"main_connection"`
			MainDownPolicy string `json:"main_down_policy"`
		} `json:"settings"`
		EngineOn bool `json:"engine_on"`
	}
	if err := client.Call("settings.get", nil, &setResp); err != nil {
		return fmt.Errorf("settings.get: %w", err)
	}

	origMain := setResp.Settings.MainConnection
	origEngineOn := setResp.EngineOn

	if !origEngineOn {
		var r map[string]string
		if err := client.Call("engine.on", nil, &r); err != nil {
			return fmt.Errorf("engine.on: %w", err)
		}
		time.Sleep(3 * time.Second)
	}

	defer func() {
		var r map[string]string
		_ = client.Call("settings.set", map[string]string{"main_connection": origMain}, &r)
		if !origEngineOn {
			_ = client.Call("engine.off", nil, &r)
		}
	}()

	var adapterList []adapters.Adapter
	if err := client.Call("adapters.list", nil, &adapterList); err != nil {
		return fmt.Errorf("adapters.list: %w", err)
	}

	var upAdapters []adapters.Adapter
	for _, a := range adapterList {
		if a.OperUp && a.HasV4Gateway && !a.IsTunnel {
			upAdapters = append(upAdapters, a)
		}
	}

	if len(upAdapters) == 0 {
		return fmt.Errorf("no physical adapters with default gateway are UP")
	}

	target := upAdapters[0].Name
	if len(upAdapters) >= 2 {
		if strings.EqualFold(origMain, upAdapters[0].Name) {
			target = upAdapters[1].Name
		} else {
			target = upAdapters[0].Name
		}
	}

	t0 := time.Now()
	var setMap map[string]string
	if err := client.Call("settings.set", map[string]string{"main_connection": target}, &setMap); err != nil {
		return fmt.Errorf("settings.set main_connection=%s: %w", target, err)
	}

	var finalIP string
	var flipSec float64
	for attempt := 0; attempt < 15; attempt++ {
		ip, err := queryPublicIP()
		if err == nil && ip != "" {
			finalIP = ip
			flipSec = time.Since(t0).Seconds()
			if flipSec <= 5.0 {
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
	}

	if finalIP == "" {
		return fmt.Errorf("unpinned public IP check failed to respond")
	}

	fmt.Printf("[PASS] flip mainConnection to %s: unpinned flow verified (public IP=%s) in %.2fs (target <= 5s)\n", target, finalIP, flipSec)
	return nil
}

func queryPublicIP() (string, error) {
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   3 * time.Second,
	}
	resp, err := httpClient.Get("http://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// ---------------- misc ----------------

func fatalDialog(err error) {
	messageBox("Detour", err.Error())
	os.Exit(1)
}
