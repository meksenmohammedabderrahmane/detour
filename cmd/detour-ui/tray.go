//go:build windows

// tray.go: system tray icon (fyne.io/systray, pure Go on Windows). The tray
// mirrors the window: open the window, toggle start-with-Windows, and quit.
// Quitting the tray/UI never touches the engine  -  the service runs on.
package main

import (
	_ "embed"

	"fyne.io/systray"
	"github.com/jchv/go-webview2"
)

var (
	procGetAncestor          = user32.NewProc("GetAncestor")
	procShowWindow           = user32.NewProc("ShowWindow")
	procSetForegroundWindow  = user32.NewProc("SetForegroundWindow")
)

//go:embed assets/tray.ico
var trayICO []byte

func startTray() {
	go systray.Run(trayOnReady, trayOnExit)
}

func trayOnReady() {
	systray.SetIcon(trayICO)
	systray.SetTooltip("Detour")

	mOpen := systray.AddMenuItem("Open Detour", "Show the Detour window")
	systray.AddSeparator()
	mAuto := systray.AddMenuItemCheckbox("Start with Windows", "Launch when you sign in", getStartWithWindows())
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit Detour", "Close the UI (engine keeps running in the service)")

	// WHY goroutines per item: systray won't enter its native loop until
	// onReady returns; blocking here would freeze the tray.
	go func() { for range mOpen.ClickedCh { showWindow() } }()
	go func() { for range mAuto.ClickedCh {
		if mAuto.Checked() {
			mAuto.Uncheck()
			_ = setStartWithWindows(false)
		} else {
			mAuto.Check()
			_ = setStartWithWindows(true)
		}
	} }()
	go func() { for range mQuit.ClickedCh { systray.Quit(); terminateWindow() } }()
}

func trayOnExit() {}

// showWindow / terminateWindow manipulate the webview window from the tray
// thread; both must round-trip through w.Dispatch (webview thread).
func showWindow() {
	wvDispatch(func() { wvShow(wv) })
}

func terminateWindow() {
	wvDispatch(func() { wv.Terminate() })
}

// wvDispatch safely queues a function onto the webview thread.
func wvDispatch(f func()) {
	if wv != nil {
		wv.Dispatch(f)
	}
}

// wvShow un-minimizes and foregrounds the webview window (webview thread only).
func wvShow(w webview2.WebView) {
	if w == nil {
		return
	}
	// WHY GetAncestor(GA_ROOTOWNER): w.Window() is the WebView2 controller's
	// child container; the message box must target the top-level owner window.
	hwnd, _, _ := procGetAncestor.Call(uintptr(w.Window()), 2 /* GA_ROOTOWNER */)
	if hwnd == 0 {
		return
	}
	_, _, _ = procShowWindow.Call(hwnd, 9 /* SW_RESTORE */)
	_, _, _ = procSetForegroundWindow.Call(hwnd)
}
