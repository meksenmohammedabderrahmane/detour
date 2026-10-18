//go:build windows

// win32.go: unprivileged Win32 helpers for the UI process (no cgo).
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	procMessageBoxW   = user32.NewProc("MessageBoxW")
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole = kernel32.NewProc("AttachConsole")
	_                 = fmt.Sprintf // keep fmt for diagnostics
)

// attachConsole connects standard output/error to the calling console window.
func attachConsole() {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err == nil && h != 0 && h != windows.InvalidHandle {
		return
	}
	const ATTACH_PARENT_PROCESS = ^uintptr(0)
	r, _, _ := procAttachConsole.Call(ATTACH_PARENT_PROCESS)
	if r != 0 {
		conout, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err == nil {
			os.Stdout = conout
			os.Stderr = conout
		}
	}
}

// messageBox shows a plain system message box (used only for fatal start errors).
func messageBox(title, text string) {
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(text)
	// MB_OK|MB_ICONERROR = 0x00000010
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10)
}

func sleepSec(n int) { time.Sleep(time.Duration(n) * time.Second) }

// ---------------- temp diagnostics (M3 dev aid; remove in M4) ----------------

var lastDiag string

func stageDiag(stage string) string {
	d := fmt.Sprintf("[%s]%s; ", time.Now().Format("15:04:05.000"), stage)
	return d
}

func diagFlush(s string) {
	if s == "" {
		return
	}
	lastDiag = s
	p := os.Getenv("TEMP") + "\\detour-ui-diag.log"
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(s + "\n")
		f.Close()
	}
}

// ---------------- start with Windows (per user, HKCU Run) ----------------

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

func setStartWithWindows(enable bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if enable {
		return k.SetStringValue("Detour", `"`+exe+`"`)
	}
	// WHY ignore missing: already absent is success for us.
	_ = k.DeleteValue("Detour")
	return nil
}

func getStartWithWindows() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue("Detour")
	return err == nil
}

// ---------------- running apps list (for "+ Add app") ----------------

// RunningApp is one candidate for the exceptions picker.
type RunningApp struct {
	Name string `json:"name"` // exe file name, e.g. chrome.exe
	Path string `json:"path"` // full path (empty when Windows hides it)
}

// runningApps walks the toolhelp snapshot; unprivileged read access is enough.
func runningApps() []RunningApp {
	const (
		TH32CS_SNAPPROCESS = 0x00000002
	)
	snap, err := windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var out []RunningApp
	seen := map[string]bool{}
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil
	}
	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if strings.TrimSpace(name) != "" && !seen[name] {
			seen[name] = true
			out = append(out, RunningApp{Name: name, Path: ""})
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
