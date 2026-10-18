//go:build windows

package winsys

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Handle-less process identification structs for NtQuerySystemInformation
// (SystemProcessIdInformation = 88).
// WHY handle-less: Anti-cheat drivers (Vanguard, EAC, BattlEye) hook ObRegisterCallbacks
// to detect OpenProcess calls. NtQuerySystemInformation queries the kernel's EPROCESS
// directly without opening a process handle, avoiding any anti-cheat scrutiny.
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type systemProcessIdInformation struct {
	ProcessId uintptr
	ImageName unicodeString
}

const systemProcessIdInformationClass = 88

var (
	dosMapMu sync.RWMutex
	dosMap   = map[string]string{}
	dosMapAt time.Time
)

func ntToDosPath(ntPath string) string {
	dosMapMu.RLock()
	stale := time.Since(dosMapAt) > 30*time.Second || len(dosMap) == 0
	dosMapMu.RUnlock()
	if stale {
		refreshDosMap()
	}
	dosMapMu.RLock()
	defer dosMapMu.RUnlock()
	lower := strings.ToLower(ntPath)
	for dev, drive := range dosMap {
		if strings.HasPrefix(lower, dev) {
			return drive + ntPath[len(dev):]
		}
	}
	return ntPath
}

func refreshDosMap() {
	dosMapMu.Lock()
	defer dosMapMu.Unlock()
	newMap := make(map[string]string)
	for letter := 'A'; letter <= 'Z'; letter++ {
		drive := fmt.Sprintf("%c:", letter)
		var target [512]uint16
		n, err := windows.QueryDosDevice(windows.StringToUTF16Ptr(drive), &target[0], uint32(len(target)))
		if err == nil && n > 0 {
			dev := strings.ToLower(windows.UTF16ToString(target[:n]))
			newMap[dev] = drive
		}
	}
	dosMap = newMap
	dosMapAt = time.Now()
}

func exePathHandleLess(pid uint32) (string, bool) {
	var info systemProcessIdInformation
	info.ProcessId = uintptr(pid)
	var buf [1024]uint16
	info.ImageName.MaximumLength = uint16(len(buf) * 2)
	info.ImageName.Buffer = &buf[0]

	err := windows.NtQuerySystemInformation(systemProcessIdInformationClass, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), nil)
	if err != nil || info.ImageName.Length == 0 {
		return "", false
	}
	ntPath := windows.UTF16ToString(buf[:info.ImageName.Length/2])
	if ntPath == "" {
		return "", false
	}
	return ntToDosPath(ntPath), true
}

// ExePath resolves a PID to its image path.
//
// 1. First tries handle-less identification (NtQuerySystemInformation with
//    SystemProcessIdInformation), which opens NO process handles.
// 2. If handle-less identification fails, falls back to OpenProcess with
//    PROCESS_QUERY_LIMITED_INFORMATION only, queries creation time and image name,
//    closes the handle immediately, and caches per PID + start time.
func ExePath(pid uint32) (string, bool) {
	if pid == 0 {
		return "", false
	}

	exeMu.RLock()
	if p, ok := exeCache[pid]; ok && time.Since(p.at) < 5*time.Second {
		exeMu.RUnlock()
		return p.path, p.ok
	}
	exeMu.RUnlock()

	// 1. Prefer handle-less identification (zero handles opened to target process)
	if path, ok := exePathHandleLess(pid); ok {
		cache(pid, path, 0, true)
		return path, true
	}

	// 2. Fallback: PROCESS_QUERY_LIMITED_INFORMATION only
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		cache(pid, "", 0, false)
		return "", false
	}
	defer windows.CloseHandle(h)

	var createTime, exitTime, kernelTime, userTime windows.Filetime
	var startTime int64
	if err := windows.GetProcessTimes(h, &createTime, &exitTime, &kernelTime, &userTime); err == nil {
		startTime = createTime.Nanoseconds()
	}

	var buf [1024]uint16
	var size uint32 = uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		cache(pid, "", startTime, false)
		return "", false
	}
	p := windows.UTF16ToString(buf[:size])
	cache(pid, p, startTime, true)
	return p, true
}

type procPath struct {
	path      string
	ok        bool
	startTime int64
	at        time.Time
}

var (
	exeCache = map[uint32]procPath{}
	exeMu    sync.RWMutex
)

func cache(pid uint32, path string, startTime int64, ok bool) {
	exeMu.Lock()
	if len(exeCache) > 4096 {
		exeCache = map[uint32]procPath{} // crash-safe size bound
	}
	exeCache[pid] = procPath{path: path, ok: ok, startTime: startTime, at: time.Now()}
	exeMu.Unlock()
}
