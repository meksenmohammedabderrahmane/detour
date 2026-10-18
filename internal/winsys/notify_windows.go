//go:build windows

package winsys

import (
	"syscall"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// NotifyChanged subscribes to IP interface changes (NotifyIpInterfaceChange).
//
// WHY IP-Helper notifications instead of polling: DHCP renewals, cable
// un/plugs, tether attach/detach and route churn all surface within
// milliseconds here, so the engine recomputes "automatic" egress live. A
// slow ticker (3 s) is kept as a safety net anyway.
//
// WHY a single global registration + non-blocking send: the callback runs on
// a random non-Go thread; it may only enqueue (the Windows notification path
// serializes events; a blocking callback would stall it). Callers must not
// block on send.
var (
	currentSink atomic.Pointer[chan struct{}]
	cbOnce      bool
	cbIfHash    uintptr
	cbRouteHash uintptr
)

func NotifyChanged(sink chan struct{}) (cancel func() error, err error) {
	if !cbOnce {
		cbIfHash = syscall.NewCallback(interfaceChangeCallback)
		cbRouteHash = syscall.NewCallback(routeChangeCallback)
		cbOnce = true
	}
	currentSink.Store(&sink)
	var hIf windows.Handle
	if err := windows.NotifyIpInterfaceChange(windows.AF_UNSPEC, cbIfHash, nil, false, &hIf); err != nil {
		return nil, err
	}
	var hRoute windows.Handle
	if err := windows.NotifyRouteChange2(windows.AF_UNSPEC, cbRouteHash, nil, false, &hRoute); err != nil {
		_ = windows.CancelMibChangeNotify2(hIf)
		return nil, err
	}
	return func() error {
		currentSink.Store(nil)
		e1 := windows.CancelMibChangeNotify2(hIf)
		e2 := windows.CancelMibChangeNotify2(hRoute)
		if e1 != nil {
			return e1
		}
		return e2
	}, nil
}

func interfaceChangeCallback(row *windows.MibIpInterfaceRow, notificationType uint32) uintptr {
	// WHY uintptr return: MIB callback contract (NOERROR). Deliver without
	// blocking: drop if the consumer is slower than the kernel's event rate.
	if sink := currentSink.Load(); sink != nil {
		select {
		case *sink <- struct{}{}:
		default:
		}
	}
	return 0
}

func routeChangeCallback(callerContext uintptr, row *windows.MibIpForwardRow2, notificationType uint32) uintptr {
	if sink := currentSink.Load(); sink != nil {
		select {
		case *sink <- struct{}{}:
		default:
		}
	}
	return 0
}
