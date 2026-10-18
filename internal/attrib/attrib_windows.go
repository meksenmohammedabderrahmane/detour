//go:build windows

// Package attrib maps a flow's (proto, local, remote) tuple to the PID+exe
// that owns it, retrying briefly to cover the race between a connection's
// first packet and the kernel's socket table visibility.
package attrib

import (
	"net/netip"
	"sync"
	"time"

	"detour/internal/winsys"
)

const (
	// maxWait bounds the attribution retry loop. WHY 250ms: the socket
	// becomes visible within a few milliseconds on real machines; 250ms is
	// the long tail. Past that we classify as "unknown" and (importantly for
	// honesty) the status UI reports the flow as unknown instead of guessing.
	maxWait = 250 * time.Millisecond
	// step: small sleeps between table re-reads (~10 attempts).
	step = 20 * time.Millisecond
)

// Result is what the flow's attribution produced.
type Result struct {
	PID        uint32
	Exe        string // full image path ("" when unresolvable)
	Attributed bool
	Delay      time.Duration // 0 → first read hit
}

// Self PID is excluded: the engine's own sockets must never be attributed
// (they would otherwise appear as apps pinned to adapters they already are
// on, which hides routing-loop bugs instead of surfacing them).
var selfPID = uint32(0)

func SetSelf(pid uint32) { selfPID = pid }

type udpPortCacheEntry struct {
	res Result
	at  time.Time
}

var (
	udpPortMu    sync.RWMutex
	udpPortCache = map[uint16]udpPortCacheEntry{}
)

// Owner returns the owning process for the given 5-tuple, or unknown.
func Owner(proto string, local, remote netip.AddrPort) Result {
	if proto == "udp" {
		udpPortMu.RLock()
		if entry, ok := udpPortCache[local.Port()]; ok && time.Since(entry.at) < 60*time.Second {
			udpPortMu.RUnlock()
			return entry.res
		}
		udpPortMu.RUnlock()
	}

	deadline := time.Now().Add(maxWait)
	start := time.Now()
	for {
		var r Result
		switch proto {
		case "tcp":
			r = ownerTCP(local, remote)
		case "udp":
			r = ownerUDP(local)
		}
		if r.Attributed {
			r.Delay = time.Since(start)
			if proto == "udp" {
				udpPortMu.Lock()
				udpPortCache[local.Port()] = udpPortCacheEntry{res: r, at: time.Now()}
				udpPortMu.Unlock()
			}
			return r
		}
		if time.Now().After(deadline) {
			r.Delay = maxWait
			if proto == "udp" {
				udpPortMu.Lock()
				// Cache unattributed entry so subsequent packets do not stall 250ms
				udpPortCache[local.Port()] = udpPortCacheEntry{res: r, at: time.Now()}
				udpPortMu.Unlock()
			}
			return r
		}
		time.Sleep(step)
	}
}

func ownerTCP(local, remote netip.AddrPort) Result {
	rows, err := winsys.TCPSnapshot()
	if err != nil {
		return Result{}
	}
	for _, row := range rows {
		// HOW we match: state is irrelevant here (a SYN_SENT row already
		// carries the owner PID  -  the common case; the retry loop covers
		// tables sampled in the instant before row insertion).
		if row.PID == selfPID {
			continue
		}
		if row.Local == local && (remote.Port() == 0 || row.Remote == remote) {
			path, _ := winsys.ExePath(row.PID)
			return Result{PID: row.PID, Exe: path, Attributed: true}
		}
	}
	return Result{}
}

func ownerUDP(local netip.AddrPort) Result {
	rows, err := winsys.UDPSnapshot()
	if err != nil {
		return Result{}
	}
	// PASS 1: exact local tuple. PASS 2 (WHY): UDP sockets are commonly bound
	// to the wildcard address (0.0.0.0) in the kernel table even when their
	// packets leave via an adapter IP, so a port-only match is the honest
	// fallback; it can only widen the match to sockets of the same ephemeral
	// port, which is effectively unique.
	for _, row := range rows {
		if row.PID == selfPID {
			continue
		}
		if row.Local == local {
			path, _ := winsys.ExePath(row.PID)
			return Result{PID: row.PID, Exe: path, Attributed: true}
		}
	}
	for _, row := range rows {
		if row.PID == selfPID {
			continue
		}
		if row.Local.Port() == local.Port() {
			path, _ := winsys.ExePath(row.PID)
			return Result{PID: row.PID, Exe: path, Attributed: true}
		}
	}
	return Result{}
}
