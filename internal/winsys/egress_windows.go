//go:build windows

// Package winsys groups the raw Windows networking syscalls (IP Helper, sockets,
// process queries) the Detour engine needs. Each trick carries a WHY comment.
package winsys

import (
	"math/bits"
	"syscall"
)

const ipUnicastIf = 31

// WHY IP_UNICAST_IF: a socket option that forces the outgoing *interface* of a
// socket regardless of the routing table. It is the documented replacement for
// "Bind() to an adapter IP" (which breaks DHCP/renewals) and for route-metric
// games (which would fight the TCP stack). Setting it per-socket is the ONLY way
// to give a single flow its own egress interface while the rest of the machine
// uses another one  -  this is exactly what makes per-app routing possible.
//
// WHY set it in a Control callback: net.Dialer/ListenConfig run Control(fds)
// right after socket() and BEFORE connect()/sendto(), so the routing decision
// for every packet of this socket happens after the pin is in place. Setting it
// after connect would race the route lookup.
//
// IPv4 docs: the option value is the interface index in NETWORK byte order.
// IPv6 docs (IPV6_UNICAST_IF shares the same option number): host byte order.
// Adapted from net-merge/internal/nics/egress_windows.go (MIT, Copyright
// rohit267), with the WHY comments extended for Detour's docs.
func ForceEgress(idx int, v6 bool) func(network, address string, c syscall.RawConn) error {
	if idx <= 0 {
		return nil // not pinned: caller intends normal OS routing
	}
	level, val := syscall.IPPROTO_IP, int(int32(bits.ReverseBytes32(uint32(idx))))
	if v6 {
		level, val = syscall.IPPROTO_IPV6, idx
	}
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(syscall.Handle(fd), level, ipUnicastIf, val)
		}); err != nil {
			return err
		}
		return serr
	}
}
