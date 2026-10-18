//go:build windows

package engine

import (
	"net/netip"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// installForwarders wires the userland stack into tun2socks' tunnel so every
// intercepted flow gets relayed through the engine's proxy (SetProxy).
//
// WHY we install our own forwarders (instead of tun2socks' defaults): IPv6
// must be refused AT THE SYN. Once the userland stack has accepted the
// connection the app believes it is connected; a browser that "won" the IPv6
// race will not fall back to IPv4 on a later RST. This is net-merge's design
// (MIT, credited in README) reused with the same RST-first and ICMP-first
// behavior, extended by Detour's counting wrappers.
//
// IPv6 modes (--ipv6 clamp|relay|off):
//   - clamp (default): capture IPv6 routes, refuse v6 at capture (RST for
//     TCP, ICMP unreachable for UDP). Apps fall back to IPv4 instantly;
//     per-app pinned byte counts stay exact. IPv6-only sites are unreachable
//     while the engine is on  -  documented product limitation of M1.
//   - relay: v6 flows are relayed per rule to adapters that have v6.
//     (Higher risk; not the default in M1.)
//   - off: no IPv6 capture routes are installed, so IPv6 bypasses the engine
//     entirely and the counters will not see v6 bytes.
func installForwarders(s *stack.Stack, e *Engine, allowV6 func(id stack.TransportEndpointID) bool) {
	tf := tcp.NewForwarder(s, 0, 2<<10, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		if isV6(id) && !allowV6(id) {
			r.Complete(true) // RST first  -  pushes Happy Eyeballs to IPv4 instantly
			e.logf("ipv6 tcp refused at SYN %s (forcing IPv4 fallback)", tuple(id))
			return
		}
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true) // prevent a half-open connection leak
			return
		}
		defer r.Complete(false)
		copyTCPOptions(s, ep)
		tunnel.T().HandleTCP(&appTcpConn{TCPConn: gonet.NewTCPConn(&wq, ep), id: id})
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)

	uf := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		if isV6(id) && !allowV6(id) {
			// WHY return false (not RST): the stack then answers ICMP port
			// unreachable, which makes QUIC fall back to IPv4 almost instantly.
			e.logf("ipv6 udp refused %s (ICMP unreachable -> QUIC fallback)", tuple(id))
			return false
		}
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}
		tunnel.T().HandleUDP(&appUdpConn{UDPConn: gonet.NewUDPConn(&wq, ep), id: id})
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)
	setICMPv4Drop(s)
}

// setICMPv4Drop makes netstack LEAVE ICMPv4 unanswered (handler consumes the
// packet without replying). WHY: netstack answered echo requests with instant
// (0-1 ms) fake replies, which makes `ping` lie about reachability and
// latency. v1 decision, documented: while the engine is on, ping to the
// internet times out (honest)  -  real ICMP proxying needs raw sockets and is
// M4 scope. IPv6 is untouched: the IPv6 clamp uses netstack's own ICMP
// unreachable messages to push apps back to IPv4.
func setICMPv4Drop(s *stack.Stack) {
	s.SetTransportProtocolHandler(header.ICMPv4ProtocolNumber, func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
		return true // handled, do not reply  -  pings honestly time out
	})
}

func isV6(id stack.TransportEndpointID) bool {
	return id.LocalAddress.Len() == header.IPv6AddressSize
}

func tuple(id stack.TransportEndpointID) string {
	return addrPort(id.LocalAddress, uint16(id.LocalPort)).String() +
		" -> " + addrPort(id.RemoteAddress, uint16(id.RemotePort)).String()
}

// addrPort converts a raw gvisor address to netip for logging.
func addrPort(a tcpip.Address, p uint16) netip.AddrPort {
	addr, ok := netip.AddrFromSlice(a.AsSlice())
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr, p)
}

// appTcpConn/appUdpConn are the app-side conns handed to the tunnel; they
// carry the netstack endpoint id for flow bookkeeping and logging.
type appTcpConn struct {
	*gonet.TCPConn
	id stack.TransportEndpointID
}

func (c *appTcpConn) ID() stack.TransportEndpointID { return c.id }

type appUdpConn struct {
	*gonet.UDPConn
	id stack.TransportEndpointID
}

func (c *appUdpConn) ID() stack.TransportEndpointID { return c.id }

// copyTCPOptions mirrors net-merge/tun2socks defaults: keepalives + the
// stack's default buffer sizes. WHY: keepalives for long-lived launchers;
// default buffers keep throughput sane without per-flow tuning.
func copyTCPOptions(s *stack.Stack, ep tcpip.Endpoint) {
	ep.SocketOptions().SetKeepAlive(true)
	idle := tcpip.KeepaliveIdleOption(60 * time.Second)
	ep.SetSockOpt(&idle)
	interval := tcpip.KeepaliveIntervalOption(30 * time.Second)
	ep.SetSockOpt(&interval)
	ep.SetSockOptInt(tcpip.KeepaliveCountOption, 9)

	var ss tcpip.TCPSendBufferSizeRangeOption
	if err := s.TransportProtocolOption(header.TCPProtocolNumber, &ss); err == nil {
		ep.SocketOptions().SetSendBufferSize(int64(ss.Default), false)
	}
	var rs tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(header.TCPProtocolNumber, &rs); err == nil {
		ep.SocketOptions().SetReceiveBufferSize(int64(rs.Default), false)
	}
}
