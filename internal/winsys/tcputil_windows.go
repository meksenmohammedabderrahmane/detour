//go:build windows

package winsys

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WHY GetExtendedTcpTable/UdpTable (IP Helper, not Winsock hooking, not WFP):
// the kernel already tracks every socket together with the PID that owns it.
// Reading that table is passive  -  no DLL is injected, no API is hooked, so
// protected processes, Store (UWP) apps, anti-cheat and AV-guarded apps keep
// working exactly as before. This is the entire attribution mechanism.
//
// WHY these are not in x/sys: x/sys v0.46 exposes most MIB*Row structs but not
// the GetExtended*Table functions, so we call iphlpapi.dll directly.

var (
	iphlpapi                 = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable  = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable  = iphlpapi.NewProc("GetExtendedUdpTable")
	errInsufficientBuffer    = windows.ERROR_INSUFFICIENT_BUFFER
)

const (
	// TCP_TABLE_OWNER_PID_ALL / UDP_TABLE_OWNER_PID  -  include the owning PID.
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
)

// TCPRow is one MIB_TCPROW_OWNER_PID (IPv4 only): endpoints + owning PID.
type TCPRow struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  uint32
	PID    uint32
}

// UDPRow is one MIB_UDPROW_OWNER_PID (only a local endpoint exists; a UDP
// row is created when the app first sends, so a "does it exist" poll after
// our first datagram is inherently racy  -  see attribution retries).
type UDPRow struct {
	Local netip.AddrPort
	PID   uint32
}

// maxTableBytes caps allocation growth; a machine with tens of thousands of
// sockets stays far below this.
const maxTableBytes = 64 << 20

// TCPSnapshot returns every IPv4 TCP connection and its owning PID.
func TCPSnapshot() ([]TCPRow, error) {
	rows, _, err := extendedTable(procGetExtendedTcpTable, tcpTableOwnerPIDAll, 24)
	if err != nil {
		return nil, err
	}
	out := make([]TCPRow, len(rows))
	for i, r := range rows {
		// WHY this order: MIB_TCPROW_OWNER_PID is {dwState, dwLocalAddr,
		// dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid}  -  state first
		// (matches MIB_TCPROW); an address-first guess shifted everything by
		// one DWORD and made every lookup miss.
		out[i] = TCPRow{
			State:  r[0],
			Local:  decodeAddrPort(r[1], r[2]),
			Remote: decodeAddrPort(r[3], r[4]),
			PID:    r[5],
		}
	}
	return out, nil
}

// UDPSnapshot returns every IPv4 UDP socket endpoint and its owning PID.
func UDPSnapshot() ([]UDPRow, error) {
	rows, _, err := extendedTable(procGetExtendedUdpTable, udpTableOwnerPID, 12)
	if err != nil {
		return nil, err
	}
	out := make([]UDPRow, len(rows))
	for i, r := range rows {
		out[i] = UDPRow{Local: decodeAddrPort(r[0], r[1]), PID: r[2]}
	}
	return out, nil
}

// extendedTable calls GetExtendedTcpTable/UdpTable into a growing buffer.
// WHY a retry loop: the table changes between allocation and the call; the
// documented protocol is caller-provided size + ERROR_INSUFFICIENT_BUFFER +
// the function returning the *required* size through the same pointer.
func extendedTable(proc *windows.LazyProc, tableClass uint32, rowSize uint32) ([][]uint32, uint32, error) {
	size := uint32(48 * 1024)
	for attempt := 0; attempt < 5; attempt++ {
		buf := make([]byte, size)
		var errcode uintptr
		if rowSize == 12 {
			errcode, _, _ = proc.Call(
				uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
				1 /* bOrder=TRUE */, uintptr(windows.AF_INET), uintptr(tableClass), 0)
		} else {
			errcode, _, _ = proc.Call(
				uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
				1 /* bOrder=TRUE */, uintptr(windows.AF_INET), uintptr(tableClass), 0)
		}
		switch uint32(errcode) {
		case 0: // NO_ERROR
			return parseTable(buf, rowSize)
		case uint32(windows.ERROR_INSUFFICIENT_BUFFER):
			if size > maxTableBytes {
				return nil, 0, fmt.Errorf("socket table too big (%d bytes)", size)
			}
			size = size * 2 // next iteration
		default:
			return nil, 0, fmt.Errorf("GetExtendedTcpTable/UdpTable failed: %d", errcode)
		}
	}
	return nil, 0, errors.New("GetExtendedTcpTable/UdpTable: out of retries")
}

// parseTable decodes the DWORD blob: one count header, then rows of rowSize bytes.
func parseTable(buf []byte, rowSize uint32) ([][]uint32, uint32, error) {
	if len(buf) < 4 {
		return nil, 0, errors.New("socket table: truncated header")
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	want := uint32(4 + n*rowSize)
	if uint32(len(buf)) < want {
		return nil, 0, fmt.Errorf("socket table: truncated rows (%d < %d)", len(buf), want)
	}
	out := make([][]uint32, n)
	for i := uint32(0); i < n; i++ {
		row := buf[4+i*rowSize : 4+(i+1)*rowSize]
		words := make([]uint32, rowSize/4)
		for j := range words {
			words[j] = binary.LittleEndian.Uint32(row[j*4 : (j+1)*4])
		}
		out[i] = words
	}
	return out, n, nil
}

// decodeAddrPort turns a raw DWORD ip + "flattened port" into an AddrPort.
//
// WHY the odd bit order: the DWORD fields carry the IPv4 octets and the port
// bytes in network byte order, but as a little-endian DWORD in memory. So the
// first memory byte is the FIRST address octet but the HIGH port byte.
func decodeAddrPort(addrDword, portDword uint32) netip.AddrPort {
	ip := netip.AddrFrom4([4]byte{
		byte(addrDword), byte(addrDword >> 8), byte(addrDword >> 16), byte(addrDword >> 24),
	})
	port := uint16(portDword&0xff)<<8 | uint16((portDword>>8)&0xff)
	return netip.AddrPortFrom(ip, port)
}
