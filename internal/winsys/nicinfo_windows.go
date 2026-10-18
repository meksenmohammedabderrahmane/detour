//go:build windows

package winsys

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WHY none of our reads parse `route print` or `netsh` output: every quantity
// (names, types, metrics, gateways, counters, routes) comes from IP Helper
// structs, which are stable ABI the docs guarantee and which cannot be
// re-worded by a Windows update.

const (
	gaaIncludeGateways  = 0x80 // GAA_FLAG_INCLUDE_GATEWAYS
	gaaSkipAnycast      = 0x2
	gaaSkipMulticast    = 0x4
	gaaSkipDnsServers   = 0x8
	ifTypeTunnel        = 131
	ifTypeEthernetCSMACD = 6
	ifTypeIEEE80211     = 71
	ifTypeLoopback      = 24
	ifTypePropVirtual   = 53
	ifTypeOtherVirtual  = 131 // (tunnel)  -  see type tunnel constant above
)

// Adapter is one network interface as Detour models it.
// Derived from GetAdaptersAddresses (names/types/metrics/gateways)  -  NOT from
// command output, so values are exact and update-safe.
type Adapter struct {
	Index        uint32
	Luid         uint64
	Guid         string // adapter GUID string, e.g. "{4F03C78B-...}"
	Name         string // friendly name as shown in Windows ("Wi-Fi", "Ethernet")
	Description  string
	Type         uint32
	OperUp       bool
	MediaConnect bool
	HasV4Gateway bool // a configured IPv4 default gateway exists on this adapter
	HasGlobalV6  bool // a GLOBAL (2000::/3) unicast address exists  -  not link-local/ULA
	V4Metric     uint32
	NlMtu        uint32
	TunnelType   uint32

	// Kernel octet counters (GetIfEntry2Ex), read on demand by the engine.
	inOctets, outOctets uint64
}

// IsPhysical reports whether the adapter can carry general internet traffic.
// WHY exclude by structure, not by a whitelist: tunnels/VPN (type 131),
// loopbacks and MS virtual switches are excluded structurally; anything else
// that is up, wired to a gateway and not our own adapter counts as a candidate.
func (a Adapter) IsPhysical() bool {
	switch a.Type {
	case ifTypeTunnel, ifTypeLoopback, ifTypePropVirtual:
		return false
	}
	if a.TunnelType != 0 {
		return false
	}
	return a.OperUp && a.HasV4Gateway
}

// Counters reads this adapter's octet counters now.
// WHY GetIfEntry2Ex (and not GetIfEntry): the v2 row returns 64-bit counters
// and covers every family; v1 rows wrap at 4 GB, which a 5-minute test can
// already exceed on a gigabit line.
func (a *Adapter) Counters() (in, out uint64, err error) {
	var row windows.MibIfRow2
	row.InterfaceIndex = a.Index
	// MibIfStatsNormal (0): composite counters across families.
	if errcode := windows.GetIfEntry2Ex(0, &row); errcode != nil {
		return 0, 0, errcode
	}
	a.inOctets, a.outOctets = row.InOctets, row.OutOctets
	return row.InOctets, row.OutOctets, nil
}

// Enumerate lists current adapters. buf/retry pattern per MSDN.
func Enumerate() ([]Adapter, error) {
	var (
		size  uint32 = 16 * 1024
		flags        = uint32(gaaIncludeGateways | gaaSkipAnycast | gaaSkipMulticast | gaaSkipDnsServers)
	)
	var aa *windows.IpAdapterAddresses
	var live []byte // keeps the backing buffer alive while aa points into it
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		errcode := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		// WHY nil-check: x/sys returns a nil error on NO_ERROR, not an
		// ERROR_SUCCESS value, so an Errno comparison never matches here.
		if errcode == nil {
			live = buf // WHY: the unsafe alias must not be the only reference
			aa = (*windows.IpAdapterAddresses)(unsafe.Pointer(&live[0]))
			break
		}
		if errcode == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		return nil, errcode
	}
	// All attempts failed or nothing succeeded: report a real error instead
	// of silently returning an empty list.
	if aa == nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: no successful read in 3 attempts")
	}
	var out []Adapter
	for p := aa; p != nil; p = p.Next {
		var guid string
		if p.AdapterName != nil {
			guid = windows.BytePtrToString(p.AdapterName)
		}
		a := Adapter{
			Index:             p.IfIndex,
			Luid:              p.Luid,
			Guid:              guid,
			Name:              windows.UTF16PtrToString(p.FriendlyName),
			Description:       windows.UTF16PtrToString(p.Description),
			Type:              p.IfType,
			OperUp:            p.OperStatus == windows.IfOperStatusUp,
			HasV4Gateway:      p.FirstGatewayAddress != nil,
			V4Metric:          p.Ipv4Metric,
			TunnelType:        p.TunnelType,
		}
		// Media connect state is not in GAA; approximate by OperStatus for M1.
		a.MediaConnect = a.OperUp
		if p.FirstGatewayAddress != nil {
			ip := p.FirstGatewayAddress.Address.IP()
			if ip != nil && ip.To4() != nil {
				a.HasV4Gateway = true
			}
		}
		for u := p.FirstUnicastAddress; u != nil; u = u.Next {
			if ip := u.Address.IP(); ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() &&
				ip.To4() == nil {
				a.HasGlobalV6 = true
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// FindByName finds an adapter by exact friendly name (case-insensitive), or nil.
func FindByName(name string) (*Adapter, error) {
	adapters, err := Enumerate()
	if err != nil {
		return nil, err
	}
	for i := range adapters {
		if eqfold(adapters[i].Name, name) {
			return &adapters[i], nil
		}
	}
	return nil, nil
}

func eqfold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := lower(a[i]), lower(b[i])
		if ca != cb {
			return false
		}
	}
	return true
}

func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + 32
	}
	return b
}
