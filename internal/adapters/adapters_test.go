//go:build windows

package adapters

import "testing"

func mk(name string, idx int, metric uint32, up, gw, tunnel bool) Adapter {
	t := uint32(6)
	if tunnel {
		t = 131 // zeroth: Refresh() derives IsTunnel from the IP Helper type
	}
	return Adapter{Name: name, Index: idx, V4Metric: metric, OperUp: up,
		HasV4Gateway: gw, IsTunnel: tunnel, Type: int(t)}
}

func TestSelectDefault_BasicMetric(t *testing.T) {
	got := SelectDefault([]Adapter{mk("Ethernet", 1, 35, true, true, false), mk("Wi-Fi", 2, 50, true, true, false)})
	if got.Index != 1 || got.Name != "Ethernet" {
		t.Fatalf("want Ethernet, got %+v", got)
	}
}

func TestSelectDefault_SkipsUnfitCandidates(t *testing.T) {
	// Down, no gateway, and the TUN itself must never be "Automatic".
	list := []Adapter{
		mk("Ethernet", 1, 35, false, true, false),  // media down
		mk("Wi-Fi", 2, 20, true, false, false),      // no gateway
		mk("Detour", 3, 1, true, true, false),       // our own TUN
		mk("Tailscale", 4, 2, true, true, true),     // VPN adapter (type 131)
		mk("Ethernet 2", 5, 90, true, true, false), // only real candidate
	}
	got := SelectDefault(list)
	if got.Index != 5 {
		t.Fatalf("want Ethernet 2 (idx 5), got %+v", got)
	}
}

func TestSelectDefault_VpnAdapterWithEthernetType(t *testing.T) {
	// Known M1 limitation, pinned by a test: an L3 VPN that presents itself
	// as an Ethernet adapter (e.g. some TAP drivers report type 6 with a
	// gateway) is NOT structurally excluded and can be picked. M2 adds a
	// description-based filter; the docs list this openly.
	list := []Adapter{mk("OpenVPN-TAP", 1, 10, true, true, false), mk("Wi-Fi", 2, 50, true, true, false)}
	got := SelectDefault(list)
	if got.Index != 1 {
		t.Fatalf("expected structural-only filtering to pick idx 1 for now, got %+v", got)
	}
}

func TestSelectDefault_NoneAvailable(t *testing.T) {
	got := SelectDefault([]Adapter{mk("Ethernet", 1, 35, false, false, false)})
	if got.Index != 0 || got.Reason == "" {
		t.Fatalf("want empty default with reason, got %+v", got)
	}
}

func TestSelectDefault_TieBreaksByIndex(t *testing.T) {
	got := SelectDefault([]Adapter{mk("B", 7, 30, true, true, false), mk("A", 5, 30, true, true, false)})
	if got.Index != 5 || got.Name != "A" {
		t.Fatalf("want adapter with lowest index on tie, got %+v", got)
	}
}

func TestSelectTarget_MainConnection(t *testing.T) {
	list := []Adapter{
		mk("Ethernet", 1, 35, true, true, false),
		mk("Wi-Fi", 2, 20, true, true, false), // Wi-Fi has lower metric
	}
	list[0].Guid = "{ETH-GUID}"
	list[1].Guid = "{WIFI-GUID}"

	// With "auto", lower metric Wi-Fi wins
	autoDef := SelectTarget(list, "auto", "fallback")
	if autoDef.Index != 2 || autoDef.Name != "Wi-Fi" {
		t.Fatalf("auto must pick lowest metric Wi-Fi, got %+v", autoDef)
	}

	// With mainConnection = "Ethernet", Ethernet wins despite higher metric
	ethDef := SelectTarget(list, "Ethernet", "fallback")
	if ethDef.Index != 1 || ethDef.Name != "Ethernet" {
		t.Fatalf("mainConnection=Ethernet must pick Ethernet, got %+v", ethDef)
	}

	// By GUID
	guidDef := SelectTarget(list, "{ETH-GUID}", "fallback")
	if guidDef.Index != 1 || guidDef.Name != "Ethernet" {
		t.Fatalf("mainConnection={ETH-GUID} must pick Ethernet, got %+v", guidDef)
	}

	// Ethernet is down: test fallback policy
	listDown := []Adapter{
		mk("Ethernet", 1, 35, false, true, false),
		mk("Wi-Fi", 2, 20, true, true, false),
	}
	listDown[0].Guid = "{ETH-GUID}"
	listDown[1].Guid = "{WIFI-GUID}"

	fallbackDef := SelectTarget(listDown, "Ethernet", "fallback")
	if fallbackDef.Index != 2 || fallbackDef.Name != "Wi-Fi" {
		t.Fatalf("fallback policy must pick Wi-Fi when Ethernet is down, got %+v", fallbackDef)
	}

	// Ethernet is down: test block policy
	blockDef := SelectTarget(listDown, "Ethernet", "block")
	if blockDef.Index != 0 || !blockDef.Blocked {
		t.Fatalf("block policy must block when Ethernet is down, got %+v", blockDef)
	}
}
