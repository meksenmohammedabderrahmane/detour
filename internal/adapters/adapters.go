//go:build windows

// Package adapters enumerates network adapters and decides which one "Automatic"
// means. The selection logic is pure and unit-tested; the Windows glue lives in
// winsys and is only exercised on real hardware.
package adapters

import (
	"sort"
	"strings"
	"sync/atomic"

	"detour/internal/winsys"
)

// Adapter re-exports the winsys model so packages above can stay
// winsys-free in their logic paths.
type Adapter struct {
	Guid         string `json:"guid"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Index        int    `json:"index"`
	Type         int    `json:"type"`
	IsTunnel     bool   `json:"isTunnel"`
	OperUp       bool   `json:"operUp"`     // WHY camelCase: this struct crosses the UI bridge raw
	HasV4Gateway bool   `json:"hasV4Gateway"`
	HasGlobalV6  bool   `json:"hasGlobalV6"`
	V4Metric     uint32 `json:"v4metric"`
	NlMtu        uint32 `json:"nlMtu"`
}

// Default holds the answer to "what does Automatic mean right now".
type Default struct {
	// Name/Index of the chosen adapter. Index 0 = no candidate found or blocked.
	Name    string `json:"name"`
	Index   int    `json:"index"`
	Blocked bool   `json:"blocked"`
	// Reason is a short human-readable explanation for logs/status.
	Reason string `json:"reason"`
}

// SelectDefault is PURE (unit tests target this).
//
// The spec: "the real default adapter, computed with the TUN excluded  -  the
// lowest-metric physical adapter with a default gateway".
func SelectDefault(list []Adapter) Default {
	var candidates []Adapter
	for _, a := range list {
		if a.IsTunnel || !a.OperUp || !a.HasV4Gateway || a.V4Metric == 0 {
			continue
		}
		if a.Name == tunName {
			continue // never select our own capture adapter as "automatic"
		}
		candidates = append(candidates, a)
	}
	if len(candidates) == 0 {
		return Default{Reason: "no physical adapter with an IPv4 default gateway is up"}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].V4Metric != candidates[j].V4Metric {
			return candidates[i].V4Metric < candidates[j].V4Metric
		}
		return candidates[i].Index < candidates[j].Index // stable tie-break
	})
	best := candidates[0]
	return Default{
		Name:   best.Name,
		Index:  best.Index,
		Reason: "lowest IPv4 interface metric (auto-chosen as System default)",
	}
}

// SelectTarget resolves Automatic based on mainConnection ("auto" or adapter name/guid)
// and mainDownPolicy ("fallback" or "block").
func SelectTarget(list []Adapter, mainConn, mainDownPolicy string) Default {
	if mainConn == "" || strings.EqualFold(mainConn, "auto") {
		return SelectDefault(list)
	}

	// Look for specific adapter by GUID or friendly name
	for _, a := range list {
		if a.Name == tunName || a.IsTunnel {
			continue
		}
		matched := false
		if a.Guid != "" && strings.EqualFold(a.Guid, mainConn) {
			matched = true
		} else if strings.EqualFold(a.Name, mainConn) {
			matched = true
		}

		if matched {
			if a.OperUp {
				return Default{
					Name:   a.Name,
					Index:  a.Index,
					Reason: "pinned main connection (" + a.Name + ")",
				}
			}
			// Adapter matched but is down
			break
		}
	}

	// Main connection is down or missing
	if strings.EqualFold(mainDownPolicy, "block") {
		return Default{
			Name:    "",
			Index:   0,
			Blocked: true,
			Reason:  "main connection is down (policy: block)",
		}
	}

	// Fallback policy
	def := SelectDefault(list)
	if def.Index != 0 {
		def.Reason = "fallback to system default (" + def.Name + ") because main connection is down"
	}
	return def
}

const tunName = "Detour"

// Table is the live adapter table with change notification.
type Table struct {
	snapshot       atomic.Pointer[[]Adapter]
	default_       atomic.Pointer[Default]
	mainConn       atomic.Pointer[string]
	mainDownPolicy atomic.Pointer[string]
}

func New() *Table {
	t := &Table{}
	auto := "auto"
	fallback := "fallback"
	t.mainConn.Store(&auto)
	t.mainDownPolicy.Store(&fallback)
	return t
}

func (t *Table) SetPolicy(mainConn, mainDownPolicy string) {
	if mainConn == "" {
		mainConn = "auto"
	}
	if mainDownPolicy == "" {
		mainDownPolicy = "fallback"
	}
	t.mainConn.Store(&mainConn)
	t.mainDownPolicy.Store(&mainDownPolicy)
	if all := t.All(); all != nil {
		d := SelectTarget(all, mainConn, mainDownPolicy)
		t.default_.Store(&d)
	}
}

// Refresh re-enumerates adapters and recomputes the default.
func (t *Table) Refresh() error {
	list, err := winsys.Enumerate()
	if err != nil {
		return err
	}
	out := make([]Adapter, 0, len(list))
	for _, a := range list {
		out = append(out, Adapter{
			Guid:         a.Guid,
			Name:         a.Name,
			Description:  a.Description,
			Index:        int(a.Index),
			Type:         int(a.Type),
			IsTunnel:     !a.IsPhysical(),
			OperUp:       a.OperUp,
			HasV4Gateway: a.HasV4Gateway,
			HasGlobalV6:  a.HasGlobalV6,
			V4Metric:     a.V4Metric,
			NlMtu:        a.NlMtu,
		})
	}
	t.snapshot.Store(&out)

	mc := "auto"
	if p := t.mainConn.Load(); p != nil {
		mc = *p
	}
	mdp := "fallback"
	if p := t.mainDownPolicy.Load(); p != nil {
		mdp = *p
	}
	d := SelectTarget(out, mc, mdp)
	t.default_.Store(&d)
	return nil
}

func (t *Table) All() []Adapter {
	if p := t.snapshot.Load(); p != nil {
		return *p
	}
	return nil
}

// Current returns the current Automatic target (name + ifindex).
func (t *Table) Current() Default {
	if p := t.default_.Load(); p != nil {
		return *p
	}
	return Default{}
}

// IndexByName resolves an adapter friendly name to its current ifindex.
func (t *Table) IndexByName(name string) (int, bool) {
	for _, a := range t.All() {
		if strings.EqualFold(a.Name, name) && a.OperUp {
			return a.Index, true
		}
	}
	return 0, false
}

// Resolve resolves an adapter by name or GUID, returning index and whether it is up.
func (t *Table) Resolve(nameOrGuid string) (int, string, bool) {
	for _, a := range t.All() {
		if (a.Guid != "" && strings.EqualFold(a.Guid, nameOrGuid)) || strings.EqualFold(a.Name, nameOrGuid) {
			return a.Index, a.Name, a.OperUp
		}
	}
	return 0, "", false
}
