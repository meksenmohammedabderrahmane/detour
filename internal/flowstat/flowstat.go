// Package flowstat keeps the per-flow registry and the aggregated
// per-app × per-adapter byte counters. These counters are the SOURCE OF TRUTH
// for "which adapter actually carried an app's traffic" (M0 requirement): the
// engine wraps every app-bound conn and counts bytes itself.
package flowstat

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Flow is one app connection tracked end-to-end.
type Flow struct {
	ID      uint64         `json:"id"`
	Proto   string         `json:"proto"`
	App     string         `json:"app"`     // exe base name, or "unknown"
	Adapter string         `json:"adapter"` // chosen egress adapter friendly name
	Rule    string         `json:"rule"`    // matched rule key; "" = Automatic (no rule)
	Local   netip.AddrPort `json:"local"`
	Remote  netip.AddrPort `json:"remote"`
	Up      int64          `json:"up"` // app -> internet (TUN RX side)
	Down    int64          `json:"down"`
	Started time.Time      `json:"started"`
	DelayMs int64          `json:"attribDelayMs"` // attribution wait, ms
	Unknown bool           `json:"unknown"`       // attribution failed -> Automatic
}

// Registry holds flows and aggregates.
type Registry struct {
	mu    sync.Mutex
	flows map[uint64]*tracked
	seq   uint64

	totUp, totDown atomic.Int64
	unattributed   atomic.Int64

	attribOK      atomic.Int64
	attribUnknown atomic.Int64

	delays []int64 // ms samples, bounded

	agg map[aggKey]*aggVal
}

type tracked struct {
	f  Flow
	up int64
	dn int64
}
type aggKey struct{ app, adapter string }
type aggVal struct {
	up, down int64
	flows    int64
}

func New() *Registry {
	return &Registry{flows: map[uint64]*tracked{}, agg: map[aggKey]*aggVal{}}
}

// Register assigns a fresh ID to *flow* and returns its counting handle.
// WHY pointer input: the caller's log line prints the ID right after this  - 
// a value copy previously left the caller's copy at ID 0 (every flow line
// logged "#0").
func (r *Registry) Register(flow *Flow) *Handle {
	r.mu.Lock()
	r.seq++
	flow.ID = r.seq
	r.flows[r.seq] = &tracked{f: *flow}

	k := aggKey{app: flow.App, adapter: flow.Adapter}
	v, ok := r.agg[k]
	if !ok {
		v = &aggVal{}
		r.agg[k] = v
	}
	v.flows++

	if len(r.delays) < 10000 {
		r.delays = append(r.delays, flow.DelayMs)
	}
	r.mu.Unlock()

	if flow.Unknown {
		r.attribUnknown.Add(1)
		r.unattributed.Add(1)
	} else {
		r.attribOK.Add(1)
	}
	return &Handle{id: r.seq, reg: r}
}

// Handle is the per-flow counting writer. The engine wraps its app-side and
// net-side conns with these, so byte counts exactly mirror the relay.
type Handle struct {
	id  uint64
	reg *Registry
}

func (h *Handle) AddUp(n int64)   { h.reg.totUp.Add(n); h.bumpUp(n) }
func (h *Handle) AddDown(n int64) { h.reg.totDown.Add(n); h.bumpDown(n) }

func (h *Handle) bumpUp(n int64) {
	h.reg.mu.Lock()
	if t := h.reg.flows[h.id]; t != nil {
		t.up += n
	}
	k := h.reg.aggKeyLocked(h.id)
	if v := h.reg.agg[k]; v != nil {
		v.up += n
	}
	h.reg.mu.Unlock()
}

func (h *Handle) bumpDown(n int64) {
	h.reg.mu.Lock()
	if t := h.reg.flows[h.id]; t != nil {
		t.dn += n
	}
	k := h.reg.aggKeyLocked(h.id)
	if v := h.reg.agg[k]; v != nil {
		v.down += n
	}
	h.reg.mu.Unlock()
}

// aggKeyLocked looks up a flow's aggregate key (must hold r.mu).
func (r *Registry) aggKeyLocked(id uint64) aggKey {
	if t := r.flows[id]; t != nil {
		return aggKey{app: t.f.App, adapter: t.f.Adapter}
	}
	return aggKey{}
}

// Close removes the flow row from the live table and closes its aggregate
// flow count (aggregated byte totals stay). MUST be called by the relay when
// a connection ends, else the live table grows without bound.
func (h *Handle) Close() {
	h.reg.mu.Lock()
	t := h.reg.flows[h.id]
	if t != nil {
		delete(h.reg.flows, h.id)
		if v, ok := h.reg.agg[aggKey{app: t.f.App, adapter: t.f.Adapter}]; ok {
			v.flows--
		}
	}
	h.reg.mu.Unlock()
}
// %ProgramData%\Detour\status.json so a NON-elevated `detour status` in
// another console can read it while the privileged engine runs (same machine,
// shared filesystem  -  this is M1's lego-brick IPC stand-in, not a design
// pattern to keep beyond M2's real named pipe).
type Snapshot struct {
	At           time.Time        `json:"at"`
	Flows        []Flow           `json:"flows"`
	Group        []GroupCounters  `json:"groups"`
	Kernel       []KernelCounters `json:"kernel"`
	Tun          TunCounters      `json:"tun"`
	UnknownFlows int64            `json:"unknownFlows"`
	Attribution  AttributionStats `json:"attribution"`
}

type GroupCounters struct {
	App     string `json:"app"`
	Adapter string `json:"adapter"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
	Flows   int64  `json:"flows"`
}

// KernelCounters are per-adapter deltas from engine start (the kernel's view
// via GetIfEntry2Ex, cross-checking the relay counters).
type KernelCounters struct {
	Adapter string `json:"adapter"`
	In      uint64 `json:"in"`
	Out     uint64 `json:"out"`
}

type TunCounters struct {
	In  int64 `json:"in"`  // app -> engine
	Out int64 `json:"out"` // engine -> app
}

type AttributionStats struct {
	OK       int64   `json:"ok"`
	Unknown  int64   `json:"unknown"`
	MedianMs float64 `json:"medianMs"`
	P95Ms    float64 `json:"p95Ms"`
}

// maxFlowsForSnapshot caps the per-flow list in the snapshot file.
const maxFlowsForSnapshot = 200

func (r *Registry) Snapshot() Snapshot {
	r.mu.Lock()
	flows := make([]Flow, 0, len(r.flows))
	for _, t := range r.flows {
		t.f.Up = t.up
		t.f.Down = t.dn
		flows = append(flows, t.f)
	}
	groups := make([]GroupCounters, 0, len(r.agg))
	for k, v := range r.agg {
		groups = append(groups, GroupCounters{App: k.app, Adapter: k.adapter, Up: v.up, Down: v.down, Flows: v.flows})
	}
	delays := append([]int64(nil), r.delays...)
	r.mu.Unlock()

	sort.Slice(flows, func(i, j int) bool { return flows[i].ID > flows[j].ID })
	if len(flows) > maxFlowsForSnapshot {
		flows = flows[:maxFlowsForSnapshot]
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Flows > groups[j].Flows })

	s := Snapshot{At: time.Now(), Flows: flows, Group: groups}
	s.Tun = TunCounters{In: r.totUp.Load(), Out: r.totDown.Load()}
	s.UnknownFlows = r.unattributed.Load()
	s.Attribution = AttributionStats{OK: r.attribOK.Load(), Unknown: r.attribUnknown.Load()}
	if len(delays) > 0 {
		sort.Slice(delays, func(i, j int) bool { return delays[i] < delays[j] })
		med := delays[(len(delays)-1)/2]
		// 1-based index of the 95th percentile, clamped  -  the raw formula
		// int(0.95*n)-1 is -1 for n<20 and crashed the status loop.
		idx := int(float64(len(delays)) * 0.95)
		if idx < 1 {
			idx = 1
		}
		if idx > len(delays) {
			idx = len(delays)
		}
		p95 := delays[idx-1]
		s.Attribution.MedianMs = float64(med)
		s.Attribution.P95Ms = float64(p95)
	}
	return s
}

// WriteSnapshot writes atomically (temp + rename) so readers never see a torn file.
func WriteSnapshot(path string, s Snapshot) error {
	b, _ := json.Marshal(s)
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0o755)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadSnapshot reads and parses a status snapshot from path.
func ReadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
