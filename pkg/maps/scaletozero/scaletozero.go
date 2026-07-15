// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scaletozero

import (
	"fmt"
	"maps"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
)

// MapName is the name of the pinned scale-to-zero map. It must match the C map
// name in "bpf/lib/scale_to_zero.h".
const MapName = "cilium_scale_to_zero"

// Cell provides the scale-to-zero map and the --enable-scale-to-zero flag.
var Cell = cell.Module(
	"scale-to-zero-map",
	"eBPF map tracking services that opted into scale-to-zero",

	cell.Provide(newScaleToZeroMap),
	cell.Config(defaultConfig),
)

type Config struct {
	EnableScaleToZero bool
}

func (c Config) Flags(fs *pflag.FlagSet) {
	fs.Bool("enable-scale-to-zero", defaultConfig.EnableScaleToZero,
		"Track scale-to-zero annotated services and export a per-service demand metric so an external autoscaler can scale them from and to zero.")
}

var defaultConfig = Config{
	EnableScaleToZero: false,
}

// Map tracks the set of services that opted into scale-to-zero, keyed by the
// datapath service id (rev_nat_index). NodePort services expand into one id
// per node address, so the service name is recorded per id to resolve datapath
// signals back to the k8s service.
type Map interface {
	// EnsureTracked marks svcID as tracked for the given service name. An
	// existing entry's rate-limit timestamp is left untouched.
	EnsureTracked(svcID loadbalancer.ServiceID, name loadbalancer.ServiceName) error
	// Delete removes svcID from the tracked set.
	Delete(svcID loadbalancer.ServiceID) error
	// Tracked returns a snapshot of the tracked service ids and their names.
	Tracked() map[loadbalancer.ServiceID]loadbalancer.ServiceName
	// Prune removes tracked entries whose service id is not retained by keep.
	Prune(keep func(loadbalancer.ServiceID) bool) error
}

func newScaleToZeroMap(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	Conf      Config
	LBConfig  loadbalancer.Config
}) (out struct {
	cell.Out

	bpf.MapOut[Map]
	defines.NodeOut
}, err error) {
	if !in.Conf.EnableScaleToZero {
		// Provide the node defines even when disabled so the datapath still compiles.
		out.NodeDefines = map[string]string{
			"CILIUM_SCALE_TO_ZERO_MAP_MAX_ENTRIES": "1",
		}
		return
	}

	size := in.LBConfig.LBServiceMapEntries
	if size <= 0 {
		return out, fmt.Errorf("unexpected scale-to-zero map size: %d", size)
	}

	out.NodeDefines = map[string]string{
		"ENABLE_SCALE_TO_ZERO":                 "1",
		"CILIUM_SCALE_TO_ZERO_MAP_MAX_ENTRIES": strconv.Itoa(size),
	}
	out.MapOut = bpf.NewMapOut(Map(newMap(in.Lifecycle, size)))
	return
}

type scaleToZeroMap struct {
	m *bpf.Map

	mu    lock.RWMutex
	names map[loadbalancer.ServiceID]loadbalancer.ServiceName
}

func newMap(lc cell.Lifecycle, size int) *scaleToZeroMap {
	// No-prealloc must match 'map_flags' in "bpf/lib/scale_to_zero.h". Only the
	// agent creates entries, so the map never allocates in BPF context.
	m := bpf.NewMap(MapName, ebpf.Hash, &Key{}, &Value{}, size, unix.BPF_F_NO_PREALLOC)
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error { return m.OpenOrCreate() },
		OnStop:  func(cell.HookContext) error { return m.Close() },
	})
	return &scaleToZeroMap{m: m, names: map[loadbalancer.ServiceID]loadbalancer.ServiceName{}}
}

func (s *scaleToZeroMap) trackName(svcID loadbalancer.ServiceID, name loadbalancer.ServiceName) {
	s.mu.Lock()
	s.names[svcID] = name
	s.mu.Unlock()
}

func (s *scaleToZeroMap) untrackName(svcID loadbalancer.ServiceID) {
	s.mu.Lock()
	delete(s.names, svcID)
	s.mu.Unlock()
}

func (s *scaleToZeroMap) EnsureTracked(svcID loadbalancer.ServiceID, name loadbalancer.ServiceName) error {
	// Register the name first: if the map update fails (and is retried by the
	// reconciler), demand counting still works, only the wake-up signal is missing.
	s.trackName(svcID, name)

	key := &Key{SvcID: byteorder.HostToNetwork16(uint16(svcID))}
	if _, err := s.m.Lookup(key); err == nil {
		// Already tracked; keep the existing rate-limit timestamp.
		return nil
	}
	return s.m.Update(key, &Value{})
}

func (s *scaleToZeroMap) Delete(svcID loadbalancer.ServiceID) error {
	// Untrack the name first so publishing stops even if the BPF delete fails.
	s.untrackName(svcID)

	key := &Key{SvcID: byteorder.HostToNetwork16(uint16(svcID))}
	_, err := s.m.SilentDelete(key)
	return err
}

func (s *scaleToZeroMap) Tracked() map[loadbalancer.ServiceID]loadbalancer.ServiceName {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return maps.Clone(s.names)
}

func (s *scaleToZeroMap) Prune(keep func(loadbalancer.ServiceID) bool) error {
	var stale []loadbalancer.ServiceID
	err := s.m.DumpWithCallback(func(k bpf.MapKey, _ bpf.MapValue) {
		id := loadbalancer.ServiceID(byteorder.NetworkToHost16(k.(*Key).SvcID))
		if !keep(id) {
			stale = append(stale, id)
		}
	})
	if err != nil {
		return fmt.Errorf("dump scale-to-zero map: %w", err)
	}
	// Delete after the dump to avoid mutating the map while iterating it.
	for _, id := range stale {
		if err := s.Delete(id); err != nil {
			return fmt.Errorf("prune scale-to-zero entry %d: %w", id, err)
		}
	}
	return nil
}

// Key is the key of the scale-to-zero map.
//
// It must match 'struct scale_to_zero_key' in "bpf/lib/scale_to_zero.h".
type Key struct {
	SvcID uint16 `align:"svc_id"` // rev_nat_index, network byte order
	Pad   uint16 `align:"pad"`
}

func (k *Key) New() bpf.MapKey { return &Key{} }

func (k *Key) String() string {
	return strconv.Itoa(int(byteorder.NetworkToHost16(k.SvcID)))
}

// Value is the value of the scale-to-zero map.
//
// It must match 'struct scale_to_zero_value' in "bpf/lib/scale_to_zero.h".
type Value struct {
	LastEmitNs uint64 `align:"last_emit_ns"`
}

func (v *Value) New() bpf.MapValue { return &Value{} }

func (v *Value) String() string {
	return strconv.FormatUint(v.LastEmitNs, 10)
}
