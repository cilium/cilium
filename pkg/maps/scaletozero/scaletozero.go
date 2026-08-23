// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scaletozero

import (
	"errors"
	"fmt"
	"log/slog"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/byteorder"
	datapathmaps "github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/registry"
)

// MapName is the name of the map as declared in bpf/lib/scale_to_zero.h.
const MapName = datapathmaps.CiliumScaleToZero

// Map holds the services that opted into scale-to-zero. The agent owns the
// membership of the map, the datapath owns the values: it stamps an entry with
// the time it last asked the agent to scale the service up and rate limits
// itself with that stamp.
//
// Tracking also records which service each datapath ID belongs to, so that a
// wake signal can be attributed back to a service. The frontends table cannot
// answer that: a NodePort, LoadBalancer or ExternalIP service is expanded by
// the reconciler into one datapath entry per node address, and those entries
// exist only in the BPF maps. The datapath signals the ID of the entry the
// packet actually hit, which for north/south traffic is always an expanded one.
type Map interface {
	// Track opts the service into scale-to-zero and records that id belongs
	// to name. Tracking an already tracked service leaves the datapath's rate
	// limiter alone, so that a re-reconciliation does not disturb it.
	Track(id loadbalancer.ServiceID, name loadbalancer.ServiceName) error

	// Untrack opts the service back out. Untracking a service that is not
	// tracked is not an error.
	Untrack(id loadbalancer.ServiceID) error

	// Resolve returns the service a tracked datapath ID belongs to. The
	// mapping is in-memory only: it is rebuilt by the reconciler on every
	// agent start, before or alongside the first signals. A signal is a hint
	// that is repeated as long as the demand lasts, so losing one to a race
	// with startup is harmless.
	Resolve(id loadbalancer.ServiceID) (loadbalancer.ServiceName, bool)

	// Dump calls fn for every tracked service, with the ktime (monotonic
	// nanoseconds since boot) at which the datapath last asked for the
	// service to be scaled up, or zero if it never did.
	Dump(fn func(id loadbalancer.ServiceID, lastWake uint64)) error
}

type scaleToZeroMap struct {
	m *ebpf.Map

	// names is written by the reconciler and read by the signal handler.
	mu    lock.RWMutex
	names map[loadbalancer.ServiceID]loadbalancer.ServiceName
}

// NewMap returns the scale-to-zero map, which is opened when the hive starts.
func NewMap(lc cell.Lifecycle, log *slog.Logger, reg *registry.MapRegistry) Map {
	m := &scaleToZeroMap{names: map[loadbalancer.ServiceID]loadbalancer.ServiceName{}}
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			spec, err := reg.Get(MapName)
			if err != nil {
				return fmt.Errorf("get scale to zero map spec: %w", err)
			}

			m.m = ebpf.NewMap(log, spec)

			return m.m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return m.m.Close()
		},
	})

	return m
}

func (m *scaleToZeroMap) Track(id loadbalancer.ServiceID, name loadbalancer.ServiceName) error {
	// BPF_NOEXIST leaves the value of an existing entry alone. Rewriting it
	// would reset the datapath's wake rate limiter, and doing it as a
	// lookup-then-update would race with the datapath stamping the entry.
	err := m.m.Update(serviceKey(id), uint64(0), ciliumebpf.UpdateNoExist)
	switch {
	case errors.Is(err, ciliumebpf.ErrKeyExist):
		// The entry survived a restart or a re-reconciliation; the name it
		// belongs to did not necessarily, so record it either way.
	case errors.Is(err, unix.E2BIG):
		// The map is not resizable, so say which one filled up and how far it
		// goes: the operator can only stop annotating services.
		return fmt.Errorf("cannot track service %d for scale-to-zero, %s is full at %d entries: %w",
			id, MapName, m.m.MaxEntries(), err)
	case err != nil:
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.names[id] = name

	return nil
}

func (m *scaleToZeroMap) Untrack(id loadbalancer.ServiceID) error {
	m.mu.Lock()
	delete(m.names, id)
	m.mu.Unlock()

	err := m.m.Delete(serviceKey(id))
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (m *scaleToZeroMap) Resolve(id loadbalancer.ServiceID) (loadbalancer.ServiceName, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	name, found := m.names[id]
	return name, found
}

func (m *scaleToZeroMap) Dump(fn func(id loadbalancer.ServiceID, lastWake uint64)) error {
	var (
		key      uint16
		lastWake uint64
	)

	return m.m.IterateWithCallback(&key, &lastWake, func(k, v any) {
		fn(serviceID(*k.(*uint16)), *v.(*uint64))
	})
}

// serviceKey converts a service ID to the map's key. The datapath looks the
// map up with the rev_nat_index it read from the service maps, which the agent
// writes there in network byte order.
func serviceKey(id loadbalancer.ServiceID) uint16 {
	return byteorder.HostToNetwork16(uint16(id))
}

func serviceID(key uint16) loadbalancer.ServiceID {
	return loadbalancer.ServiceID(byteorder.NetworkToHost16(key))
}
