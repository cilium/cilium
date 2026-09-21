// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"maps"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/scaletozero"
)

var _ scaletozero.Map = (*FakeScaleToZeroMap)(nil)

// FakeScaleToZeroMap is an in-memory stand-in for the scale-to-zero BPF map.
// It is safe for concurrent use: the reconciler writes to it from its own
// goroutine while a test reads it.
type FakeScaleToZeroMap struct {
	mu lock.Mutex
	// entries maps a tracked service to the stamp the datapath would have
	// left there. Use [FakeScaleToZeroMap.Wake] to simulate the datapath.
	entries map[loadbalancer.ServiceID]uint64
	// names maps a tracked datapath ID to the service it belongs to.
	names map[loadbalancer.ServiceID]loadbalancer.ServiceName
}

func NewFakeScaleToZeroMap() *FakeScaleToZeroMap {
	return &FakeScaleToZeroMap{
		entries: map[loadbalancer.ServiceID]uint64{},
		names:   map[loadbalancer.ServiceID]loadbalancer.ServiceName{},
	}
}

func (f *FakeScaleToZeroMap) Track(id loadbalancer.ServiceID, name loadbalancer.ServiceName) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.names[id] = name
	if _, tracked := f.entries[id]; tracked {
		return nil
	}
	f.entries[id] = 0
	return nil
}

func (f *FakeScaleToZeroMap) Untrack(id loadbalancer.ServiceID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.entries, id)
	delete(f.names, id)
	return nil
}

func (f *FakeScaleToZeroMap) Resolve(id loadbalancer.ServiceID) (loadbalancer.ServiceName, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	name, found := f.names[id]
	return name, found
}

func (f *FakeScaleToZeroMap) Dump(fn func(id loadbalancer.ServiceID, lastWake uint64)) error {
	for id, lastWake := range f.Entries() {
		fn(id, lastWake)
	}
	return nil
}

// Entries returns the tracked services and the stamp each of them carries.
func (f *FakeScaleToZeroMap) Entries() map[loadbalancer.ServiceID]uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()

	return maps.Clone(f.entries)
}

// Wake stamps a tracked service as the datapath does when it asks for the
// service to be scaled up.
func (f *FakeScaleToZeroMap) Wake(id loadbalancer.ServiceID, lastWake uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, tracked := f.entries[id]; !tracked {
		return
	}
	f.entries[id] = lastWake
}
