// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package fake provides an in-memory scaletozero.Map for tests.
package fake

import (
	"maps"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/scaletozero"
)

// ScaleToZeroMap is an in-memory scaletozero.Map. Entries is the tracked set,
// exported so tests can seed and inspect it directly.
type ScaleToZeroMap struct {
	Entries map[loadbalancer.ServiceID]loadbalancer.ServiceName
}

var _ scaletozero.Map = &ScaleToZeroMap{}

func NewFakeScaleToZeroMap() *ScaleToZeroMap {
	return &ScaleToZeroMap{Entries: map[loadbalancer.ServiceID]loadbalancer.ServiceName{}}
}

func (f *ScaleToZeroMap) EnsureTracked(svcID loadbalancer.ServiceID, name loadbalancer.ServiceName) error {
	f.Entries[svcID] = name
	return nil
}

func (f *ScaleToZeroMap) Delete(svcID loadbalancer.ServiceID) error {
	delete(f.Entries, svcID)
	return nil
}

func (f *ScaleToZeroMap) Tracked() map[loadbalancer.ServiceID]loadbalancer.ServiceName {
	return maps.Clone(f.Entries)
}

func (f *ScaleToZeroMap) Prune(keep func(loadbalancer.ServiceID) bool) error {
	for id := range f.Entries {
		if !keep(id) {
			delete(f.Entries, id)
		}
	}
	return nil
}
