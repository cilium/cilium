// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/nat"
)

// A structure that implements PerClusterNATMapper for testing purposes.
type PerClusterMaps struct {
	lock.RWMutex
	ids sets.Set[uint32]
}

var _ nat.PerClusterNATMapper = (*PerClusterMaps)(nil)

func NewPerClusterMaps() *PerClusterMaps {
	return &PerClusterMaps{ids: sets.New[uint32]()}
}

func (maps *PerClusterMaps) OpenOrCreate() error { return nil }
func (maps *PerClusterMaps) Close() error        { return nil }

func (maps *PerClusterMaps) CreateClusterNATMaps(clusterID uint32) error {
	maps.Lock()
	defer maps.Unlock()
	maps.ids.Insert(clusterID)
	return nil
}

func (maps *PerClusterMaps) DeleteClusterNATMaps(clusterID uint32) error {
	maps.Lock()
	defer maps.Unlock()
	maps.ids.Delete(clusterID)
	return nil
}

func (maps *PerClusterMaps) Has(clusterID uint32) bool {
	maps.RLock()
	defer maps.RUnlock()
	return maps.ids.Has(clusterID)
}
