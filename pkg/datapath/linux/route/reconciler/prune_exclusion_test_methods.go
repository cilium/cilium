// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import "maps"

// All methods in this file are only used for testing purposes.
// Currently used in:
// - pkg/datapath/linux/node_linux_test.go

func (pe *PruneExclusion) SnapshotForTest() map[DesiredRouteKey]struct{} {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	// Owner is always nil so we don't need to worry about it when cloning the map.
	return maps.Clone(pe.keys)
}

func (pe *PruneExclusion) DrainForTest() map[DesiredRouteKey]struct{} {
	return pe.consume()
}
