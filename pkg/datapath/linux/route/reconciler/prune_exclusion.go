// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import "github.com/cilium/cilium/pkg/lock"

// PruneExclusion is used to keep track of route keys that should
// be excluded from the initial route reconciler pruning process.
//
// This logic prevents connection disruptions during downgrades. Specifically,
// Cilium v1.21 introduces an auto-direct-node-routes (ADNR) component that writes
// routes to the desired route table using the route reconciliation mechanism,
// which the reconciler then stores in the WAL (Write-Ahead Log).
//
// When downgrading to Cilium v1.20, the older ADNR component no longer writes
// these routes. Consequently, the route reconciler's pruning logic would normally
// scan the WAL and remove routes added by the newer version that are missing
// from the v1.20 desired route table. This causes connection disruptions as the
// routes are temporarily removed.
//
// If no other use cases are found, we can remove this logic when v1.20 is phased out.
type PruneExclusion struct {
	mu lock.Mutex

	keys     map[DesiredRouteKey]struct{}
	consumed bool
}

func NewPruneExclusion() *PruneExclusion {
	return &PruneExclusion{
		keys: make(map[DesiredRouteKey]struct{}),
	}
}

// Add adds a key to the prune exclusion set.
// It returns true if the key was successfully added, or false if the exclusion set has already been consumed.
func (m *PruneExclusion) Add(key DesiredRouteKey) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If the exclusion set has already been consumed,
	// we should not add any more keys.
	if m.consumed {
		return false
	}

	// These keys will be matched against the keys stored in the WAL,
	// where we use only ownerless keys. So we need to clear the
	// owner field before adding it to the exclusion set.
	key.Owner = nil
	m.keys[key] = struct{}{}
	return true
}

func (m *PruneExclusion) consume() map[DesiredRouteKey]struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumed {
		return nil
	}
	keys := m.keys
	m.keys = nil
	m.consumed = true
	return keys
}
