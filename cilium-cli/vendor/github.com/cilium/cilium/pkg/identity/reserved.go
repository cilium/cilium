// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	// cacheMU protects the following map.
	cacheMU lock.RWMutex
	// ReservedIdentityCache that maps all reserved identities from their
	// numeric identity to their corresponding identity.
	reservedIdentityCache = map[NumericIdentity]*Identity{}
)

// AddReservedIdentity adds the reserved numeric identity with the respective
// label into the map of reserved identity cache, and returns the resulting Identity.
// This identity must not be mutated!
func AddReservedIdentity(ni NumericIdentity, lbl string) *Identity {
	identity := NewIdentity(ni, labels.Labels{lbl: labels.NewLabel(lbl, "", labels.LabelSourceReserved)})
	cacheMU.Lock()
	reservedIdentityCache[ni] = identity
	cacheMU.Unlock()
	return identity
}

// AddReservedIdentityWithLabels is the same as AddReservedIdentity but accepts
// multiple labels. Returns the resulting Identity.
// This identity must not be mutated!
func AddReservedIdentityWithLabels(ni NumericIdentity, lbls labels.Labels) *Identity {
	identity := NewIdentity(ni, lbls)
	cacheMU.Lock()
	reservedIdentityCache[ni] = identity
	cacheMU.Unlock()
	return identity
}

// LookupReservedIdentity looks up a reserved identity by its NumericIdentity
// and returns it if found. Returns nil if not found.
// This identity must not be mutated!
func LookupReservedIdentity(ni NumericIdentity) *Identity {
	cacheMU.RLock()
	defer cacheMU.RUnlock()
	return reservedIdentityCache[ni]
}

func init() {
	iterateReservedIdentityLabels(func(ni NumericIdentity, lbls labels.Labels) {
		AddReservedIdentityWithLabels(ni, lbls)
	})
}

// IterateReservedIdentities iterates over all reserved identities and
// executes the given function for each identity.
func IterateReservedIdentities(f func(_ NumericIdentity, _ *Identity)) {
	cacheMU.RLock()
	defer cacheMU.RUnlock()
	for ni, identity := range reservedIdentityCache {
		f(ni, identity)
	}
}
