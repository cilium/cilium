// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

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
	ReservedIdentityCache = map[NumericIdentity]*Identity{}
)

// AddReservedIdentity adds the reserved numeric identity with the respective
// label into the map of reserved identity cache.
func AddReservedIdentity(ni NumericIdentity, lbl string) {
	identity := NewIdentity(ni, labels.Labels{lbl: labels.NewLabel(lbl, "", labels.LabelSourceReserved)})
	// Pre-calculate the SHA256 hash.
	identity.GetLabelsSHA256()
	cacheMU.Lock()
	ReservedIdentityCache[ni] = identity
	cacheMU.Unlock()
}

// AddReservedIdentityWithLabels is the same as AddReservedIdentity but accepts
// multiple labels.
func AddReservedIdentityWithLabels(ni NumericIdentity, lbls labels.Labels) {
	identity := NewIdentity(ni, lbls)
	// Pre-calculate the SHA256 hash.
	identity.GetLabelsSHA256()
	cacheMU.Lock()
	ReservedIdentityCache[ni] = identity
	cacheMU.Unlock()
}

// LookupReservedIdentity looks up a reserved identity by its NumericIdentity
// and returns it if found. Returns nil if not found.
func LookupReservedIdentity(ni NumericIdentity) *Identity {
	cacheMU.RLock()
	defer cacheMU.RUnlock()
	return ReservedIdentityCache[ni]
}

func init() {
	IterateReservedIdentities(func(lbl string, ni NumericIdentity) {
		identity := NewIdentity(ni, labels.Labels{lbl: labels.NewLabel(lbl, "", labels.LabelSourceReserved)})
		// Pre-calculate the SHA256 hash.
		identity.GetLabelsSHA256()
		ReservedIdentityCache[ni] = identity
	})
}
