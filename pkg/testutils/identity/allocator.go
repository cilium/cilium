// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testidentity

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
)

type IdentityAllocatorOwnerMock struct{}

func (i *IdentityAllocatorOwnerMock) UpdateIdentities(added, deleted identity.IdentityMap) {}

func (i *IdentityAllocatorOwnerMock) GetNodeSuffix() string {
	return "foo"
}

// MockIdentityAllocator is used as a mock identity allocator for unit tests.
type MockIdentityAllocator struct {
	identity.IdentityMap

	// map from scope -> next ID
	nextIDs map[identity.NumericIdentity]int

	idToIdentity     map[int]*identity.Identity
	labelsToIdentity map[string]int // labels are sorted as a key

	withheldIdentities map[identity.NumericIdentity]struct{}

	labelsToReject map[string]struct{}
}

// NewMockIdentityAllocator returns a new mock identity allocator to be used
// for unit testing purposes. It can be used as a drop-in for "real" identity
// allocation in a testing context.
func NewMockIdentityAllocator(c identity.IdentityMap) *MockIdentityAllocator {
	if c == nil {
		c = identity.IdentityMap{}
	}
	return &MockIdentityAllocator{
		IdentityMap: c,

		nextIDs: map[identity.NumericIdentity]int{
			identity.IdentityScopeGlobal:     1000,
			identity.IdentityScopeLocal:      0,
			identity.IdentityScopeRemoteNode: 0,
		},

		idToIdentity:       make(map[int]*identity.Identity),
		labelsToIdentity:   make(map[string]int),
		withheldIdentities: map[identity.NumericIdentity]struct{}{},

		labelsToReject: map[string]struct{}{},
	}
}

// WaitForInitialGlobalIdentities does nothing.
func (f *MockIdentityAllocator) WaitForInitialGlobalIdentities(context.Context) error {
	return nil
}

// GetIdentities returns the identities from the identity cache.
func (f *MockIdentityAllocator) GetIdentities() cache.IdentitiesModel {
	result := cache.IdentitiesModel{}
	return result.FromIdentityCache(f.IdentityMap)
}

// Reject programs the mock allocator to reject an identity
// for testing purposes
func (f *MockIdentityAllocator) Reject(lbls labels.Labels) {
	f.labelsToReject[lbls.String()] = struct{}{}
}

func (f *MockIdentityAllocator) Unreject(lbls labels.Labels) {
	delete(f.labelsToReject, lbls.String())
}

// AllocateIdentity allocates a fake identity. It is meant to generally mock
// the canonical identity allocator logic.
func (f *MockIdentityAllocator) AllocateIdentity(_ context.Context, lbls labels.Labels, _ bool, oldNID identity.NumericIdentity) (*identity.Identity, bool, error) {
	if reservedIdentity := identity.LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		return reservedIdentity, false, nil
	}

	if _, ok := f.labelsToReject[lbls.String()]; ok {
		return nil, false, fmt.Errorf("rejecting labels manually")
	}

	if numID, ok := f.labelsToIdentity[lbls.String()]; ok {
		id := f.idToIdentity[numID]
		id.ReferenceCount++
		return id, false, nil
	}

	scope := identity.ScopeForLabels(lbls)
	id := identity.IdentityUnknown

	// if suggested id is available, use it
	if scope != identity.IdentityScopeGlobal {
		if _, ok := f.idToIdentity[int(oldNID)]; !ok && oldNID.Scope() == identity.ScopeForLabels(lbls) {
			id = oldNID
		}
	}
	for id == identity.IdentityUnknown {
		candidate := identity.NumericIdentity(f.nextIDs[scope]) | scope
		_, allocated := f.idToIdentity[int(candidate)]
		_, withheld := f.withheldIdentities[candidate]
		if !allocated && !withheld {
			id = candidate
		}
		f.nextIDs[scope]++
	}

	f.IdentityMap[identity.NumericIdentity(id)] = lbls.LabelArray()
	f.labelsToIdentity[lbls.String()] = int(id)

	realID := &identity.Identity{
		ID:             identity.NumericIdentity(id),
		Labels:         lbls,
		ReferenceCount: 1,
	}
	realID.Sanitize() // copy Labels to LabelArray
	f.idToIdentity[int(id)] = realID

	return realID, true, nil
}

// Release releases a fake identity. It is meant to generally mock the
// canonical identity release logic.
func (f *MockIdentityAllocator) Release(_ context.Context, id *identity.Identity, _ bool) (released bool, err error) {
	realID, ok := f.idToIdentity[int(id.ID)]
	if !ok {
		return false, nil
	}
	if realID.ReferenceCount == 1 {
		delete(f.idToIdentity, int(id.ID))
		delete(f.IdentityMap, id.ID)
		for key, lblID := range f.labelsToIdentity {
			if lblID == int(id.ID) {
				delete(f.labelsToIdentity, key)
			}
		}
	} else {
		realID.ReferenceCount--
		return false, nil
	}
	return true, nil
}

func (f *MockIdentityAllocator) WithholdLocalIdentities(nids []identity.NumericIdentity) {
	for _, nid := range nids {
		f.withheldIdentities[nid] = struct{}{}
	}
}

func (f *MockIdentityAllocator) UnwithholdLocalIdentities(nids []identity.NumericIdentity) {
	for _, nid := range nids {
		delete(f.withheldIdentities, nid)
	}
}

// LookupIdentity looks up the labels in the mock identity store.
func (f *MockIdentityAllocator) LookupIdentity(ctx context.Context, lbls labels.Labels) *identity.Identity {
	if reservedIdentity := identity.LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		return reservedIdentity
	}
	return f.idToIdentity[f.labelsToIdentity[lbls.String()]]
}

// LookupIdentityByID returns the identity corresponding to the id if the
// identity is a reserved identity. Otherwise, returns nil.
func (f *MockIdentityAllocator) LookupIdentityByID(ctx context.Context, id identity.NumericIdentity) *identity.Identity {
	if identity := identity.LookupReservedIdentity(id); identity != nil {
		return identity
	}
	return f.idToIdentity[int(id)]
}

// GetIdentityCache returns the identity cache.
func (f *MockIdentityAllocator) GetIdentityCache() identity.IdentityMap {
	return f.IdentityMap
}

func (f *MockIdentityAllocator) Observe(ctx context.Context, next func(cache.IdentityChange), complete func(error)) {
	go complete(nil)
}
