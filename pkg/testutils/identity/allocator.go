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

func (i *IdentityAllocatorOwnerMock) UpdateIdentities(_, _ identity.IdentityMap) <-chan struct{} {
	out := make(chan struct{})
	close(out)
	return out
}

func (i *IdentityAllocatorOwnerMock) GetNodeSuffix() string {
	return "foo"
}

type idEntry struct {
	id             identity.Identity
	referenceCount int
}

// MockIdentityAllocator is used as a mock identity allocator for unit tests.
type MockIdentityAllocator struct {
	// map from scope -> next ID
	nextIDs map[identity.NumericIdentity]int

	idToIdentity     map[identity.NumericIdentity]idEntry
	labelsToIdentity map[string]identity.NumericIdentity // labels are sorted as a key

	withheldIdentities map[identity.NumericIdentity]struct{}

	labelsToReject map[string]struct{}
}

// NewMockIdentityAllocator returns a new mock identity allocator to be used
// for unit testing purposes. It can be used as a drop-in for "real" identity
// allocation in a testing context.
func NewMockIdentityAllocator(c identity.IdentityMap) *MockIdentityAllocator {
	f := &MockIdentityAllocator{
		nextIDs: map[identity.NumericIdentity]int{
			identity.IdentityScopeGlobal:     1000,
			identity.IdentityScopeLocal:      0,
			identity.IdentityScopeRemoteNode: 0,
		},

		idToIdentity:       make(map[identity.NumericIdentity]idEntry),
		labelsToIdentity:   make(map[string]identity.NumericIdentity),
		withheldIdentities: map[identity.NumericIdentity]struct{}{},

		labelsToReject: map[string]struct{}{},
	}

	for nid, lbls := range c {
		f.AllocateLocalIdentity(lbls, false, nid)
	}
	return f
}

// WaitForInitialGlobalIdentities does nothing.
func (f *MockIdentityAllocator) WaitForInitialGlobalIdentities(context.Context) error {
	return nil
}

// GetIdentities returns the identities from the identity cache.
func (f *MockIdentityAllocator) GetIdentities() cache.IdentitiesModel {
	result := cache.IdentitiesModel{}
	return result.FromIdentityCache(f.GetIdentityCache())
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
		ide := f.idToIdentity[numID]
		ide.referenceCount++
		f.idToIdentity[numID] = ide
		return &ide.id, false, nil
	}

	scope := identity.ScopeForLabels(lbls)
	nid := identity.IdentityUnknown

	// if suggested id is available, use it
	if scope != identity.IdentityScopeGlobal {
		if _, ok := f.idToIdentity[oldNID]; !ok && oldNID.Scope() == identity.ScopeForLabels(lbls) {
			nid = oldNID
		}
	}
	for nid == identity.IdentityUnknown {
		candidate := identity.NumericIdentity(f.nextIDs[scope]) | scope
		_, allocated := f.idToIdentity[candidate]
		_, withheld := f.withheldIdentities[candidate]
		if !allocated && !withheld {
			nid = candidate
		}
		f.nextIDs[scope]++
	}

	f.labelsToIdentity[lbls.String()] = nid

	ide := idEntry{
		id: identity.Identity{
			ID:     identity.NumericIdentity(nid),
			Labels: lbls,
		},
		referenceCount: 1,
	}
	f.idToIdentity[nid] = ide

	return &ide.id, true, nil
}

func (f *MockIdentityAllocator) AllocateLocalIdentity(lbls labels.Labels, notifyOwner bool, oldNID identity.NumericIdentity) (*identity.Identity, bool, error) {
	scope := identity.ScopeForLabels(lbls)
	if scope == identity.IdentityScopeGlobal {
		return nil, false, cache.ErrNonLocalIdentity
	}
	return f.AllocateIdentity(context.TODO(), lbls, notifyOwner, oldNID)
}

func (f *MockIdentityAllocator) ReleaseLocalIdentities(nids ...identity.NumericIdentity) ([]identity.NumericIdentity, error) {
	var dealloc []identity.NumericIdentity
	for _, nid := range nids {
		if nid.Scope() == identity.IdentityScopeGlobal {
			continue
		}
		id := f.LookupIdentityByID(context.TODO(), nid)
		if id == nil {
			continue
		}

		if r, _ := f.Release(context.TODO(), id, true); r {
			dealloc = append(dealloc, nid)
		}
	}
	return dealloc, nil
}

// Release releases a fake identity. It is meant to generally mock the
// canonical identity release logic.
func (f *MockIdentityAllocator) Release(_ context.Context, id *identity.Identity, _ bool) (released bool, err error) {
	ide, ok := f.idToIdentity[id.ID]
	if !ok {
		return false, nil
	}
	if ide.referenceCount == 1 {
		delete(f.idToIdentity, id.ID)
		for key, lblID := range f.labelsToIdentity {
			if lblID == id.ID {
				delete(f.labelsToIdentity, key)
			}
		}
	} else {
		ide.referenceCount--
		f.idToIdentity[id.ID] = ide
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
	nid := f.labelsToIdentity[lbls.String()]
	if nid == 0 {
		return nil
	}
	ide := f.idToIdentity[nid]
	return &ide.id
}

// LookupIdentityByID returns the identity corresponding to the id if the
// identity is a reserved identity. Otherwise, returns nil.
func (f *MockIdentityAllocator) LookupIdentityByID(ctx context.Context, nid identity.NumericIdentity) *identity.Identity {
	if identity := identity.LookupReservedIdentity(nid); identity != nil {
		return identity
	}
	ide, ok := f.idToIdentity[nid]
	if !ok {
		return nil
	}
	return &ide.id
}

// GetIdentityCache returns the identity cache.
func (f *MockIdentityAllocator) GetIdentityCache() identity.IdentityMap {
	out := make(identity.IdentityMap, len(f.idToIdentity))
	for _, ide := range f.idToIdentity {
		out[ide.id.ID] = ide.id.Labels
	}
	return out
}

func (f *MockIdentityAllocator) Observe(ctx context.Context, next func(cache.IdentityChange), complete func(error)) {
	go complete(nil)
}
