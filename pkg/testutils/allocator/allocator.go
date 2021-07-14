// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2019 Authors of Cilium

package allocator

import (
	"context"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
)

type IdentityAllocatorOwnerMock struct{}

func (i *IdentityAllocatorOwnerMock) UpdateIdentities(added, deleted cache.IdentityCache) {}

func (i *IdentityAllocatorOwnerMock) GetNodeSuffix() string {
	return "foo"
}

// FakeIdentityAllocator is used as a mock identity allocator for unit tests.
type FakeIdentityAllocator struct{}

// WaitForInitialGlobalIdentities does nothing.
func (f *FakeIdentityAllocator) WaitForInitialGlobalIdentities(context.Context) error {
	return nil
}

// AllocateIdentity does nothing.
func (f *FakeIdentityAllocator) AllocateIdentity(context.Context, labels.Labels, bool) (*identity.Identity, bool, error) {
	return nil, true, nil
}

// Release does nothing.
func (f *FakeIdentityAllocator) Release(context.Context, *identity.Identity) (released bool, err error) {
	return true, nil
}

// LookupIdentityByID returns the identity corresponding to the id if the
// identity is a reserved identity. Otherwise, returns nil.
func (f *FakeIdentityAllocator) LookupIdentityByID(ctx context.Context, id identity.NumericIdentity) *identity.Identity {
	if identity := identity.LookupReservedIdentity(id); identity != nil {
		return identity
	}
	return nil
}
