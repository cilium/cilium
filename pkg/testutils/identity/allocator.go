// Copyright 2018-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testidentity

import (
	"context"
	"net"

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
type FakeIdentityAllocator struct {
	cache.IdentityCache
}

func NewFakeIdentityAllocator(c cache.IdentityCache) *FakeIdentityAllocator {
	if c == nil {
		c = cache.IdentityCache{}
	}
	return &FakeIdentityAllocator{
		IdentityCache: c,
	}
}

// WaitForInitialGlobalIdentities does nothing.
func (f *FakeIdentityAllocator) WaitForInitialGlobalIdentities(context.Context) error {
	return nil
}

func (f *FakeIdentityAllocator) GetIdentities() cache.IdentitiesModel {
	result := cache.IdentitiesModel{}
	return result.FromIdentityCache(f.IdentityCache)
}

// AllocateIdentity does nothing.
func (f *FakeIdentityAllocator) AllocateIdentity(context.Context, labels.Labels, bool) (*identity.Identity, bool, error) {
	return nil, true, nil
}

// Release does nothing.
func (f *FakeIdentityAllocator) Release(context.Context, *identity.Identity, bool) (released bool, err error) {
	return true, nil
}

// ReleaseSlice does nothing.
func (f *FakeIdentityAllocator) ReleaseSlice(context.Context, cache.IdentityAllocatorOwner, []*identity.Identity) error {
	return nil
}

// LookupIdentity is a no-op.
func (f *FakeIdentityAllocator) LookupIdentity(ctx context.Context, lbls labels.Labels) *identity.Identity {
	return nil
}

// LookupIdentityByID returns the identity corresponding to the id if the
// identity is a reserved identity. Otherwise, returns nil.
func (f *FakeIdentityAllocator) LookupIdentityByID(ctx context.Context, id identity.NumericIdentity) *identity.Identity {
	if identity := identity.LookupReservedIdentity(id); identity != nil {
		return identity
	}
	return nil
}

func (f *FakeIdentityAllocator) AllocateCIDRsForIPs(IPs []net.IP, newlyAllocatedIdentities map[string]*identity.Identity) ([]*identity.Identity, error) {
	return nil, nil
}

func (f *FakeIdentityAllocator) ReleaseCIDRIdentitiesByID(ctx context.Context, identities []identity.NumericIdentity) {
}

func (f *FakeIdentityAllocator) GetIdentityCache() cache.IdentityCache {
	return f.IdentityCache
}
