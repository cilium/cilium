// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/identity"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
)

// IdentityGetter implements types.IdentityGetter using Cilium's identity
// allocator.
type IdentityGetter struct {
	identityAllocator identitycell.CachingIdentityAllocator
}

func NewIdentityGetter(identityAllocator identitycell.CachingIdentityAllocator) types.IdentityGetter {
	return &IdentityGetter{identityAllocator: identityAllocator}
}

// GetIdentity implements types.IdentityGetter. It looks up identity by ID
// from Cilium's identity cache.
func (g *IdentityGetter) GetIdentity(securityIdentity uint32) (*identity.Identity, error) {
	ident := g.identityAllocator.LookupIdentityByID(context.Background(), identity.NumericIdentity(securityIdentity))
	if ident == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return ident, nil
}
