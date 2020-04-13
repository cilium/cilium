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

package ipcache

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	ipPkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/cidr"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

var (
	// IdentityAllocator is a package-level variable which is used to allocate
	// identities for CIDRs.
	// TODO: plumb an allocator in from callers of these functions vs. having
	// this as a package-level variable.
	IdentityAllocator *cache.CachingIdentityAllocator
)

// AllocateCIDRs attempts to allocate identities for a list of CIDRs. If any
// allocation fails, all allocations are rolled back and the error is returned.
// When an identity is freshly allocated for a CIDR, it is added to the
// ipcache.
func AllocateCIDRs(prefixes []*net.IPNet) ([]*identity.Identity, error) {
	// maintain list of used identities to undo on error
	ids := make([]*identity.Identity, 0, len(prefixes))

	for i, prefix := range prefixes {
		id, err := allocateCIDR(prefix)
		if err != nil {
			// release successfully allocated CIDRs
			ReleaseCIDRs(prefixes[:i])
			return nil, err
		}
		ids = append(ids, id)
	}

	return ids, nil
}

// AllocateCIDRForIP attempts to allocate an identity for an IP. When
// an identity is freshly allocated for an IP, it is added to
// the ipcache.
func AllocateCIDRForIP(ip net.IP) (*identity.Identity, error) {
	return allocateCIDR(ipPkg.IPToPrefix(ip))
}

// ReleaseCIDRForIP attempts to release an identity for an IP. When
// the final instance is released, it is removed from the ipcache.
func ReleaseCIDRForIP(ip net.IP, id *identity.Identity) {
	releaseCIDR(ipPkg.IPToPrefix(ip), id)
}

func allocateCIDR(prefix *net.IPNet) (*identity.Identity, error) {
	if prefix == nil {
		return nil, fmt.Errorf("nil prefix!")
	}
	prefixStr := prefix.String()

	// Figure out if this call needs to be able to update the selector cache synchronously.
	allocateCtx, cancel := context.WithTimeout(context.Background(), option.Config.IPAllocationTimeout)
	defer cancel()

	if IdentityAllocator == nil {
		return nil, fmt.Errorf("IdentityAllocator not initialized!")
	}
	id, isNew, err := IdentityAllocator.AllocateIdentity(allocateCtx, cidr.GetCIDRLabels(prefix), false)
	if err != nil || id == nil {
		return nil, fmt.Errorf("failed to allocate identity for cidr %s: %s", prefixStr, err)
	}

	// Only upsert into ipcache if identity wasn't allocated before.
	if isNew {
		id.CIDRLabel = labels.NewLabelsFromModel([]string{labels.LabelSourceCIDR + ":" + prefixStr})
		IPIdentityCache.Upsert(prefixStr, nil, 0, nil, Identity{
			ID:     id.ID,
			Source: source.Generated,
		})
	}
	return id, nil
}

func releaseCIDR(prefix *net.IPNet, id *identity.Identity) {
	releaseCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()

	released, err := IdentityAllocator.Release(releaseCtx, id)
	if err != nil {
		log.WithError(err).Warningf("Unable to release identity for CIDR %s. Ignoring error. Identity may be leaked", prefix.String())
		return
	}

	if released {
		IPIdentityCache.Delete(prefix.String(), source.Generated)
	}
}

// ReleaseCIDRs releases the identities of a list of CIDRs. When the last use
// of the identity is released, the ipcache entry is deleted.
func ReleaseCIDRs(prefixes []*net.IPNet) {
	for _, prefix := range prefixes {
		if prefix == nil {
			continue
		}
		if id := IdentityAllocator.LookupIdentity(context.TODO(), cidr.GetCIDRLabels(prefix)); id != nil {
			releaseCIDR(prefix, id)
		} else {
			log.Errorf("Unable to find identity of previously used CIDR %s", prefix.String())
		}
	}
}
