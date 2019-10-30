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

package cache

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/cidr"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// AllocateCIDRs attempts to allocate identities for a list of CIDRs. If any
// allocation fails, all allocations are rolled back and the error is returned.
// When an identity is freshly allocated for a CIDR, it is added to the
// ipcache.
func (m *CachingIdentityAllocator) AllocateCIDRs(prefixes []*net.IPNet) ([]*identity.Identity, error) {
	return m.allocateCIDRs(prefixes)
}

// AllocateCIDRsForIPs attempts to allocate identities for a list of CIDRs. If
// any allocation fails, all allocations are rolled back and the error is
// returned. When an identity is freshly allocated for a CIDR, it is added to
// the ipcache.
func (m *CachingIdentityAllocator) AllocateCIDRsForIPs(prefixes []net.IP) ([]*identity.Identity, error) {
	return m.allocateCIDRs(ip.GetCIDRPrefixesFromIPs(prefixes))
}

func (m *CachingIdentityAllocator) allocateCIDRs(prefixes []*net.IPNet) ([]*identity.Identity, error) {
	// maintain list of used identities to undo on error
	var usedIdentities []*identity.Identity

	// maintain list of newly allocated identities to update ipcache
	allocatedIdentities := map[string]*identity.Identity{}
	newlyAllocatedIdentities := map[string]*identity.Identity{}

	for _, prefix := range prefixes {
		if prefix == nil {
			continue
		}

		prefixStr := prefix.String()

		// Figure out if this call needs to be able to update the selector cache synchronously.
		allocateCtx, cancel := context.WithTimeout(context.Background(), option.Config.IPAllocationTimeout)
		defer cancel()

		id, isNew, err := m.AllocateIdentity(allocateCtx, cidr.GetCIDRLabels(prefix), false)
		if err != nil {
			m.ReleaseSlice(context.Background(), nil, usedIdentities)
			return nil, fmt.Errorf("failed to allocate identity for cidr %s: %s", prefixStr, err)
		}

		id.CIDRLabel = labels.NewLabelsFromModel([]string{labels.LabelSourceCIDR + ":" + prefixStr})

		usedIdentities = append(usedIdentities, id)
		allocatedIdentities[prefixStr] = id
		if isNew {
			newlyAllocatedIdentities[prefixStr] = id
		}

	}

	allocatedIdentitiesSlice := make([]*identity.Identity, 0, len(allocatedIdentities))

	// Only upsert into ipcache if identity wasn't allocated before.
	for prefixString, id := range newlyAllocatedIdentities {
		m.ipc.Upsert(prefixString, nil, 0, nil, ipcache.Identity{
			ID:     id.ID,
			Source: source.Generated,
		})
	}

	for _, id := range allocatedIdentities {
		allocatedIdentitiesSlice = append(allocatedIdentitiesSlice, id)
	}

	return allocatedIdentitiesSlice, nil
}

// ReleaseCIDRs releases the identities of a list of CIDRs. When the last use
// of the identity is released, the ipcache entry is deleted.
func (m *CachingIdentityAllocator) ReleaseCIDRs(prefixes []*net.IPNet) {
	for _, prefix := range prefixes {
		if prefix == nil {
			continue
		}

		if id := m.LookupIdentity(context.TODO(), cidr.GetCIDRLabels(prefix)); id != nil {
			releaseCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
			defer cancel()

			released, err := m.Release(releaseCtx, id)
			if err != nil {
				log.WithError(err).Warningf("Unable to release identity for CIDR %s. Ignoring error. Identity may be leaked", prefix.String())
			}

			if released {
				m.ipc.Delete(prefix.String(), source.Generated)
			}
		} else {
			log.Errorf("Unable to find identity of previously used CIDR %s", prefix.String())
		}
	}
}
