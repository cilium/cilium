// Copyright 2018 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/cidr"
)

// AllocateCIDRs attempts to allocate identities for a list of CIDRs. If any
// allocation fails, all allocations are rolled back and the error is returned.
// When an identity is freshly allocated for a CIDR, it is added to the
// ipcache.
func AllocateCIDRs(impl Implementation, prefixes []*net.IPNet) error {
	// First, if the implementation will complain, exit early.
	if err := checkPrefixes(impl, prefixes); err != nil {
		return err
	}

	// maintain list of used identities to undo on error
	usedIdentities := []*identity.Identity{}

	// maintain list of newly allocated identities to update ipcache
	allocatedIdentities := map[string]*identity.Identity{}

	for _, prefix := range prefixes {
		if prefix == nil {
			continue
		}

		id, isNew, err := cache.AllocateIdentity(context.Background(), cidr.GetCIDRLabels(prefix))
		if err != nil {
			cache.ReleaseSlice(context.Background(), usedIdentities)
			return fmt.Errorf("failed to allocate identity for cidr %s: %s", prefix.String(), err)
		}

		id.CIDRLabel = labels.NewLabelsFromModel([]string{labels.LabelSourceCIDR + ":" + prefix.String()})

		usedIdentities = append(usedIdentities, id)
		if isNew {
			allocatedIdentities[prefix.String()] = id
		}
	}

	for prefixString, id := range allocatedIdentities {
		IPIdentityCache.Upsert(prefixString, nil, 0, Identity{
			ID:     id.ID,
			Source: FromCIDR,
		})
	}

	return nil
}

// ReleaseCIDRs releases the identities of a list of CIDRs. When the last use
// of the identity is released, the ipcache entry is deleted.
func ReleaseCIDRs(prefixes []*net.IPNet) {
	for _, prefix := range prefixes {
		if prefix == nil {
			continue
		}

		if id := cache.LookupIdentity(cidr.GetCIDRLabels(prefix)); id != nil {
			released, err := cache.Release(context.Background(), id)
			if err != nil {
				log.WithError(err).Warningf("Unable to release identity for CIDR %s. Ignoring error. Identity may be leaked", prefix.String())
			}

			if released {
				IPIdentityCache.Delete(prefix.String(), FromCIDR)
			}
		} else {
			log.Errorf("Unable to find identity of previously used CIDR %s", prefix.String())
		}
	}
}
