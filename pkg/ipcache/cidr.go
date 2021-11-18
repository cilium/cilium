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
	"strings"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/cidr"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"

	"github.com/sirupsen/logrus"
)

var (
	// IdentityAllocator is a package-level variable which is used to allocate
	// identities for CIDRs.
	// TODO: plumb an allocator in from callers of these functions vs. having
	// this as a package-level variable.
	IdentityAllocator cache.IdentityAllocator
)

// AllocateCIDRs attempts to allocate identities for a list of CIDRs. If any
// allocation fails, all allocations are rolled back and the error is returned.
// When an identity is freshly allocated for a CIDR, it is added to the
// ipcache if 'newlyAllocatedIdentities' is 'nil', otherwise the newly allocated
// identities are placed in 'newlyAllocatedIdentities' and it is the caller's
// responsibility to upsert them into ipcache by calling UpsertGeneratedIdentities().
//
// Upon success, the caller must also arrange for the resulting identities to
// be released via a subsequent call to ReleaseCIDRIdentitiesByCIDR().
func AllocateCIDRs(prefixes []*net.IPNet, newlyAllocatedIdentities map[string]*identity.Identity) ([]*identity.Identity, error) {
	return allocateCIDRs(prefixes, newlyAllocatedIdentities)
}

// AllocateCIDRsForIPs attempts to allocate identities for a list of CIDRs. If
// any allocation fails, all allocations are rolled back and the error is
// returned. When an identity is freshly allocated for a CIDR, it is added to
// the ipcache if 'newlyAllocatedIdentities' is 'nil', otherwise the newly allocated
// identities are placed in 'newlyAllocatedIdentities' and it is the caller's
// responsibility to upsert them into ipcache by calling UpsertGeneratedIdentities().
//
// Upon success, the caller must also arrange for the resulting identities to
// be released via a subsequent call to ReleaseCIDRIdentitiesByID().
func AllocateCIDRsForIPs(prefixes []net.IP, newlyAllocatedIdentities map[string]*identity.Identity) ([]*identity.Identity, error) {
	return allocateCIDRs(ip.GetCIDRPrefixesFromIPs(prefixes), newlyAllocatedIdentities)
}

func UpsertGeneratedIdentities(newlyAllocatedIdentities map[string]*identity.Identity) {
	for prefixString, id := range newlyAllocatedIdentities {
		IPIdentityCache.Upsert(prefixString, nil, 0, nil, Identity{
			ID:     id.ID,
			Source: source.Generated,
		})
	}
}

func allocateCIDRs(prefixes []*net.IPNet, newlyAllocatedIdentities map[string]*identity.Identity) ([]*identity.Identity, error) {
	// maintain list of used identities to undo on error
	usedIdentities := make([]*identity.Identity, 0, len(prefixes))

	allocatedIdentities := make(map[string]*identity.Identity, len(prefixes))
	// Maintain list of newly allocated identities to update ipcache,
	// but upsert them to ipcache only if no map was given by the caller.
	upsert := false
	if newlyAllocatedIdentities == nil {
		upsert = true
		newlyAllocatedIdentities = map[string]*identity.Identity{}
	}

	for _, prefix := range prefixes {
		if prefix == nil {
			continue
		}

		prefixStr := prefix.String()

		// Figure out if this call needs to be able to update the selector cache synchronously.
		allocateCtx, cancel := context.WithTimeout(context.Background(), option.Config.IPAllocationTimeout)
		defer cancel()

		if IdentityAllocator == nil {
			return nil, fmt.Errorf("IdentityAllocator not initialized!")
		}
		id, isNew, err := IdentityAllocator.AllocateIdentity(allocateCtx, cidr.GetCIDRLabels(prefix), false)
		if err != nil {
			IdentityAllocator.ReleaseSlice(context.Background(), nil, usedIdentities)
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

	// Only upsert into ipcache if identity wasn't allocated
	// before and the caller does not care doing this
	if upsert {
		UpsertGeneratedIdentities(newlyAllocatedIdentities)
	}

	for _, id := range allocatedIdentities {
		allocatedIdentitiesSlice = append(allocatedIdentitiesSlice, id)
	}

	return allocatedIdentitiesSlice, nil
}

func releaseCIDRIdentities(ctx context.Context, identities map[string]*identity.Identity) {
	for prefix, id := range identities {
		released, err := IdentityAllocator.Release(ctx, id, false)
		if err != nil {
			log.WithFields(logrus.Fields{
				logfields.Identity: id,
				logfields.CIDR:     prefix,
			}).WithError(err).Warning("Unable to release CIDR identity. Ignoring error. Identity may be leaked")
		}

		if released {
			IPIdentityCache.Delete(prefix, source.Generated)
		}
	}
}

// ReleaseCIDRIdentitiesByCIDR releases the identities of a list of CIDRs.
// When the last use of the identity is released, the ipcache entry is deleted.
func ReleaseCIDRIdentitiesByCIDR(prefixes []*net.IPNet) {
	// TODO: Structure the code to pass context down from the Daemon.
	releaseCtx, cancel := context.WithTimeout(context.TODO(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()

	identities := make(map[string]*identity.Identity, len(prefixes))
	for _, prefix := range prefixes {
		if prefix == nil {
			continue
		}

		if id := IdentityAllocator.LookupIdentity(releaseCtx, cidr.GetCIDRLabels(prefix)); id != nil {
			identities[prefix.String()] = id
		} else {
			log.Errorf("Unable to find identity of previously used CIDR %s", prefix.String())
		}
	}

	releaseCIDRIdentities(releaseCtx, identities)
}

// ReleaseCIDRIdentitiesByID releases the specified identities.
// When the last use of the identity is released, the ipcache entry is deleted.
func ReleaseCIDRIdentitiesByID(ctx context.Context, identities []identity.NumericIdentity) {
	fullIdentities := make(map[string]*identity.Identity, len(identities))
	for _, nid := range identities {
		if id := IdentityAllocator.LookupIdentityByID(ctx, nid); id != nil {
			cidr := id.CIDRLabel.String()
			if !strings.HasPrefix(cidr, labels.LabelSourceCIDR) {
				log.WithFields(logrus.Fields{
					logfields.Identity: nid,
					logfields.Labels:   id.Labels,
				}).Warn("Unexpected release of non-CIDR identity, will leak this identity. Please report this issue to the developers.")
				continue
			}
			fullIdentities[strings.TrimPrefix(cidr, labels.LabelSourceCIDR+":")] = id
		} else {
			log.WithFields(logrus.Fields{
				logfields.Identity: nid,
			}).Warn("Unexpected release of numeric identity that is no longer allocated")
		}
	}

	releaseCIDRIdentities(ctx, fullIdentities)
}
