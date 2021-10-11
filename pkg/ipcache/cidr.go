// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2019 Authors of Cilium

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
func AllocateCIDRs(
	prefixes []*net.IPNet, newlyAllocatedIdentities map[string]*identity.Identity,
) ([]*identity.Identity, error) {
	// maintain list of used identities to undo on error
	usedIdentities := make([]*identity.Identity, 0, len(prefixes))

	// Maintain list of newly allocated identities to update ipcache,
	// but upsert them to ipcache only if no map was given by the caller.
	upsert := false
	if newlyAllocatedIdentities == nil {
		upsert = true
		newlyAllocatedIdentities = map[string]*identity.Identity{}
	}

	allocatedIdentities := make(map[string]*identity.Identity, len(prefixes))
	for _, p := range prefixes {
		if p == nil {
			continue
		}

		lbls := cidr.GetCIDRLabels(p)
		lbls.MergeLabels(GetIDMetadataByIP(p.IP.String()))

		id, isNew, err := allocate(p, lbls)
		if err != nil {
			IdentityAllocator.ReleaseSlice(context.Background(), nil, usedIdentities)
			return nil, err
		}

		prefixStr := p.String()
		usedIdentities = append(usedIdentities, id)
		allocatedIdentities[prefixStr] = id
		if isNew {
			newlyAllocatedIdentities[prefixStr] = id
		}
	}

	// Only upsert into ipcache if identity wasn't allocated
	// before and the caller does not care doing this
	if upsert {
		UpsertGeneratedIdentities(newlyAllocatedIdentities)
	}

	identities := make([]*identity.Identity, 0, len(allocatedIdentities))
	for _, id := range allocatedIdentities {
		identities = append(identities, id)
	}
	return identities, nil
}

// AllocateCIDRsForIPs performs the same action as AllocateCIDRs but for IP
// addresses instead of CIDRs.
//
// Upon success, the caller must also arrange for the resulting identities to
// be released via a subsequent call to ReleaseCIDRIdentitiesByID().
func AllocateCIDRsForIPs(
	prefixes []net.IP, newlyAllocatedIdentities map[string]*identity.Identity,
) ([]*identity.Identity, error) {
	return AllocateCIDRs(ip.GetCIDRPrefixesFromIPs(prefixes), newlyAllocatedIdentities)
}

func UpsertGeneratedIdentities(newlyAllocatedIdentities map[string]*identity.Identity) {
	for prefixString, id := range newlyAllocatedIdentities {
		IPIdentityCache.Upsert(prefixString, nil, 0, nil, Identity{
			ID:     id.ID,
			Source: source.Generated,
		})
	}
}

// allocate will allocate a new identity for the given prefix based on the
// given set of labels. This function performs both global and local (CIDR)
// identity allocation and the set of labels determine which identity
// allocation type is to occur.
//
// If the identity is a CIDR identity, then its corresponding Identity will
// have its CIDR labels set correctly.
//
// It is up to the caller to provide the full set of labels for identity
// allocation.
func allocate(prefix *net.IPNet, lbls labels.Labels) (*identity.Identity, bool, error) {
	if prefix == nil {
		return nil, false, nil
	}

	allocateCtx, cancel := context.WithTimeout(context.Background(), option.Config.IPAllocationTimeout)
	defer cancel()

	id, isNew, err := IdentityAllocator.AllocateIdentity(allocateCtx, lbls, false)
	if err != nil {
		return nil, isNew, fmt.Errorf("failed to allocate identity for cidr %s: %s", prefix, err)
	}

	if lbls.Has(labels.LabelWorld[labels.IDNameWorld]) {
		id.CIDRLabel = labels.NewLabelsFromModel([]string{labels.LabelSourceCIDR + ":" + prefix.String()})
	}

	return id, isNew, err
}

func releaseCIDRIdentities(ctx context.Context, identities map[string]*identity.Identity) {
	for prefix, id := range identities {
		released, err := IdentityAllocator.Release(ctx, id)
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
