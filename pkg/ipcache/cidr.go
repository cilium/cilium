// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/cidr"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// AllocateCIDRs attempts to allocate identities for a list of CIDRs. If any
// allocation fails, all allocations are rolled back and the error is returned.
// When an identity is freshly allocated for a CIDR, it is added to the
// ipcache if 'newlyAllocatedIdentities' is 'nil', otherwise the newly allocated
// identities are placed in 'newlyAllocatedIdentities' and it is the caller's
// responsibility to upsert them into ipcache by calling UpsertGeneratedIdentities().
//
// Previously used numeric identities for the given prefixes may be passed in as the
// 'oldNIDs' parameter; nil slice must be passed if no previous numeric identities exist.
// Previously used NID is allocated if still available. Non-availability is not an error.
//
// Upon success, the caller must also arrange for the resulting identities to
// be released via a subsequent call to ReleaseCIDRIdentitiesByCIDR().
func (ipc *IPCache) AllocateCIDRs(
	prefixes []netip.Prefix, oldNIDs []identity.NumericIdentity, newlyAllocatedIdentities map[netip.Prefix]*identity.Identity,
) ([]*identity.Identity, error) {
	// maintain list of used identities to undo on error
	usedIdentities := make([]*identity.Identity, 0, len(prefixes))

	// Maintain list of newly allocated identities to update ipcache,
	// but upsert them to ipcache only if no map was given by the caller.
	upsert := false
	if newlyAllocatedIdentities == nil {
		upsert = true
		newlyAllocatedIdentities = map[netip.Prefix]*identity.Identity{}
	}

	allocateCtx, cancel := context.WithTimeout(context.Background(), option.Config.IPAllocationTimeout)
	defer cancel()

	ipc.metadata.RLock()
	ipc.Lock()
	allocatedIdentities := make(map[netip.Prefix]*identity.Identity, len(prefixes))
	for i, prefix := range prefixes {
		info := ipc.metadata.getLocked(prefix)

		oldNID := identity.InvalidIdentity
		if oldNIDs != nil && len(oldNIDs) > i {
			oldNID = oldNIDs[i]
		}
		id, isNew, err := ipc.resolveIdentity(allocateCtx, prefix, info, oldNID)
		if err != nil {
			ipc.IdentityAllocator.ReleaseSlice(context.Background(), usedIdentities)
			ipc.Unlock()
			ipc.metadata.RUnlock()
			return nil, err
		}

		usedIdentities = append(usedIdentities, id)
		allocatedIdentities[prefix] = id
		if isNew {
			newlyAllocatedIdentities[prefix] = id
		}
	}
	ipc.Unlock()
	ipc.metadata.RUnlock()

	// Only upsert into ipcache if identity wasn't allocated
	// before and the caller does not care doing this
	if upsert {
		ipc.UpsertGeneratedIdentities(newlyAllocatedIdentities, nil)
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
func (ipc *IPCache) AllocateCIDRsForIPs(
	prefixes []net.IP, newlyAllocatedIdentities map[netip.Prefix]*identity.Identity,
) ([]*identity.Identity, error) {
	return ipc.AllocateCIDRs(ip.IPsToNetPrefixes(prefixes), nil, newlyAllocatedIdentities)
}

func cidrLabelToPrefix(id *identity.Identity) (prefix netip.Prefix, ok bool) {
	var err error

	label := id.CIDRLabel.String()
	if !strings.HasPrefix(label, labels.LabelSourceCIDR) {
		log.WithFields(logrus.Fields{
			logfields.Identity: id.ID,
		}).Warning("BUG: Attempting to upsert non-CIDR identity")
		return
	}

	if prefix, err = netip.ParsePrefix(strings.TrimPrefix(label, labels.LabelSourceCIDR+":")); err != nil {
		log.WithFields(logrus.Fields{
			logfields.Identity: id.ID,
			logfields.Labels:   label,
		}).Warning("BUG: Attempting to upsert identity with bad CIDR label")
		return
	}
	return prefix, true
}

// UpsertGeneratedIdentities unconditionally upserts 'newlyAllocatedIdentities'
// into the ipcache, then also upserts any CIDR identities in 'usedIdentities'
// that were not already upserted. If any 'usedIdentities' are upserted, these
// are counted separately as they may provide an indication of another logic
// error elsewhere in the codebase that is causing premature ipcache deletions.
func (ipc *IPCache) UpsertGeneratedIdentities(newlyAllocatedIdentities map[netip.Prefix]*identity.Identity, usedIdentities []*identity.Identity) {
	for prefix, id := range newlyAllocatedIdentities {
		ipc.Upsert(prefix.String(), nil, 0, nil, Identity{
			ID:     id.ID,
			Source: source.Generated,
		})
	}
	if len(usedIdentities) == 0 {
		return
	}

	toUpsert := make(map[netip.Prefix]*identity.Identity)
	ipc.mutex.RLock()
	for _, id := range usedIdentities {
		prefix, ok := cidrLabelToPrefix(id)
		if !ok {
			continue
		}
		if _, ok := ipc.LookupByIPRLocked(prefix.String()); ok {
			// Already there; continue
			continue
		}
		toUpsert[prefix] = id
	}
	ipc.mutex.RUnlock()
	for prefix, id := range toUpsert {
		metrics.IPCacheErrorsTotal.WithLabelValues(
			metricTypeRecover, metricErrorUnexpected,
		).Inc()
		ipc.Upsert(prefix.String(), nil, 0, nil, Identity{
			ID:     id.ID,
			Source: source.Generated,
		})
	}
}

func (ipc *IPCache) releaseCIDRIdentities(ctx context.Context, prefixes []netip.Prefix) {
	// Create a critical section for identity release + removal from ipcache.
	// Otherwise, it's possible to trigger the following race condition:
	//
	// Goroutine 1                | Goroutine 2
	// releaseCIDRIdentities()    | AllocateCIDRs()
	// -> Release(..., id, ...)   |
	//                            | -> allocate(...)
	//                            | -> ipc.UpsertGeneratedIdentities(...)
	// -> ipc.deleteLocked(...)   |
	//
	// In this case, the expectation from Goroutine 2 is that an identity
	// is allocated and that identity is in the ipcache, but the result
	// is that the identity is allocated but the ipcache entry is missing.
	ipc.Lock()
	defer ipc.Unlock()

	toDelete := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		lbls := cidr.GetCIDRLabels(prefix)
		id := ipc.IdentityAllocator.LookupIdentity(ctx, lbls)
		if id == nil {
			log.Errorf("Unable to find identity of previously used CIDR %s", prefix.String())
			continue
		}
		released, err := ipc.IdentityAllocator.Release(ctx, id, false)
		if err != nil {
			log.WithFields(logrus.Fields{
				logfields.Identity: id,
				logfields.CIDR:     prefix,
			}).WithError(err).Warning("Unable to release CIDR identity. Ignoring error. Identity may be leaked")
		}
		if released {
			toDelete = append(toDelete, prefix)
		}
	}

	for _, prefix := range toDelete {
		ipc.deleteLocked(prefix.String(), source.Generated)
	}
}

// ReleaseCIDRIdentitiesByCIDR releases the identities of a list of CIDRs.
// When the last use of the identity is released, the ipcache entry is deleted.
func (ipc *IPCache) ReleaseCIDRIdentitiesByCIDR(prefixes []netip.Prefix) {
	ipc.deferredPrefixRelease.enqueue(prefixes, "cidr-prefix-release")
}

// ReleaseCIDRIdentitiesByID releases the specified identities.
// When the last use of the identity is released, the ipcache entry is deleted.
func (ipc *IPCache) ReleaseCIDRIdentitiesByID(ctx context.Context, identities []identity.NumericIdentity) {
	prefixes := make([]netip.Prefix, 0, len(identities))
	for _, nid := range identities {
		if id := ipc.IdentityAllocator.LookupIdentityByID(ctx, nid); id != nil {
			prefix, ok := cidrLabelToPrefix(id)
			if !ok {
				log.WithFields(logrus.Fields{
					logfields.Identity: nid,
					logfields.Labels:   id.Labels,
				}).Warn("Unexpected release of non-CIDR identity, will leak this identity. Please report this issue to the developers.")
				continue
			}
			prefixes = append(prefixes, prefix)
		} else {
			log.WithFields(logrus.Fields{
				logfields.Identity: nid,
			}).Warn("Unexpected release of numeric identity that is no longer allocated")
		}
	}

	ipc.deferredPrefixRelease.enqueue(prefixes, "selector-prefix-release")
}
