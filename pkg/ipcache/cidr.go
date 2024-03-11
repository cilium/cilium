// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net/netip"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

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

// upsertGeneratedIdentities unconditionally upserts 'newlyAllocatedIdentities'
// into the ipcache, then also upserts any CIDR identities in 'usedIdentities'
// that were not already upserted. If any 'usedIdentities' are upserted, these
// are counted separately as they may provide an indication of another logic
// error elsewhere in the codebase that is causing premature ipcache deletions.
//
// Deprecated: Prefer UpsertLabels() instead.
func (ipc *IPCache) upsertGeneratedIdentities(newlyAllocatedIdentities map[netip.Prefix]*identity.Identity, usedIdentities []*identity.Identity) {
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
		existing, ok := ipc.LookupByIPRLocked(prefix.String())
		if !ok {
			// We need this identity, but it was somehow deleted
			metrics.IPCacheErrorsTotal.WithLabelValues(
				metricTypeRecover, metricErrorUnexpected,
			).Inc()
			toUpsert[prefix] = id
			continue
		}
		if existing.createdFromMetadata {
			// the createdFromMetadata field is used to tell the ipcache that it is safe to delete
			// a prefix when all entries are removed from the metadata layer. However, as this is the
			// "old-style" API, we need to tell InjectLabels(): hands off!
			//
			// This upsert tells the ipcache that the prefix is now in the domain of an older user
			// and thus should not be deleted by clearing createdFromMetadata
			toUpsert[prefix] = id
		}
	}
	ipc.mutex.RUnlock()
	for prefix, id := range toUpsert {

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
	//                            | -> ipc.upsertGeneratedIdentities(...)
	// -> ipc.deleteLocked(...)   |
	//
	// In this case, the expectation from Goroutine 2 is that an identity
	// is allocated and that identity is in the ipcache, but the result
	// is that the identity is allocated but the ipcache entry is missing.
	ipc.Lock()
	defer ipc.Unlock()

	toDelete := make([]netip.Prefix, 0, len(prefixes))
	deletedIDs := make(map[identity.NumericIdentity]labels.LabelArray, len(prefixes))
	for _, prefix := range prefixes {
		lbls := labels.GetCIDRLabels(prefix)
		id := ipc.IdentityAllocator.LookupIdentity(ctx, lbls)
		if id == nil && option.Config.PolicyCIDRMatchesNodes() {
			// Hack for node-cidr feature.
			// We need to look up, exactly, the labels created during AllocateCIDRs(). Which we don't actually
			// know, since it might be a "normal" CIDR identity *or* a remote-node identity.
			//
			// So, if we don't find an identity for the CIDR label-set, and the node-cidr feature is enabled, then try
			// again with the set of labels for nodes.
			//
			// This can go away when CIDR identity restoration transitions to the UpsertLabels() api.
			lbls.MergeLabels(labels.LabelRemoteNode)
			lbls = lbls.Remove(labels.LabelWorld)
			lbls = lbls.Remove(labels.LabelWorldIPv4)
			lbls = lbls.Remove(labels.LabelWorldIPv6)
			id = ipc.IdentityAllocator.LookupIdentity(ctx, lbls)
		}
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
			deletedIDs[id.ID] = id.LabelArray
			toDelete = append(toDelete, prefix)
		}
	}

	for _, prefix := range toDelete {
		ipc.deleteLocked(prefix.String(), source.Generated)
	}
	// Remove any deleted identities from the policy engine.
	ipc.UpdatePolicyMaps(ctx, nil, deletedIDs)
}
