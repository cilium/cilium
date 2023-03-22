// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	cidrlabels "github.com/cilium/cilium/pkg/labels/cidr"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
)

var (
	// ErrLocalIdentityAllocatorUninitialized is an error that's returned when
	// the local identity allocator is uninitialized.
	ErrLocalIdentityAllocatorUninitialized = errors.New("local identity allocator uninitialized")

	LabelInjectorName = "ipcache-inject-labels"
)

// metadata contains the ipcache metadata. Mainily it holds a map which maps IP
// prefixes (x.x.x.x/32) to a set of information (PrefixInfo).
//
// When allocating an identity to associate with each prefix, the
// identity allocation routines will merge this set of labels into the
// complete set of labels used for that local (CIDR) identity,
// thereby associating these labels with each prefix that is 'covered'
// by this prefix. Subsequently these labels may be matched by network
// policy and propagated in monitor output.
//
// ```mermaid
// flowchart
//
//	subgraph resourceInfo
//	labels.Labels
//	source.Source
//	end
//	subgraph PrefixInfo
//	UA[ResourceID]-->LA[resourceInfo]
//	UB[ResourceID]-->LB[resourceInfo]
//	...
//	end
//	subgraph identityMetadata
//	IP_Prefix-->PrefixInfo
//	end
//
// ```
type metadata struct {
	// Protects the m map.
	//
	// If this mutex will be held at the same time as the IPCache mutex,
	// this mutex must be taken first and then take the IPCache mutex in
	// order to prevent deadlocks.
	lock.RWMutex

	// m is the actual map containing the mappings.
	m map[netip.Prefix]PrefixInfo

	// queued* handle updates into the IPCache. Whenever a label is added
	// or removed from a specific IP prefix, that prefix is added into
	// 'queuedPrefixes'. Each time label injection is triggered, it will
	// process the metadata changes for these prefixes and potentially
	// generate updates into the ipcache, policy engine and datapath.
	queuedChangesMU lock.Mutex
	queuedPrefixes  map[netip.Prefix]struct{}
}

func newMetadata() *metadata {
	return &metadata{
		m:              make(map[netip.Prefix]PrefixInfo),
		queuedPrefixes: make(map[netip.Prefix]struct{}),
	}
}

func (m *metadata) dequeuePrefixUpdates() (modifiedPrefixes []netip.Prefix) {
	m.queuedChangesMU.Lock()
	modifiedPrefixes = make([]netip.Prefix, 0, len(m.queuedPrefixes))
	for p := range m.queuedPrefixes {
		modifiedPrefixes = append(modifiedPrefixes, p)
	}
	m.queuedPrefixes = make(map[netip.Prefix]struct{})
	m.queuedChangesMU.Unlock()

	return
}

func (m *metadata) enqueuePrefixUpdates(prefixes ...netip.Prefix) {
	m.queuedChangesMU.Lock()
	defer m.queuedChangesMU.Unlock()

	for _, prefix := range prefixes {
		m.queuedPrefixes[prefix] = struct{}{}
	}
}

func (m *metadata) upsertLocked(prefix netip.Prefix, src source.Source, resource types.ResourceID, info ...IPMetadata) {
	if _, ok := m.m[prefix]; !ok {
		m.m[prefix] = make(PrefixInfo)
	}
	if _, ok := m.m[prefix][resource]; !ok {
		m.m[prefix][resource] = &resourceInfo{
			source: src,
		}
	}

	for _, i := range info {
		m.m[prefix][resource].merge(i, src)
	}

	m.m[prefix].logConflicts(log.WithField(logfields.CIDR, prefix))
}

// GetMetadataLabelsByIP returns the associated labels with an IP.
func (ipc *IPCache) GetMetadataLabelsByIP(addr netip.Addr) labels.Labels {
	prefix := netip.PrefixFrom(addr, addr.BitLen())
	if info := ipc.GetMetadataByPrefix(prefix); info != nil {
		return info.ToLabels()
	}
	return nil
}

// GetMetadataByPrefix returns full metadata for a given IP as a copy.
func (ipc *IPCache) GetMetadataByPrefix(prefix netip.Prefix) PrefixInfo {
	ipc.metadata.RLock()
	defer ipc.metadata.RUnlock()
	m := ipc.metadata.getLocked(prefix)
	n := make(PrefixInfo, len(m))
	for k, v := range m {
		n[k] = v.DeepCopy()
	}
	return n
}

func (m *metadata) getLocked(prefix netip.Prefix) PrefixInfo {
	return m.m[prefix]
}

// InjectLabels injects labels from the ipcache metadata (IDMD) map into the
// identities used for the prefixes in the IPCache. The given source is the
// source of the caller, as inserting into the IPCache requires knowing where
// this updated information comes from. Conversely, RemoveLabelsExcluded()
// performs the inverse: removes labels from the IDMD map and releases
// identities allocated by this function.
//
// Note that as this function iterates through the IDMD, if it detects a change
// in labels for a given prefix, then this might allocate a new identity. If a
// prefix was previously associated with an identity, it will get deallocated,
// so a balance is kept, ensuring a one-to-one mapping between prefix and
// identity.
//
// Returns the CIDRs that were not yet processed, for example due to an
// unexpected error while processing the identity updates for those CIDRs
// The caller should attempt to retry injecting labels for those CIDRs.
func (ipc *IPCache) InjectLabels(ctx context.Context, modifiedPrefixes []netip.Prefix) (remainingPrefixes []netip.Prefix, err error) {
	if ipc.IdentityAllocator == nil {
		return modifiedPrefixes, ErrLocalIdentityAllocatorUninitialized
	}

	if !ipc.cacheStatus.Synchronized() {
		return modifiedPrefixes, errors.New("k8s cache not fully synced")
	}

	type ipcacheEntry struct {
		identity   Identity
		tunnelPeer net.IP
		encryptKey uint8

		force bool
	}

	var (
		// previouslyAllocatedIdentities maps IP Prefix -> Identity for
		// old identities where the prefix will now map to a new identity
		previouslyAllocatedIdentities = make(map[netip.Prefix]Identity)
		// idsToAdd stores the identities that must be updated via the
		// selector cache.
		idsToAdd    = make(map[identity.NumericIdentity]labels.LabelArray)
		idsToDelete = make(map[identity.NumericIdentity]labels.LabelArray)
		// entriesToReplace stores the identity to replace in the ipcache.
		entriesToReplace = make(map[netip.Prefix]ipcacheEntry)
		entriesToDelete  = make(map[netip.Prefix]Identity)
	)

	ipc.metadata.RLock()

	for i, prefix := range modifiedPrefixes {
		pstr := prefix.String()
		oldID, entryExists := ipc.LookupByIP(pstr)
		oldTunnelIP, oldEncryptionKey := ipc.GetHostIPCache(pstr)
		prefixInfo := ipc.metadata.getLocked(prefix)
		if prefixInfo == nil {
			if !entryExists {
				// Already deleted, no new metadata to associate
				continue
			} // else continue below to remove the old entry
		} else {
			var newID *identity.Identity

			// Insert to propagate the updated set of labels after removal.
			newID, _, err = ipc.resolveIdentity(ctx, prefix, prefixInfo, identity.InvalidIdentity)
			if err != nil {
				// NOTE: This may fail during a 2nd or later
				// iteration of the loop. To handle this, break
				// the loop here and continue executing the set
				// of changes for the prefixes that were
				// already processed.
				//
				// Old identities corresponding to earlier
				// prefixes may be released as part of this,
				// so hopefully this forward progress will
				// unblock subsequent calls into this function.
				log.WithError(err).WithFields(logrus.Fields{
					logfields.IPAddr:   prefix,
					logfields.Identity: oldID,
					logfields.Labels:   newID.Labels,
				}).Warning(
					"Failed to allocate new identity while handling change in labels associated with a prefix.",
				)
				remainingPrefixes = modifiedPrefixes[i:]
				err = fmt.Errorf("failed to allocate new identity during label injection: %w", err)
				break
			}

			// We can safely skip the ipcache upsert if the entry matches with
			// the entry in the metadata cache exactly.
			// Note that checking ID alone is insufficient, see GH-24502.
			if oldID.ID == newID.ID && prefixInfo.Source() == oldID.Source &&
				oldTunnelIP.Equal(prefixInfo.TunnelPeer().IP()) &&
				oldEncryptionKey == prefixInfo.EncryptKey().Uint8() {
				goto releaseIdentity
			}

			idsToAdd[newID.ID] = newID.Labels.LabelArray()
			entriesToReplace[prefix] = ipcacheEntry{
				identity: Identity{
					ID:                  newID.ID,
					Source:              prefixInfo.Source(),
					createdFromMetadata: true,
				},
				tunnelPeer: prefixInfo.TunnelPeer().IP(),
				encryptKey: prefixInfo.EncryptKey().Uint8(),
				// IPCache.Upsert() and friends currently require a
				// Source to be provided during upsert. If the old
				// Source was higher precedence due to labels that
				// have now been removed, then we need to explicitly
				// work around that to remove the old higher-priority
				// identity and replace it with this new identity.
				force: entryExists && prefixInfo.Source() != oldID.Source && oldID.ID != newID.ID,
			}
		}
	releaseIdentity:
		if entryExists {
			// 'prefix' is being removed or modified, so some prior
			// iteration of this loop hit the 'injectLabels' case
			// above, thereby allocating a (new) identity. If we
			// delete or update the identity for 'prefix' in this
			// iteration of the loop, then we must balance the
			// allocation from the prior InjectLabels() call by
			// releasing the previous reference.
			previouslyAllocatedIdentities[prefix] = oldID

			// If all associated metadata for this prefix has been removed,
			// and the existing IPCache entry was never touched by any other
			// subsystem using the old Upsert API, then we can safely remove
			// the IPCache entry associated with this prefix.
			if prefixInfo == nil && oldID.createdFromMetadata {
				entriesToDelete[prefix] = oldID
			}
		}
	}
	// Don't hold lock while calling UpdateIdentities, as it will otherwise run into a deadlock
	ipc.metadata.RUnlock()

	// Recalculate policy first before upserting into the ipcache.
	if len(idsToAdd) > 0 {
		ipc.UpdatePolicyMaps(ctx, idsToAdd, idsToDelete)
	}

	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	for p, entry := range entriesToReplace {
		prefix := p.String()
		meta := ipc.getK8sMetadata(prefix)
		if _, err2 := ipc.upsertLocked(
			prefix,
			entry.tunnelPeer,
			entry.encryptKey,
			meta,
			entry.identity,
			entry.force,
		); err2 != nil {
			// It's plausible to pull the same information twice
			// from different sources, for instance in etcd mode
			// where node information is propagated both via the
			// kvstore and via the k8s control plane. If the
			// upsert was rejected due to source precedence, but the
			// identity is unchanged, then we can safely ignore the
			// error message.
			oldID, ok := previouslyAllocatedIdentities[p]
			if !(ok && oldID.ID == entry.identity.ID && errors.Is(err2, &ErrOverwrite{
				ExistingSrc: oldID.Source,
				NewSrc:      entry.identity.Source,
			})) {
				log.WithError(err2).WithFields(logrus.Fields{
					logfields.IPAddr:   prefix,
					logfields.Identity: entry.identity.ID,
				}).Error("Failed to replace ipcache entry with new identity after label removal. Traffic may be disrupted.")
			}
		}
	}

	for _, id := range previouslyAllocatedIdentities {
		realID := ipc.IdentityAllocator.LookupIdentityByID(ctx, id.ID)
		if realID == nil {
			continue
		}
		released, err := ipc.IdentityAllocator.Release(ctx, realID, false)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Identity:       realID,
				logfields.IdentityLabels: realID.Labels,
			}).Warning(
				"Failed to release previously allocated identity during ipcache metadata injection.",
			)
		}
		// Note that not all subsystems currently funnel their
		// IP prefix => metadata mappings through this code. Notably,
		// CIDR policy currently allocates its own identities.
		// Therefore it's possible that the identity that was
		// previously allocated is still in use or referred in that
		// policy. Avoid removing references in the policy engine
		// since those other subsystems should have their own cleanup
		// logic for handling the removal of these identities.
		if released {
			idsToDelete[id.ID] = nil // SelectorCache removal
		}
	}
	if len(idsToDelete) > 0 {
		ipc.UpdatePolicyMaps(ctx, nil, idsToDelete)
	}
	for prefix, id := range entriesToDelete {
		ipc.deleteLocked(prefix.String(), id.Source)
	}

	return remainingPrefixes, err
}

// UpdatePolicyMaps pushes updates for the specified identities into the policy
// engine and ensures that they are propagated into the underlying datapaths.
func (ipc *IPCache) UpdatePolicyMaps(ctx context.Context, addedIdentities, deletedIdentities map[identity.NumericIdentity]labels.LabelArray) {
	// GH-17962: Refactor to call (*Daemon).UpdateIdentities(), instead of
	// re-implementing the same logic here. It will also allow removing the
	// dependencies that are passed into this function.

	var wg sync.WaitGroup
	// SelectorCache.UpdateIdentities() asks for callers to avoid
	// handing the same identity in both 'adds' and 'deletes'
	// parameters here, so make two calls. These changes will not
	// be propagated to the datapath until the UpdatePolicyMaps
	// call below.
	if deletedIdentities != nil {
		ipc.PolicyHandler.UpdateIdentities(nil, deletedIdentities, &wg)
	}
	if addedIdentities != nil {
		ipc.PolicyHandler.UpdateIdentities(addedIdentities, nil, &wg)
	}
	policyImplementedWG := ipc.DatapathHandler.UpdatePolicyMaps(ctx, &wg)
	policyImplementedWG.Wait()
}

// resolveIdentity will either return a previously-allocated identity for the
// given prefix or allocate a new one corresponding to the labels associated
// with the specified PrefixInfo.
//
// This function will take an additional reference on the returned identity.
// The caller *must* ensure that this reference is eventually released via
// a call to ipc.IdentityAllocator.Release(). Typically this is tied to whether
// the caller subsequently injects an entry into the BPF IPCache map:
//   - If the entry is inserted, we assume that the entry will eventually be
//     removed, and when it is removed, we will remove that reference from the
//     identity & release the identity.
//   - If the entry is not inserted (for instance, because the bpf IPCache map
//     already has the same IP -> identity entry in the map), immediately release
//     the reference.
func (ipc *IPCache) resolveIdentity(ctx context.Context, prefix netip.Prefix, info PrefixInfo, restoredIdentity identity.NumericIdentity) (*identity.Identity, bool, error) {
	// Override identities always take precedence
	if identityOverrideLabels, ok := info.identityOverride(); ok {
		return ipc.IdentityAllocator.AllocateIdentity(ctx, identityOverrideLabels, false, identity.InvalidIdentity)
	}

	lbls := info.ToLabels()
	if lbls.Has(labels.LabelWorld[labels.IDNameWorld]) &&
		(lbls.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode]) ||
			lbls.Has(labels.LabelHost[labels.IDNameHost])) {
		// If the prefix is associated with both world and (remote-node or
		// host), then the latter (remote-node or host) take precedence to
		// avoid allocating a CIDR identity for an entity within the cluster.
		n := lbls.Remove(labels.LabelWorld)
		n = n.Remove(cidrlabels.GetCIDRLabels(prefix))
		lbls = n
	}

	if lbls.Has(labels.LabelHost[labels.IDNameHost]) {
		// Associate any new labels with the host identity.
		//
		// This case is a bit special, because other parts of Cilium
		// have hardcoded assumptions around the host identity and
		// that it corresponds to identity.ReservedIdentityHost.
		// If additional labels are associated with the IPs of the
		// host, add those extra labels into the host identity here
		// so that policy will match on the identity correctly.
		//
		// We can get away with this because the host identity is only
		// significant within the current agent's view (ie each agent
		// will calculate its own host identity labels independently
		// for itself). For all other identities, we avoid modifying
		// the labels at runtime and instead opt to allocate new
		// identities below.
		identity.AddReservedIdentityWithLabels(identity.ReservedIdentityHost, lbls)
		return identity.LookupReservedIdentity(identity.ReservedIdentityHost), false, nil
	}

	// If no other labels are associated with this IP, we assume that it's
	// outside of the cluster and hence needs a CIDR identity.
	//
	// This is trying to ensure that remote nodes are assigned the reserved
	// identity "remote-node" (6) or "kube-apiserver" (7). The datapath
	// later makes assumptions about remote cluster nodes in the function
	// identity_is_remote_node(). For now, there is no way to associate any
	// other labels with such IPs, but this assumption will break if/when
	// we allow more arbitrary labels to be associated with these IPs that
	// correspond to remote nodes.
	if !lbls.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode]) &&
		!lbls.Has(labels.LabelHealth[labels.IDNameHealth]) &&
		!lbls.Has(labels.LabelIngress[labels.IDNameIngress]) {
		cidrLabels := cidrlabels.GetCIDRLabels(prefix)
		lbls.MergeLabels(cidrLabels)
	}

	// This should only ever allocate an identity locally on the node,
	// which could theoretically fail if we ever allocate a very large
	// number of identities.
	id, isNew, err := ipc.IdentityAllocator.AllocateIdentity(ctx, lbls, false, restoredIdentity)
	if lbls.Has(labels.LabelWorld[labels.IDNameWorld]) {
		id.CIDRLabel = labels.NewLabelsFromModel([]string{labels.LabelSourceCIDR + ":" + prefix.String()})
	}
	return id, isNew, err
}

// RemoveLabelsExcluded removes the given labels from all IPs inside the IDMD
// except for the IPs / prefixes inside the given excluded set.
//
// The caller must subsequently call IPCache.TriggerLabelInjection() to push
// these changes down into the policy engine and ipcache datapath maps.
func (ipc *IPCache) RemoveLabelsExcluded(
	lbls labels.Labels,
	toExclude map[netip.Prefix]struct{},
	rid types.ResourceID,
) {
	ipc.metadata.Lock()
	defer ipc.metadata.Unlock()

	oldSet := ipc.metadata.filterByLabels(lbls)
	for _, ip := range oldSet {
		if _, ok := toExclude[ip]; !ok {
			ipc.metadata.remove(ip, rid, lbls)
		}
	}
}

// filterByLabels returns all the prefixes inside the ipcache metadata map
// which contain the given labels. Note that `filter` is a subset match, not a
// full match.
//
// Assumes that the ipcache metadata read lock is taken!
func (m *metadata) filterByLabels(filter labels.Labels) []netip.Prefix {
	var matching []netip.Prefix
	sortedFilter := filter.SortedList()
	for prefix, info := range m.m {
		lbls := info.ToLabels()
		if bytes.Contains(lbls.SortedList(), sortedFilter) {
			matching = append(matching, prefix)
		}
	}
	return matching
}

// removeLabels asynchronously removes the labels association for a prefix.
//
// This function assumes that the ipcache metadata lock is held for writing.
func (m *metadata) remove(prefix netip.Prefix, resource types.ResourceID, aux ...IPMetadata) {
	info, ok := m.m[prefix]
	if !ok || info[resource] == nil {
		return
	}
	for _, a := range aux {
		info[resource].unmerge(a)
	}
	if !info[resource].isValid() {
		delete(info, resource)
	}
	if !info.isValid() { // Labels empty, delete
		delete(m.m, prefix)
	}
	m.enqueuePrefixUpdates(prefix)
}

// TriggerLabelInjection triggers the label injection controller to iterate
// through the IDMD and potentially allocate new identities based on any label
// changes.
//
// The following diagram describes the relationship between the label injector
// triggered here and the callers/callees.
//
//	+------------+  (1)        (1)  +-----------------------------+
//	| EP Watcher +-----+      +-----+ CN Watcher / Node Discovery |
//	+-----+------+   W |      | W   +------+----------------------+
//	      |            |      |            |
//	      |            v      v            |
//	      |            +------+            |
//	      |            | IDMD |            |
//	      |            +------+            |
//	      |               ^                |
//	      |               |                |
//	      |           (3) |R               |
//	      | (2)    +------+--------+   (2) |
//	      +------->|Label Injector |<------+
//	     Trigger   +-------+-------+ Trigger
//		      (4) |W    (5) |W
//		          |         |
//		          v         v
//		     +--------+   +---+
//		     |Policy &|   |IPC|
//		     |datapath|   +---+
//		     +--------+
//	legend:
//	* W means write
//	* R means read
func (ipc *IPCache) TriggerLabelInjection() {
	// GH-17829: Would also be nice to have an end-to-end test to validate
	//           on upgrade that there are no connectivity drops when this
	//           channel is preventing transient BPF entries.

	// This controller is for retrying this operation in case it fails. It
	// should eventually succeed.
	ipc.UpdateController(
		LabelInjectorName,
		controller.ControllerParams{
			Context: ipc.Configuration.Context,
			DoFunc: func(ctx context.Context) error {
				var err error

				idsToModify := ipc.metadata.dequeuePrefixUpdates()
				idsToModify, err = ipc.InjectLabels(ctx, idsToModify)
				ipc.metadata.enqueuePrefixUpdates(idsToModify...)

				return err
			},
			MaxRetryInterval: 1 * time.Minute,
		},
	)
}

// ShutdownLabelInjection shuts down the controller in TriggerLabelInjection().
func (ipc *IPCache) ShutdownLabelInjection() error {
	return ipc.controllers.RemoveControllerAndWait(LabelInjectorName)
}
