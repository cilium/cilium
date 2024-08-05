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

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// ErrLocalIdentityAllocatorUninitialized is an error that's returned when
	// the local identity allocator is uninitialized.
	ErrLocalIdentityAllocatorUninitialized = errors.New("local identity allocator uninitialized")

	LabelInjectorName = "ipcache-inject-labels"

	injectLabelsControllerGroup = controller.NewGroup("ipcache-inject-labels")
)

// metadata contains the ipcache metadata. Mainily it holds a map which maps IP
// prefixes (x.x.x.x/32) to a set of information (prefixInfo).
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
//	subgraph prefixInfo
//	UA[ResourceID]-->LA[resourceInfo]
//	UB[ResourceID]-->LB[resourceInfo]
//	...
//	end
//	subgraph identityMetadata
//	IP_Prefix-->prefixInfo
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
	m map[netip.Prefix]prefixInfo

	// queued* handle updates into the IPCache. Whenever a label is added
	// or removed from a specific IP prefix, that prefix is added into
	// 'queuedPrefixes'. Each time label injection is triggered, it will
	// process the metadata changes for these prefixes and potentially
	// generate updates into the ipcache, policy engine and datapath.
	queuedChangesMU lock.Mutex
	queuedPrefixes  map[netip.Prefix]struct{}

	// queuedRevision is the "version" of the prefix queue. It is incremented
	// on every *dequeue*. If injection is successful, then injectedRevision
	// is updated and an update broadcast to waiters.
	queuedRevision uint64

	// injectedRevision indicates the current "version" of the queue that has
	// been applied to the ipcache. It is optionally used by ipcache clients
	// to wait for a specific update to be processed. It is protected by a
	// Cond's mutex. When label injection is successful, this will be updated
	// to whatever revision was dequeued and any waiters will be "awoken" via
	// the Cond's Broadcast().
	injectedRevision     uint64
	injectedRevisionCond *sync.Cond

	// reservedHostLock protects the localHostLabels map. Holders must
	// always take the metadata read lock first.
	reservedHostLock lock.Mutex

	// reservedHostLabels collects all labels that apply to the host identity.
	// see updateLocalHostLabels() for more info.
	reservedHostLabels map[netip.Prefix]labels.Labels
}

func newMetadata() *metadata {
	return &metadata{
		m:              make(map[netip.Prefix]prefixInfo),
		queuedPrefixes: make(map[netip.Prefix]struct{}),
		queuedRevision: 1,

		injectedRevisionCond: sync.NewCond(&lock.Mutex{}),

		reservedHostLabels: make(map[netip.Prefix]labels.Labels),
	}
}

// dequeuePrefixUpdates returns the set of queued prefixes, as well as the revision
// that should be passed to setInjectedRevision once label injection has successfully
// completed.
func (m *metadata) dequeuePrefixUpdates() (modifiedPrefixes []netip.Prefix, revision uint64) {
	m.queuedChangesMU.Lock()
	modifiedPrefixes = make([]netip.Prefix, 0, len(m.queuedPrefixes))
	for p := range m.queuedPrefixes {
		modifiedPrefixes = append(modifiedPrefixes, p)
	}
	m.queuedPrefixes = make(map[netip.Prefix]struct{})
	revision = m.queuedRevision
	m.queuedRevision++ // Increment, as any newly-queued prefixes are now subject to the next revision cycle
	m.queuedChangesMU.Unlock()

	return
}

// enqueuePrefixUpdates queues prefixes for label injection. It returns the "next"
// queue revision number, which can be passed to waitForRevision.
func (m *metadata) enqueuePrefixUpdates(prefixes ...netip.Prefix) uint64 {
	m.queuedChangesMU.Lock()
	defer m.queuedChangesMU.Unlock()

	for _, prefix := range prefixes {
		m.queuedPrefixes[prefix] = struct{}{}
	}
	return m.queuedRevision
}

// setInjectectRevision updates the injected revision to a new value and
// wakes all waiters.
func (m *metadata) setInjectedRevision(rev uint64) {
	m.injectedRevisionCond.L.Lock()
	m.injectedRevision = rev
	m.injectedRevisionCond.Broadcast()
	m.injectedRevisionCond.L.Unlock()
}

// waitForRevision waits for the injected revision to be at or above the
// supplied revision. We may skip revisions, as the desired revision is bumped
// every time prefixes are dequeued, but injection may fail. Thus, any revision
// greater or equal to the desired revision is acceptable.
func (m *metadata) waitForRevision(ctx context.Context, rev uint64) error {
	// Allow callers to bail out by cancelling the context
	cleanupCancellation := context.AfterFunc(ctx, func() {
		// We need to acquire injectedRevisionCond.L here to be sure that the
		// Broadcast won't occur before the call to Wait, which would result
		// in a missed signal.
		m.injectedRevisionCond.L.Lock()
		defer m.injectedRevisionCond.L.Unlock()
		m.injectedRevisionCond.Broadcast()
	})
	defer cleanupCancellation()

	m.injectedRevisionCond.L.Lock()
	defer m.injectedRevisionCond.L.Unlock()
	for m.injectedRevision < rev {
		m.injectedRevisionCond.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	return nil
}

// canonicalPrefix returns the canonical version of the prefix which must be
// used for lookups in the metadata prefix map. The canonical representation of
// a prefix has the lower bits of the address always zeroed out and does
// not contain any IPv4-mapped IPv6 address
func canonicalPrefix(prefix netip.Prefix) netip.Prefix {
	if !prefix.IsValid() {
		return prefix // no canonical version of invalid prefix
	}

	// Prefix() always zeroes out the lower bits
	p, err := prefix.Addr().Unmap().Prefix(prefix.Bits())
	if err != nil {
		return prefix // no canonical version of invalid prefix
	}

	return p
}

func (m *metadata) upsertLocked(prefix netip.Prefix, src source.Source, resource types.ResourceID, info ...IPMetadata) []netip.Prefix {
	prefix = canonicalPrefix(prefix)
	changed := false
	if _, ok := m.m[prefix]; !ok {
		changed = true
		m.m[prefix] = make(prefixInfo)
	}
	if _, ok := m.m[prefix][resource]; !ok {
		changed = true
		m.m[prefix][resource] = &resourceInfo{
			source: src,
		}
	}

	for _, i := range info {
		c := m.m[prefix][resource].merge(i, src)
		changed = changed || c
	}

	m.m[prefix].logConflicts(log.WithField(logfields.CIDR, prefix))

	if !changed {
		return nil
	}

	return m.findAffectedChildPrefixes(prefix)
}

// GetMetadataSourceByPrefix returns the highest precedence source which has
// provided metadata for this prefix
func (ipc *IPCache) GetMetadataSourceByPrefix(prefix netip.Prefix) source.Source {
	ipc.metadata.RLock()
	defer ipc.metadata.RUnlock()
	return ipc.metadata.getLocked(prefix).Source()
}

func (m *metadata) getLocked(prefix netip.Prefix) prefixInfo {
	return m.m[canonicalPrefix(prefix)]
}

// findCIDRParentPrefix returns the closest parent prefix has a parent prefix with a CIDR label
// in the metadata cache
func (m *metadata) findCIDRParentPrefix(prefix netip.Prefix) (parent netip.Prefix, ok bool) {
	for bits := prefix.Bits() - 1; bits > 0; bits-- {
		parent, _ = prefix.Addr().Unmap().Prefix(bits) // canonical
		if info, ok := m.m[parent]; ok && info.hasLabelSource(labels.LabelSourceCIDR) {
			return parent, true
		}
	}

	return netip.Prefix{}, false
}

func isChildPrefix(parent, child netip.Prefix) bool {
	if child == parent {
		return true
	}

	return parent.Contains(child.Addr()) && child.Bits() >= parent.Bits()
}

// findAffectedChildPrefixes returns the list of all child prefixes which are
// affected by an update to the parent prefix
func (m *metadata) findAffectedChildPrefixes(parent netip.Prefix) (children []netip.Prefix) {
	if parent.IsSingleIP() {
		return []netip.Prefix{parent} // no children
	}

	for child := range m.m {
		if isChildPrefix(parent, child) {
			children = append(children, child)
		}
	}

	return children
}

// doInjectLabels injects labels from the ipcache metadata (IDMD) map into the
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
//
// Do not call this directly; rather, use TriggerLabelInjection()
func (ipc *IPCache) doInjectLabels(ctx context.Context, modifiedPrefixes []netip.Prefix) (remainingPrefixes []netip.Prefix, err error) {
	if ipc.IdentityAllocator == nil {
		return modifiedPrefixes, ErrLocalIdentityAllocatorUninitialized
	}

	if !ipc.Configuration.CacheStatus.Synchronized() {
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
		// unmanagedPrefixes is the set of prefixes for which we no longer have
		// any metadata, but were created by a call directly to Upsert()
		unmanagedPrefixes = make(map[netip.Prefix]Identity)
	)

	ipc.metadata.RLock()

	for i, prefix := range modifiedPrefixes {
		pstr := prefix.String()
		oldID, entryExists := ipc.LookupByIP(pstr)
		oldTunnelIP, oldEncryptionKey := ipc.GetHostIPCache(pstr)
		prefixInfo := ipc.metadata.getLocked(prefix)
		var newID *identity.Identity
		var isNew bool
		if prefixInfo == nil {
			if !entryExists {
				// Already deleted, no new metadata to associate
				continue
			} // else continue below to remove the old entry
		} else {
			// Insert to propagate the updated set of labels after removal.
			newID, isNew, err = ipc.resolveIdentity(ctx, prefix, prefixInfo, prefixInfo.RequestedIdentity().ID())
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

			// If this ID was newly allocated, we must add it to the SelectorCache
			if isNew {
				idsToAdd[newID.ID] = newID.Labels.LabelArray()
			}
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
			entry, entryToBeReplaced := entriesToReplace[prefix]
			if !oldID.createdFromMetadata && entryToBeReplaced {
				// If the previous ipcache entry for the prefix
				// was not managed by this function, then the
				// previous ipcache user to inject the IPCache
				// entry retains its own reference to the
				// Security Identity. Given that this function
				// is going to assume responsibility for the
				// IPCache entry now, this path must retain its
				// own reference to the Security Identity to
				// ensure that if the other owner ever releases
				// their reference, this reference stays live.
				if option.Config.Debug {
					log.WithFields(logrus.Fields{
						logfields.Prefix:      prefix,
						logfields.OldIdentity: oldID.ID,
						logfields.Identity:    entry.identity.ID,
					}).Debug("Acquiring Identity reference")
				}
			} else {
				previouslyAllocatedIdentities[prefix] = oldID
			}
			// If all associated metadata for this prefix has been removed,
			// and the existing IPCache entry was never touched by any other
			// subsystem using the old Upsert API, then we can safely remove
			// the IPCache entry associated with this prefix.
			if prefixInfo == nil {
				if oldID.createdFromMetadata {
					entriesToDelete[prefix] = oldID
				} else {
					// If, on the other hand, this prefix *was* touched by
					// another, Upsert-based system, flag this prefix as
					// potentially eligible for deletion if all references
					// are removed.
					unmanagedPrefixes[prefix] = oldID
				}
			}
		}

		// The reserved:host identity is special: the numeric ID is fixed,
		// and the set of labels is mutable. Thus, whenever it changes,
		// we must always update the SelectorCache (normally, this is elided
		// when no changes are present).
		if newID != nil && newID.ID == identity.ReservedIdentityHost {
			idsToAdd[newID.ID] = newID.Labels.LabelArray()
		}

		// Again, more reserved:host bookkeeping: if this prefix is no longer ID 1 (because
		// it is being deleted or changing IDs), we need to recompute the labels
		// for reserved:host and push that to the SelectorCache
		if entryExists && oldID.ID == identity.ReservedIdentityHost &&
			(newID == nil || newID.ID != identity.ReservedIdentityHost) {

			i := ipc.updateReservedHostLabels(prefix, nil)
			idsToAdd[i.ID] = i.Labels.LabelArray()
		}

	}
	// Don't hold lock while calling UpdateIdentities, as it will otherwise run into a deadlock
	ipc.metadata.RUnlock()

	// Recalculate policy first before upserting into the ipcache.
	if len(idsToAdd) > 0 {
		ipc.UpdatePolicyMaps(ctx, idsToAdd, nil)
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

	for prefix, id := range previouslyAllocatedIdentities {
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

		// A local identity can be shared by multiple IPCache entries.
		// Therefore, it's possible that the identity that was
		// previously allocated is still in use by other entries.
		// Avoid removing references in the policy engine until we've
		// removed reference to the identity.
		if released {
			idsToDelete[id.ID] = nil // SelectorCache removal

			// Corner case: This prefix + identity was initially created by a direct Upsert(),
			// but all identity references have been released. We should then delete this prefix.
			if oldID, unmanaged := unmanagedPrefixes[prefix]; unmanaged && oldID.ID == id.ID {
				entriesToDelete[prefix] = oldID
				log.WithFields(logrus.Fields{
					logfields.IPAddr:   prefix,
					logfields.Identity: id,
				}).Debug("Force-removing released prefix from the ipcache.")
			}
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
	if len(deletedIdentities) != 0 {
		ipc.PolicyHandler.UpdateIdentities(nil, deletedIdentities, &wg)
	}
	if len(addedIdentities) != 0 {
		ipc.PolicyHandler.UpdateIdentities(addedIdentities, nil, &wg)
	}

	policyImplementedWG := ipc.DatapathHandler.UpdatePolicyMaps(ctx, &wg)
	policyImplementedWG.Wait()
}

// resolveIdentity will either return a previously-allocated identity for the
// given prefix or allocate a new one corresponding to the labels associated
// with the specified prefixInfo.
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
func (ipc *IPCache) resolveIdentity(ctx context.Context, prefix netip.Prefix, info prefixInfo, restoredIdentity identity.NumericIdentity) (*identity.Identity, bool, error) {
	// Override identities always take precedence
	if identityOverrideLabels, ok := info.identityOverride(); ok {
		id, isNew, err := ipc.IdentityAllocator.AllocateIdentity(ctx, identityOverrideLabels, false, identity.InvalidIdentity)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.IPAddr: prefix,
				logfields.Labels: identityOverrideLabels,
			}).Warning("Failed to allocate new identity for prefix's IdentityOverrideLabels.")
		}
		return id, isNew, err
	}

	lbls := info.ToLabels()

	// If there is a parent with an explicit CIDR label, then we want to inherit
	// that - unless prefix already has a CIDR label, has a reserved
	// label, or is a global identity
	if !lbls.HasSource(labels.LabelSourceReserved) &&
		!lbls.HasSource(labels.LabelSourceCIDR) &&
		identity.ScopeForLabels(lbls) != identity.IdentityScopeGlobal {
		// Note: We attach the CIDR label of the parent, not prefix. This ensures
		// that two prefixes with the same identity and the same parent will
		// have the same identity.
		if parent, ok := ipc.metadata.findCIDRParentPrefix(prefix); ok {
			cidrLabels := labels.GetCIDRLabels(parent)
			lbls.MergeLabels(cidrLabels)
		}
	}

	// Ensure any prefix with a FQDN label also has the world label set
	if lbls.HasSource(labels.LabelSourceFQDN) {
		lbls.AddWorldLabel(prefix.Addr())
	}

	// If the prefix is associated with the host or remote-node, then
	// force-remove the world label.
	if lbls.HasRemoteNodeLabel() || lbls.HasHostLabel() {
		n := lbls.Remove(labels.LabelWorld)
		n = n.Remove(labels.LabelWorldIPv4)
		n = n.Remove(labels.LabelWorldIPv6)

		// It is not allowed for nodes to have CIDR labels, unless policy-cidr-match-mode
		// includes "nodes". Then CIDR labels are required.
		if !option.Config.PolicyCIDRMatchesNodes() {
			n = n.Remove(labels.GetCIDRLabels(prefix))
		}
		if !option.Config.PerNodeLabelsEnabled() {
			nodeLabels := n.GetFromSource(labels.LabelSourceNode)
			n = n.Remove(nodeLabels)
		}
		lbls = n
	}

	if lbls.HasHostLabel() {
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
		//
		// As an extra gotcha, we need need to merge all labels for all IPs
		// that resolve to the reserved:host identity, otherwise we can
		// flap identities labels depending on which prefix writes first. See GH-28259.
		i := ipc.updateReservedHostLabels(prefix, lbls)
		return i, false, nil
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
	if !lbls.HasRemoteNodeLabel() && !lbls.HasHealthLabel() && !lbls.HasIngressLabel() &&
		!lbls.HasSource(labels.LabelSourceFQDN) &&
		!lbls.HasSource(labels.LabelSourceCIDR) {
		cidrLabels := labels.GetCIDRLabels(prefix)
		lbls.MergeLabels(cidrLabels)
	}

	// This should only ever allocate an identity locally on the node,
	// which could theoretically fail if we ever allocate a very large
	// number of identities.
	id, isNew, err := ipc.IdentityAllocator.AllocateIdentity(ctx, lbls, false, restoredIdentity)
	if err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.IPAddr: prefix,
			logfields.Labels: lbls,
		}).Warning("Failed to allocate new identity for prefix's Labels.")
		return nil, false, err
	}
	if lbls.HasWorldLabel() {
		id.CIDRLabel = labels.NewLabelsFromModel([]string{labels.LabelSourceCIDR + ":" + prefix.String()})
	}
	return id, isNew, err
}

// updateReservedHostLabels adds or removes labels that apply to the local host.
// The `reserved:host` identity is special: the numeric identity is fixed
// and the set of labels is mutable. (The datapath requires this.) So,
// we need to determine all prefixes that have the `reserved:host` label and
// capture their labels. Then, we must aggregate *all* labels from all prefixes and
// update the labels that correspond to the `reserved:host` identity.
//
// This could be termed a meta-ipcache. The ipcache metadata layer aggregates
// an arbitrary set of resources and labels to a prefix. Here, we are aggregating an arbitrary
// set of prefixes and labels to an identity.
func (ipc *IPCache) updateReservedHostLabels(prefix netip.Prefix, lbls labels.Labels) *identity.Identity {
	ipc.metadata.reservedHostLock.Lock()
	defer ipc.metadata.reservedHostLock.Unlock()
	if lbls == nil {
		delete(ipc.metadata.reservedHostLabels, prefix)
	} else {
		ipc.metadata.reservedHostLabels[prefix] = lbls
	}

	// aggregate all labels and update static identity
	newLabels := labels.NewFrom(labels.LabelHost)
	for _, l := range ipc.metadata.reservedHostLabels {
		newLabels.MergeLabels(l)
	}

	log.WithField(logfields.Labels, newLabels).Debug("Merged labels for reserved:host identity")

	return identity.AddReservedIdentityWithLabels(identity.ReservedIdentityHost, newLabels)
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

	var affectedPrefixes []netip.Prefix
	oldSet := ipc.metadata.filterByLabels(lbls)
	for _, ip := range oldSet {
		if _, ok := toExclude[ip]; !ok {
			affectedPrefixes = append(affectedPrefixes, ipc.metadata.remove(ip, rid, lbls)...)
		}
	}
	ipc.metadata.enqueuePrefixUpdates(affectedPrefixes...)
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

// remove asynchronously removes the labels association for a prefix.
//
// This function assumes that the ipcache metadata lock is held for writing.
func (m *metadata) remove(prefix netip.Prefix, resource types.ResourceID, aux ...IPMetadata) []netip.Prefix {
	prefix = canonicalPrefix(prefix)
	info, ok := m.m[prefix]
	if !ok || info[resource] == nil {
		return nil
	}

	// compute affected prefixes before deletion, to ensure the prefix matches
	// its own entry before it is deleted
	affected := m.findAffectedChildPrefixes(prefix)

	for _, a := range aux {
		info[resource].unmerge(a)
	}
	if !info[resource].isValid() {
		delete(info, resource)
	}
	if !info.isValid() { // Labels empty, delete
		delete(m.m, prefix)
	}

	return affected
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
	ipc.injectionStarted.Do(func() {
		ipc.UpdateController(
			LabelInjectorName,
			controller.ControllerParams{
				Group:            injectLabelsControllerGroup,
				Context:          ipc.Configuration.Context,
				DoFunc:           ipc.handleLabelInjection,
				MaxRetryInterval: 1 * time.Minute,
			},
		)
	})
	ipc.controllers.TriggerController(LabelInjectorName)
}

// Changeable just for unit tests.
var chunkSize = 512

// handleLabelInjection dequeues the set of pending prefixes and processes
// their metadata updates
func (ipc *IPCache) handleLabelInjection(ctx context.Context) error {
	if ipc.Configuration.CacheStatus != nil {
		// wait for k8s caches to sync.
		// this is duplicated from doInjectLabels(), but it keeps us from needlessly
		// churning the queue while the agent initializes.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ipc.Configuration.CacheStatus:
		}
	}

	// Any prefixes that have failed and must be retried
	var retry []netip.Prefix
	var err error

	idsToModify, rev := ipc.metadata.dequeuePrefixUpdates()

	cs := chunkSize
	// no point in dividing for the first run, we will not be releasing any identities anyways.
	if rev == 1 {
		cs = len(idsToModify)
	}

	// Split ipcache updates in to chunks to reduce resource spikes.
	// InjectLabels releases all identities only at the end of processing, so
	// it may allocate up to `chunkSize` additional identities.
	for len(idsToModify) > 0 {
		idx := min(len(idsToModify), cs)
		chunk := idsToModify[0:idx]
		idsToModify = idsToModify[idx:]

		var failed []netip.Prefix

		// If individual prefixes failed injection, doInjectLabels() the set of failed prefixes
		// and sets err. We must ensure the failed prefixes are re-queued for injection.
		failed, err = ipc.doInjectLabels(ctx, chunk)
		retry = append(retry, failed...)
		if err != nil {
			break
		}
	}

	ok := true
	if len(retry) > 0 {
		// err will also be set, so
		ipc.metadata.enqueuePrefixUpdates(retry...)
		ok = false
	}
	if len(idsToModify) > 0 {
		ipc.metadata.enqueuePrefixUpdates(idsToModify...)
		ok = false
	}
	if ok {
		// if all prefixes were successfully injected, bump the revision
		// so that any waiters are made aware.
		ipc.metadata.setInjectedRevision(rev)
	}

	// non-nil err will re-trigger this controller
	return err
}
