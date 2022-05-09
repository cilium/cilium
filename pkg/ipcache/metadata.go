// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	cidrlabels "github.com/cilium/cilium/pkg/labels/cidr"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

var (
	// ErrLocalIdentityAllocatorUninitialized is an error that's returned when
	// the local identity allocator is uninitialized.
	ErrLocalIdentityAllocatorUninitialized = errors.New("local identity allocator uninitialized")
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
//   subgraph labelsWithSource
//   labels.Labels
//   source.Feature
//   end
//   subgraph prefixInfo
//   UA[ResourceID]-->LA[labelsWithSource]
//   UB[ResourceID]-->LB[labelsWithSource]
//   ...
//   end
//   subgraph identityMetadata
//   IP_Prefix-->prefixInfo
//   end
// ```
type metadata struct {
	// Protects the m map.
	//
	// If this mutex will be held at the same time as the IPCache mutex,
	// this mutex must be taken first and then take the IPCache mutex in
	// order to prevent deadlocks.
	lock.RWMutex

	// m is the actual map containing the mappings.
	m map[string]prefixInfo

	// queued* handle updates into the IPCache. Whenever a label is added
	// or removed from a specific IP prefix, that prefix is added into
	// 'queuedPrefixes'. Each time label injection is triggered, it will
	// process the metadata changes for these prefixes and potentially
	// generate updates into the ipcache, policy engine and datapath.
	queuedChangesMU lock.Mutex
	queuedPrefixes  map[string]struct{}
}

func newMetadata() *metadata {
	return &metadata{
		m:              make(map[string]prefixInfo),
		queuedPrefixes: make(map[string]struct{}),
	}
}

func (m *metadata) dequeuePrefixUpdates() (modifiedPrefixes []string) {
	m.queuedChangesMU.Lock()
	modifiedPrefixes = make([]string, 0, len(m.queuedPrefixes))
	for p := range m.queuedPrefixes {
		modifiedPrefixes = append(modifiedPrefixes, p)
	}
	m.queuedPrefixes = make(map[string]struct{})
	m.queuedChangesMU.Unlock()

	return
}

func (m *metadata) enqueuePrefixUpdates(prefixes []string) {
	m.queuedChangesMU.Lock()
	defer m.queuedChangesMU.Unlock()

	for _, prefix := range prefixes {
		m.queuedPrefixes[prefix] = struct{}{}
	}
}

// UpsertMetadata upserts a given IP and its corresponding labels associated
// with it into the ipcache metadata map. The given labels are not modified nor
// is its reference saved, as they're copied when inserting into the map.
//
// The caller must subsequently call ipc.TriggerLabelInjection() to implement
// these metadata updates into the datapath.
func (ipc *IPCache) UpsertMetadata(prefix string, lbls labels.Labels, src source.Source, rid types.ResourceID) {
	ipc.metadata.Lock()
	ipc.metadata.upsert(prefix, lbls, src, rid)
	ipc.metadata.enqueuePrefixUpdates([]string{prefix})
	ipc.metadata.Unlock()
}

func (m *metadata) upsert(prefix string, lbls labels.Labels, src source.Source, rid types.ResourceID) {
	l := labels.NewLabelsFromModel(nil)
	l.MergeLabels(lbls)

	m.Lock()
	if _, ok := m.m[prefix]; !ok {
		m.m[prefix] = make(prefixInfo)
	}
	m.m[prefix][rid] = newLabelsWithSource(l, src)
	m.Unlock()
}

// GetIDMetadataByIP returns the associated labels with an IP. The caller must
// not modifying the returned object as it's a live reference to the underlying
// map.
func (ipc *IPCache) GetIDMetadataByIP(prefix string) labels.Labels {
	if info := ipc.metadata.get(prefix); info != nil {
		return info.ToLabels()
	}
	return nil
}

func (m *metadata) get(prefix string) prefixInfo {
	m.RLock()
	defer m.RUnlock()
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
func (ipc *IPCache) InjectLabels(modifiedCIDRs []string) (remainingCIDRs []string, err error) {
	if ipc.IdentityAllocator == nil {
		return modifiedCIDRs, ErrLocalIdentityAllocatorUninitialized
	}

	if ipc.k8sSyncedChecker != nil &&
		!ipc.k8sSyncedChecker.K8sCacheIsSynced() {
		return modifiedCIDRs, errors.New("k8s cache not fully synced")
	}

	var (
		// previouslyAllocatedIdentities maps IP Prefix -> Identity for
		// old identities where the prefix will now map to a new identity
		previouslyAllocatedIdentities = make(map[string]Identity)
		// idsToAdd stores the identities that must be updated via the
		// selector cache.
		idsToAdd    = make(map[identity.NumericIdentity]labels.LabelArray)
		idsToDelete = make(map[identity.NumericIdentity]labels.LabelArray)
		// entriesToReplace stores the identity to replace in the ipcache.
		entriesToReplace   = make(map[string]Identity)
		entriesToDelete    = make(map[string]Identity)
		forceIPCacheUpdate = make(map[string]bool) // prefix => force
	)

	ipc.metadata.RLock()

	for i, prefix := range modifiedCIDRs {
		id, entryExists := ipc.LookupByIP(prefix)
		prefixInfo := ipc.metadata.get(prefix)
		if prefixInfo == nil {
			if !entryExists {
				// Already deleted, no new metadata to associate
				continue
			} // else continue below to remove the old entry
		} else {
			var newID *identity.Identity

			lbls := prefixInfo.ToLabels()

			// Insert to propagate the updated set of labels after removal.
			newID, _, err = ipc.injectLabels(prefix, lbls)
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
					logfields.Identity: id,
					logfields.Labels:   lbls, // new labels
				}).Warning(
					"Failed to allocate new identity while handling change in labels associated with a prefix.",
				)
				remainingCIDRs = modifiedCIDRs[i:]
				err = fmt.Errorf("failed to allocate new identity during label injection: %w", err)
				break
			}

			idsToAdd[newID.ID] = lbls.LabelArray()
			entriesToReplace[prefix] = Identity{
				ID:     newID.ID,
				Source: prefixInfo.Source(),
			}
			// IPCache.Upsert() and friends currently require a
			// Source to be provided during upsert. If the old
			// Source was higher precedence due to labels that
			// have now been removed, then we need to explicitly
			// work around that to remove the old higher-priority
			// identity and replace it with this new identity.
			if entryExists && prefixInfo.Source() != id.Source {
				forceIPCacheUpdate[prefix] = true
			}
		}
		if entryExists {
			// 'prefix' is being removed or modified, so some
			// previous iteration of this code hit one the
			// 'injectLabels' case above, thereby allocating a
			// (new) identity. If we delete or update the identity
			// for 'prefix' in this iteration of the loop, then we
			// must balance the allocation from the prior
			// InjectLabels() call by releasing the previous
			// reference.
			if _, ok := idsToAdd[id.ID]; !ok {
				previouslyAllocatedIdentities[prefix] = id
			}
		}
	}
	// Don't hold lock while calling UpdateIdentities, as it will otherwise run into a deadlock
	ipc.metadata.RUnlock()

	// Recalculate policy first before upserting into the ipcache.
	if len(idsToAdd) > 0 {
		ipc.UpdatePolicyMaps(context.TODO(), idsToAdd, nil)
	}

	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	for ip, id := range entriesToReplace {
		hIP, key := ipc.getHostIPCache(ip)
		meta := ipc.getK8sMetadata(ip)
		if _, err2 := ipc.upsertLocked(
			ip,
			hIP,
			key,
			meta,
			id,
			forceIPCacheUpdate[ip],
		); err2 != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.IPAddr:   ip,
				logfields.Identity: id,
			}).Error("Failed to replace ipcache entry with new identity after label removal. Traffic may be disrupted.")
		}
	}

	for prefix, id := range previouslyAllocatedIdentities {
		realID := ipc.IdentityAllocator.LookupIdentityByID(context.TODO(), id.ID)
		if realID == nil {
			continue
		}
		released, err := ipc.IdentityAllocator.Release(context.TODO(), realID, false)
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
			if _, ok := entriesToReplace[prefix]; !ok {
				entriesToDelete[prefix] = id // IPCache removal
			}
		}
	}
	if len(idsToDelete) > 0 {
		ipc.UpdatePolicyMaps(context.TODO(), nil, idsToDelete)
	}
	for ip, id := range entriesToDelete {
		ipc.deleteLocked(ip, id.Source)
	}

	return remainingCIDRs, err
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

// injectLabels will allocate an identity for the given prefix and the given
// labels. The caller of this function can expect that an identity is newly
// allocated with reference count of 1 or an identity is looked up and its
// reference count is incremented.
//
// The release of the identity must be managed by the caller, except for the
// case where a CIDR policy exists first and then the kube-apiserver policy is
// applied. This is because the CIDR identities before the kube-apiserver
// policy is applied will need to be converted (released and re-allocated) to
// account for the new kube-apiserver label that will be attached to them. This
// is a known issue, see GH-17962 below.
func (ipc *IPCache) injectLabels(prefix string, lbls labels.Labels) (*identity.Identity, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), option.Config.IPAllocationTimeout)
	defer cancel()

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
	if !(lbls.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode])) {
		// GH-17962: Handle the following case:
		//   1) Apply ToCIDR policy (matching IPs of kube-apiserver)
		//   2) Apply kube-apiserver policy
		//
		// Possible implementation:
		//   Lookup CIDR ID => get all CIDR labels minus kube-apiserver label.
		//   If found, means that ToCIDR policy already applied. Convert CIDR
		//   IDs to include a new identity with kube-apiserver label. We don't
		//   need to remove old entries from ipcache because the caller will
		//   overwrite the ipcache entry anyway.

		return ipc.injectLabelsForCIDR(prefix, lbls)
	}

	return ipc.IdentityAllocator.AllocateIdentity(ctx, lbls, false, identity.InvalidIdentity)
}

// injectLabelsForCIDR will allocate a CIDR identity for the given prefix. The
// release of the identity must be managed by the caller.
func (ipc *IPCache) injectLabelsForCIDR(p string, lbls labels.Labels) (*identity.Identity, bool, error) {
	var prefix string

	ip := net.ParseIP(p)
	if ip == nil {
		return nil, false, fmt.Errorf("Invalid IP inserted into IdentityMetadata: %s", prefix)
	} else if ip.To4() != nil {
		prefix = p + "/32"
	} else {
		prefix = p + "/128"
	}

	_, cidr, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, false, err
	}

	allLbls := cidrlabels.GetCIDRLabels(cidr)
	allLbls.MergeLabels(lbls)

	log.WithFields(logrus.Fields{
		logfields.CIDR:   cidr,
		logfields.Labels: lbls, // omitting allLbls as CIDR labels would make this massive
	}).Debug(
		"Injecting CIDR labels for prefix",
	)

	return ipc.allocate(cidr, allLbls, identity.InvalidIdentity)
}

// RemoveLabelsExcluded removes the given labels from all IPs inside the IDMD
// except for the IPs / prefixes inside the given excluded set.
//
// The caller must subsequently call IPCache.TriggerLabelInjection() to push
// these changes down into the policy engine and ipcache datapath maps.
func (ipc *IPCache) RemoveLabelsExcluded(
	lbls labels.Labels,
	toExclude map[string]struct{},
	rid types.ResourceID,
) {
	ipc.metadata.Lock()
	defer ipc.metadata.Unlock()

	oldSet := ipc.metadata.filterByLabels(lbls)
	for _, ip := range oldSet {
		if _, ok := toExclude[ip]; !ok {
			ipc.removeLabels(ip, lbls, rid)
		}
	}
}

// filterByLabels returns all the prefixes inside the ipcache metadata map
// which contain the given labels. Note that `filter` is a subset match, not a
// full match.
//
// Assumes that the ipcache metadata read lock is taken!
func (m *metadata) filterByLabels(filter labels.Labels) []string {
	var matching []string
	sortedFilter := filter.SortedList()
	for prefix, info := range m.m {
		lbls := info.ToLabels()
		if bytes.Contains(lbls.SortedList(), sortedFilter) {
			matching = append(matching, prefix)
		}
	}
	return matching
}

// removeLabels removes the given labels association with the given prefix.
//
// This function assumes that the ipcache metadata lock is held for writing.
func (ipc *IPCache) removeLabels(prefix string, lbls labels.Labels, rid types.ResourceID) {
	info, ok := ipc.metadata.m[prefix]
	if !ok {
		return
	}
	delete(info, rid)

	allLbls := info.ToLabels()
	if len(allLbls) == 0 { // Labels empty, delete
		delete(ipc.metadata.m, prefix)
	}
	ipc.metadata.enqueuePrefixUpdates([]string{prefix})
}

// TriggerLabelInjection triggers the label injection controller to iterate
// through the IDMD and potentially allocate new identities based on any label
// changes.
//
// The following diagram describes the relationship between the label injector
// triggered here and the callers/callees.
//
//      +------------+  (1)        (1)  +-----------------------------+
//      | EP Watcher +-----+      +-----+ CN Watcher / Node Discovery |
//      +-----+------+   W |      | W   +------+----------------------+
//            |            |      |            |
//            |            v      v            |
//            |            +------+            |
//            |            | IDMD |            |
//            |            +------+            |
//            |               ^                |
//            |               |                |
//            |           (3) |R               |
//            | (2)    +------+--------+   (2) |
//            +------->|Label Injector |<------+
//           Trigger   +-------+-------+ Trigger
//                         (4) |W
//                             |
//                             v
//                           +---+
//                           |IPC|
//                           +---+
//      legend:
//      * W means write
//      * R means read
func (ipc *IPCache) TriggerLabelInjection() {
	// GH-17829: Would also be nice to have an end-to-end test to validate
	//           on upgrade that there are no connectivity drops when this
	//           channel is preventing transient BPF entries.

	// This controller is for retrying this operation in case it fails. It
	// should eventually succeed.
	ipc.UpdateController(
		"ipcache-inject-labels",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				var err error

				idsToModify := ipc.metadata.dequeuePrefixUpdates()
				idsToModify, err = ipc.InjectLabels(idsToModify)
				ipc.metadata.enqueuePrefixUpdates(idsToModify)

				return err
			},
		},
	)
}
