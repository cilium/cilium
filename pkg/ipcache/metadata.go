// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2019 Authors of Cilium

package ipcache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	cidrlabels "github.com/cilium/cilium/pkg/labels/cidr"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"

	"github.com/sirupsen/logrus"
)

var (
	// idMDMU protects the IdentityMetadata map.
	idMDMU lock.RWMutex
	// IdentityMetadata maps IP prefixes (x.x.x.x/32) to their labels.
	IdentityMetadata = make(map[string]labels.Labels)

	// ErrLocalIdentityAllocatorUninitialized is an error that's returned when
	// the local identity allocator is uninitialized.
	ErrLocalIdentityAllocatorUninitialized = errors.New("local identity allocator uninitialized")
)

// UpsertMetadata upserts a given IP and its corresponding labels associated
// with it into the IdentityMetadata map. The given labels are not modified nor
// is its reference saved, as their copied when inserting into the map.
func UpsertMetadata(prefix string, lbls labels.Labels) {
	l := labels.NewLabelsFromModel(nil)
	l.MergeLabels(lbls)

	idMDMU.Lock()
	if cur, ok := IdentityMetadata[prefix]; !ok {
		IdentityMetadata[prefix] = l
	} else {
		l.MergeLabels(cur)
		IdentityMetadata[prefix] = l
	}
	idMDMU.Unlock()
}

// GetIDMetadataByIP returns the associated labels with an IP. The caller must
// not modifying the returned object as it's a live reference to the underlying
// map.
func GetIDMetadataByIP(prefix string) labels.Labels {
	idMDMU.RLock()
	defer idMDMU.RUnlock()
	return IdentityMetadata[prefix]
}

// InjectLabels injects labels into the IdentityMetadata (IDMD) map. The given
// source is the source of the caller, as inserting into the IPCache requires
// where this updated information is coming from.

// Note that as this function iterates through the IDMD, if it detects a change
// in labels for a given prefix, then this might allocate a new identity. If a
// prefix was previously assoicated with an identity, it will get deallocated,
// so a balance is kept.
func InjectLabels(src source.Source, updater identityUpdater, triggerer policyTriggerer) error {
	if !IdentityAllocator.IsLocalIdentityAllocatorInitialized() {
		return ErrLocalIdentityAllocatorUninitialized
	}

	idMDMU.Lock()
	defer idMDMU.Unlock()

	var (
		// trigger is true when we need to trigger policy recalculations.
		trigger bool
		// toUpsert stores IPKeyPairs to upsert into the ipcache.
		toUpsert = make(map[string]Identity)
		// idsToPropagate stores the identities that must be updated via the
		// selector cache.
		idsToPropagate = make(map[identity.NumericIdentity]labels.LabelArray)
	)
	for prefix, lbls := range IdentityMetadata {
		id, isNew, err := injectLabels(prefix, lbls)
		if err != nil {
			return fmt.Errorf("failed to allocate new identity for IP %v: %w", prefix, err)
		}

		// Reserved IDs should always be upserted if there was a change to
		// their labels. This is especially important for IDs such as
		// kube-apiserver which is can be accompanied by other labels such as
		// remote-node, host, or CIDR labels.
		// Also, any new identity should be upserted.
		if id.IsReserved() || isNew {
			var hasKubeAPIServer bool
			if lbls.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]) {
				// Overwrite the source because any IP associated with the
				// kube-apiserver takes the strongest precedence. This is
				// because we need to overwrite Local if only the local node IP
				// has been upserted into the ipcache first.
				//
				// Also, trigger policy recalculations to update kube-apiserver
				// identity.
				src = source.KubeAPIServer
				trigger = true
				hasKubeAPIServer = true
			}

			toUpsert[prefix] = Identity{
				ID:     id.ID,
				Source: src,
			}
			if id.IsReserved() && hasKubeAPIServer {
				identity.AddReservedIdentityWithLabels(id.ID, lbls)
				idsToPropagate[id.ID] = lbls.LabelArray()
			}
		}
	}

	if IPIdentityCache.k8sSyncedChecker == nil ||
		!IPIdentityCache.k8sSyncedChecker.K8sCacheIsSynced() {
		return errors.New("k8s cache not fully synced")
	}

	// Recalculate policy first before upserting into the ipcache.
	if trigger {
		if updater == nil || triggerer == nil {
			return errors.New("policy updater not yet initialized")
		}

		// Accumulate the desired policy map changes as the identities have
		// been updated with new labels.
		var wg sync.WaitGroup
		updater.UpdateIdentities(idsToPropagate, nil, &wg)
		wg.Wait()

		// This will take the accumulated policy map changes from the above,
		// and realizes it into the datapath.
		triggerer.TriggerPolicyUpdates(false, "kube-apiserver identity updated")
	}

	for ip, id := range toUpsert {
		hIP, key := IPIdentityCache.GetHostIPCache(ip)
		meta := IPIdentityCache.GetK8sMetadata(ip)
		if _, err := IPIdentityCache.Upsert(ip, hIP, key, meta, Identity{
			ID:     id.ID,
			Source: src,
		}); err != nil {
			return fmt.Errorf("failed to upsert %s into ipcache: %w", ip, err)
		}
	}

	return nil
}

func injectLabels(prefix string, lbls labels.Labels) (*identity.Identity, bool, error) {
	// Before allocating an identity, check if we should deallocate the old one
	// first, if it exists.
	if id, exists := IPIdentityCache.LookupByIP(prefix); exists {
		// But not if it's only the kube-apiserver reserved identity. The
		// kube-apiserver label can be associated with the host and CIDR
		// labels.
		realID := IdentityAllocator.LookupIdentityByID(context.TODO(), id.ID)
		if realID != nil && !realID.Labels.Equals(labels.LabelKubeAPIServer) {
			scopedLog := log.WithFields(logrus.Fields{
				logfields.IPAddr:         prefix,
				logfields.OldIdentity:    realID,
				logfields.IdentityLabels: realID.Labels,
			})

			released, err := IdentityAllocator.Release(context.TODO(), realID)
			if err != nil {
				scopedLog.WithError(err).Warn(
					"Failed to release previously assigned identity to IP, this might be a leak.",
				)
			} else {
				scopedLog.WithFields(logrus.Fields{
					"released":       released,
					logfields.Labels: lbls,
				}).Debug(
					"Releasing old identity with previously assigned to IP and updating with new set of labels",
				)
			}
		}
	}

	// If no other labels are associated with this IP, we assume that it's
	// outside of the cluster and hence needs a CIDR identity. This might be a
	// temporary identity.
	if lbls.Equals(labels.LabelKubeAPIServer) {
		// The release of the identitiy allocated has been handled above. This
		// can happen if we discover that the prefix is also associated with
		// other labels besides kube-apiserver, i.e. if the kube-apiserver is
		// not running outside of the cluster.
		return injectLabelsForCIDR(prefix, lbls)
	}

	ctx, cancel := context.WithTimeout(context.Background(), option.Config.IPAllocationTimeout)
	defer cancel()
	return IdentityAllocator.AllocateIdentity(ctx, lbls, false)
}

// injectLabelsForCIDR will allocate a CIDR identity for the given prefix. The
// release of the identity must be managed by the caller.
func injectLabelsForCIDR(prefix string, lbls labels.Labels) (*identity.Identity, bool, error) {
	if !strings.Contains(prefix, "/") {
		prefix = prefix + "/32"
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

	return allocate(cidr, allLbls)
}

// FilterMetadataByLabels returns all the prefixes inside the IdentityMetadata
// map which contain the given labels. Note that `filter` is a subset match,
// not a full match.
func FilterMetadataByLabels(filter labels.Labels) []string {
	idMDMU.RLock()
	defer idMDMU.RUnlock()
	matching := make([]string, 0)
	for prefix, lbls := range IdentityMetadata {
		if bytes.Contains(lbls.SortedList(), filter.SortedList()) {
			matching = append(matching, prefix)
		}
	}
	return matching
}

// RemoveAllPrefixesWithLabels wraps RemoveLabels to provide a convenient
// method for the caller to remove all given prefixes at once. This function
// will trigger policy update and recalculation if necessary on behalf of the
// caller if any changes to the kube-apiserver were detected.
//
// Identities allocated by InjectLabels() may be released by RemoveLabels().
//
// A prefix will only be removed from the IDMD if the set of labels becomes
// empty.
func RemoveAllPrefixesWithLabels(
	m map[string]labels.Labels,
	src source.Source,
	updater identityUpdater,
	triggerer policyTriggerer,
) {
	var (
		hasKubeAPIServer bool

		idsToPropagate = make(map[identity.NumericIdentity]labels.LabelArray)
	)
	for prefix, lbls := range m {
		id, exists := IPIdentityCache.LookupByIP(prefix)
		if id.ID <= identity.IdentityUnknown || !exists {
			continue
		}
		if lbls.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]) {
			hasKubeAPIServer = true
		}
		// Insert to propagate the updated set of labels after removal.
		idsToPropagate[id.ID] = RemoveLabels(prefix, lbls, src).LabelArray()
	}
	if hasKubeAPIServer {
		if updater == nil || triggerer == nil {
			log.Warn("Unable to trigger policy updates after removing from ipcache because policy subsystem is not yet initialized.")
			return
		}

		var wg sync.WaitGroup
		updater.UpdateIdentities(nil, idsToPropagate, &wg)
		wg.Wait()

		triggerer.TriggerPolicyUpdates(false, "kube-apiserver identity updated by removal")
	}
}

// RemoveLabels removes the given labels association with the given prefix. The
// leftover labels are returned, if any.
//
// Identities are deallocated and their subequent entry in the IPCache is
// removed if the prefix is no longer associated with any labels.
//
// It is the responsibility of the caller to trigger policy recalculation after
// calling this function.
func RemoveLabels(prefix string, lbls labels.Labels, src source.Source) labels.Labels {
	idMDMU.Lock()
	defer idMDMU.Unlock()

	l, ok := IdentityMetadata[prefix]
	if !ok {
		return nil
	}

	l.Remove(lbls)
	if !l.Equals(lbls) { // Labels left over, do not deallocate
		n := labels.NewLabelsFromModel(nil)
		n.MergeLabels(l)
		return n // copy of leftover
	}

	// No labels left, perform deallocation

	delete(IdentityMetadata, prefix)
	id, exists := IPIdentityCache.LookupByIP(prefix)
	if !exists {
		return nil
	}
	realID := IdentityAllocator.LookupIdentityByID(context.TODO(), id.ID)
	if realID == nil {
		return nil
	}
	released, err := IdentityAllocator.Release(context.TODO(), realID)
	if err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.IPAddr:         prefix,
			logfields.Labels:         lbls,
			logfields.Identity:       realID,
			logfields.IdentityLabels: realID.Labels,
		}).Error(
			"Failed to release assigned identity to IP while removing label association, this might be a leak.",
		)
	}
	if released {
		if lbls.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]) {
			src = source.KubeAPIServer
		}
		IPIdentityCache.Delete(prefix, src)
	}
	return nil
}

// TriggerLabelInjection triggers the label injection controller to iterate
// through the IDMD and potentially allocate new identities based on any label
// changes.
func (ipc *IPCache) TriggerLabelInjection(src source.Source, sc identityUpdater, pt policyTriggerer) {
	// TODO: Would also be nice to have an end-to-end test to validate on
	//       upgrade that there are no connectivity drops when this channel is
	//       preventing transient BPF entries.

	// This controller is for retrying this operation in case it fails. It
	// should eventually succeed.
	ipc.UpdateController(
		"ipcache-inject-labels",
		controller.ControllerParams{
			DoFunc: func(context.Context) error {
				if err := InjectLabels(src, sc, pt); err != nil {
					return fmt.Errorf("failed to inject labels into ipcache: %w", err)
				}
				return nil
			},
		},
	)
}

type identityUpdater interface {
	UpdateIdentities(added, deleted cache.IdentityCache, wg *sync.WaitGroup)
}

type policyTriggerer interface {
	TriggerPolicyUpdates(bool, string)
}
