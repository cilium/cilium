package cache

import (
	"context"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
)

// LocalCacheAllocator is used to share common code for allocating local and
// reserved identities between different implementations of identity allocators.
type LocalCacheAllocator struct {
	Owner               IdentityAllocatorOwner
	LocalIdentities     *LocalIdentityCache
	LocalNodeIdentities *LocalIdentityCache
}

func (l *LocalCacheAllocator) AllocateLocalIdentity(ctx context.Context, lbls labels.Labels, notifyOwner bool, oldNID identity.NumericIdentity) (id *identity.Identity, allocated, completed bool, err error) {
	if option.Config.Debug {
		log.WithFields(logrus.Fields{
			logfields.IdentityLabels: lbls.String(),
		}).Debug("Resolving identity")
	}

	// If there is only one label with the "reserved" source and a well-known
	// key, use the well-known identity for that key.
	if reservedIdentity := identity.LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		if option.Config.Debug {
			log.WithFields(logrus.Fields{
				logfields.Identity:       reservedIdentity.ID,
				logfields.IdentityLabels: lbls.String(),
				"isNew":                  false,
			}).Debug("Resolved reserved identity")
		}
		return reservedIdentity, false, true, nil
	}

	// If the set of labels uses non-global scope,
	// then allocate with the appropriate local allocator and return.
	switch identity.ScopeForLabels(lbls) {
	case identity.IdentityScopeLocal:
		id, allocated, err = l.LocalIdentities.LookupOrCreate(lbls, oldNID, notifyOwner)
		return id, allocated, true, err
	case identity.IdentityScopeRemoteNode:
		id, allocated, err = l.LocalNodeIdentities.LookupOrCreate(lbls, oldNID, notifyOwner)
		return id, allocated, true, err
	}

	return nil, false, false, nil
}

// Release is the reverse operation of AllocateIdentity() and releases the
// identity again. This function may result in kvstore operations.
// After the last user has released the ID, the returned lastUse value is true.
func (l *LocalCacheAllocator) ReleaseLocalIdentity(ctx context.Context, id *identity.Identity, notifyOwner bool) (released, completed bool, err error) {
	// Ignore reserved identities.
	if id.IsReserved() {
		return false, true, nil
	}

	switch identity.ScopeForLabels(id.Labels) {
	case identity.IdentityScopeLocal:
		return l.LocalIdentities.Release(id, notifyOwner), true, nil
	case identity.IdentityScopeRemoteNode:
		return l.LocalNodeIdentities.Release(id, notifyOwner), true, nil
	}

	return false, false, nil
}

func (l *LocalCacheAllocator) WithholdLocalIDs(nids []identity.NumericIdentity) {
	log.WithField(logfields.Identity, nids).Debug("Withholding numeric identities for later restoration")

	// The allocators will return any identities that are not in-scope.
	nids = l.LocalIdentities.withhold(nids)
	nids = append(nids, l.LocalNodeIdentities.withhold(nids)...)
	if len(nids) > 0 {
		log.WithField(logfields.Identity, nids).Error("Attempt to restore invalid numeric identities.")
	}
}

func (l *LocalCacheAllocator) UnwithholdLocalIDs(nids []identity.NumericIdentity) {
	log.WithField(logfields.Identity, nids).Debug("Unwithholding numeric identities")

	// The allocators will ignore any identities that are not in-scope.
	l.LocalIdentities.unwithhold(nids)
	l.LocalNodeIdentities.unwithhold(nids)
}

// GetIdentityCache returns a cache of all known identities
func (l *LocalCacheAllocator) GetLocalIdentityCache() IdentityCache {
	log.Debug("getting identity cache for identity allocator manager")
	cache := IdentityCache{}

	identity.IterateReservedIdentities(func(ni identity.NumericIdentity, id *identity.Identity) {
		cache[ni] = id.Labels.LabelArray()
	})

	for _, identity := range l.LocalIdentities.GetIdentities() {
		cache[identity.ID] = identity.Labels.LabelArray()
	}
	for _, identity := range l.LocalNodeIdentities.GetIdentities() {
		cache[identity.ID] = identity.Labels.LabelArray()
	}

	return cache
}

// GetIdentities returns all known identities
func (l *LocalCacheAllocator) GetLocalIdentities() IdentitiesModel {
	identities := IdentitiesModel{}
	identity.IterateReservedIdentities(func(ni identity.NumericIdentity, id *identity.Identity) {
		identities = append(identities, identitymodel.CreateModel(id))
	})

	for _, v := range l.LocalIdentities.GetIdentities() {
		identities = append(identities, identitymodel.CreateModel(v))
	}
	for _, v := range l.LocalNodeIdentities.GetIdentities() {
		identities = append(identities, identitymodel.CreateModel(v))
	}

	return identities
}

func (l *LocalCacheAllocator) LookupLocalIdentity(ctx context.Context, lbls labels.Labels) (*identity.Identity, bool) {
	if reservedIdentity := identity.LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		return reservedIdentity, true
	}

	switch identity.ScopeForLabels(lbls) {
	case identity.IdentityScopeLocal:
		return l.LocalIdentities.Lookup(lbls), true
	case identity.IdentityScopeRemoteNode:
		return l.LocalNodeIdentities.Lookup(lbls), true
	}

	return nil, false
}

func (l *LocalCacheAllocator) LookupLocalIdentityByID(ctx context.Context, id identity.NumericIdentity) (*identity.Identity, bool) {
	if id == identity.IdentityUnknown {
		return identity.UnknownIdentity, true
	}

	if identity := identity.LookupReservedIdentity(id); identity != nil {
		return identity, true
	}

	switch id.Scope() {
	case identity.IdentityScopeLocal:
		return l.LocalIdentities.LookupByID(id), true
	case identity.IdentityScopeRemoteNode:
		return l.LocalNodeIdentities.LookupByID(id), true
	}

	return nil, false
}

func (l *LocalCacheAllocator) RecordCompletedAllocation(id *identity.Identity, allocated, isNewLocally, notifyOwner bool) {
	// Notify the owner of the newly added identities so that the
	// cached identities can be updated ASAP, rather than just
	// relying on the kv-store update events.
	if allocated || isNewLocally {
		if id.ID.HasLocalScope() {
			metrics.Identity.WithLabelValues(identity.NodeLocalIdentityType).Inc()
		} else if id.ID.HasRemoteNodeScope() {
			metrics.Identity.WithLabelValues(identity.RemoteNodeIdentityType).Inc()
		} else if id.ID.IsReservedIdentity() {
			metrics.Identity.WithLabelValues(identity.ReservedIdentityType).Inc()
		} else {
			metrics.Identity.WithLabelValues(identity.ClusterLocalIdentityType).Inc()
		}
	}

	if allocated && notifyOwner {
		added := IdentityCache{
			id.ID: id.LabelArray,
		}
		l.Owner.UpdateIdentities(added, nil)
	}
}

func (l *LocalCacheAllocator) RecordCompletedRelease(id *identity.Identity, released, notifyOwner bool) {
	if released {
		if id.ID.HasLocalScope() {
			metrics.Identity.WithLabelValues(identity.NodeLocalIdentityType).Dec()
		} else if id.ID.HasRemoteNodeScope() {
			metrics.Identity.WithLabelValues(identity.RemoteNodeIdentityType).Dec()
		} else if id.ID.IsReservedIdentity() {
			metrics.Identity.WithLabelValues(identity.ReservedIdentityType).Dec()
		} else {
			metrics.Identity.WithLabelValues(identity.ClusterLocalIdentityType).Dec()
		}
	}
	if l.Owner != nil && released && notifyOwner {
		deleted := IdentityCache{
			id.ID: id.LabelArray,
		}
		l.Owner.UpdateIdentities(nil, deleted)
	}
}

func MapLabels(allocatorKey allocator.AllocatorKey) labels.Labels {
	var idLabels labels.Labels = nil

	if allocatorKey != nil {
		idLabels = labels.Labels{}
		for k, v := range allocatorKey.GetAsMap() {
			label := labels.ParseLabel(k + "=" + v)
			idLabels[label.Key] = label
		}
	}

	return idLabels
}
