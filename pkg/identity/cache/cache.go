// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"reflect"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/key"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "identity-cache")
)

// IdentitiesModel is a wrapper so that we can implement the sort.Interface
// to sort the slice by ID
type IdentitiesModel []*models.Identity

// Less returns true if the element in index `i` is lower than the element
// in index `j`
func (s IdentitiesModel) Less(i, j int) bool {
	return s[i].ID < s[j].ID
}

// FromIdentityCache populates the provided model from an identity cache.
func (s IdentitiesModel) FromIdentityCache(cache identity.IdentityMap) IdentitiesModel {
	for id, lbls := range cache {
		s = append(s, identitymodel.CreateModel(&identity.Identity{
			ID:     id,
			Labels: lbls.Labels(),
		}))
	}
	return s
}

// GetIdentityCache returns a cache of all known identities
func (m *CachingIdentityAllocator) GetIdentityCache() identity.IdentityMap {
	log.Debug("getting identity cache for identity allocator manager")
	cache := identity.IdentityMap{}

	if m.isGlobalIdentityAllocatorInitialized() {
		m.IdentityAllocator.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
			if val != nil {
				if gi, ok := val.(*key.GlobalIdentity); ok {
					cache[identity.NumericIdentity(id)] = gi.LabelArray
				} else {
					log.Warningf("Ignoring unknown identity type '%s': %+v",
						reflect.TypeOf(val), val)
				}
			}
		})
	}

	identity.IterateReservedIdentities(func(ni identity.NumericIdentity, id *identity.Identity) {
		cache[ni] = id.Labels.LabelArray()
	})

	for _, identity := range m.localIdentities.GetIdentities() {
		cache[identity.ID] = identity.Labels.LabelArray()
	}
	for _, identity := range m.localNodeIdentities.GetIdentities() {
		cache[identity.ID] = identity.Labels.LabelArray()
	}

	return cache
}

// GetIdentities returns all known identities
func (m *CachingIdentityAllocator) GetIdentities() IdentitiesModel {
	identities := IdentitiesModel{}

	if m.isGlobalIdentityAllocatorInitialized() {
		m.IdentityAllocator.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
			if gi, ok := val.(*key.GlobalIdentity); ok {
				identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(id), gi.LabelArray)
				identities = append(identities, identitymodel.CreateModel(identity))
			}

		})
	}
	identity.IterateReservedIdentities(func(ni identity.NumericIdentity, id *identity.Identity) {
		identities = append(identities, identitymodel.CreateModel(id))
	})

	for _, v := range m.localIdentities.GetIdentities() {
		identities = append(identities, identitymodel.CreateModel(v))
	}
	for _, v := range m.localNodeIdentities.GetIdentities() {
		identities = append(identities, identitymodel.CreateModel(v))
	}

	return identities
}

type identityWatcher struct {
	owner IdentityAllocatorOwner
}

// watch starts the identity watcher
// This should be called in a fresh goroutine
func (w *identityWatcher) watch(events allocator.AllocatorEventRecvChan) {
	// The identity watcher batches update events, but only as long as no blocking is required.
	// It also needs to break batching if a given numeric identity is deleted and re-added, since
	// the SelectorCache does not expect identities to mutate.
	// leftover is the add that conflicted with a delete, and thus caused the batching to be broken.

	var (
		added, deleted identity.IdentityMap
		leftover       *allocator.AllocatorEvent
	)

	// collectEvent records the 'event' as an added or deleted identity,
	// and makes sure that any identity is present in only one of the sets
	// (added or deleted).
	// If a delete-then-add is detected for the same numeric identity, it processes
	// the delete, then stashes the add in leftover. This way we never have
	// mutated identities.
	collectEvent := func(event allocator.AllocatorEvent) {
		id := identity.NumericIdentity(event.ID)

		// Only create events have the set of labels.
		if event.Typ == allocator.AllocatorChangeUpsert {
			// We cannot delete and re-add an identity, as label mutation is not allowed.
			// Stash the event in "leftover" and stop iteration
			if _, ok := deleted[id]; ok {
				leftover = &event
				return
			}

			if gi, ok := event.Key.(*key.GlobalIdentity); ok {
				added[id] = gi.LabelArray
			} else {
				log.Warningf("collectEvent: Ignoring unknown identity type '%T': %+v", event.Key, event.Key)
			}
			return
		}

		// Reverse an add when subsequently deleted
		delete(added, id)

		// record the id deleted even if an add was reversed, as the
		// id may also have previously existed, in which case the
		// result is not no-op!
		deleted[id] = labels.LabelArray{}
	}

	for {
		added = identity.IdentityMap{}
		deleted = identity.IdentityMap{}

		// if we had to abort processing a previous event, then pick that up
		// and proceed to flush the queue.
		//
		// Otherwise, wait for the first update.
		if leftover != nil {
			collectEvent(*leftover)
			leftover = nil
		} else {
			// Do nothing until first update or delete is determined
			for {
				event, ok := <-events
				// Wait for one identity add or delete or stop
				if !ok {
					// 'events' was closed
					return
				}
				// skip sync events; wait until first add
				if event.Typ == allocator.AllocatorChangeSync {
					continue
				}
				collectEvent(event)
				break
			}
		}

	More:
		for {
			// see if there is more, but do not wait nor stop
			select {
			case event, ok := <-events:
				if !ok {
					// 'events' was closed
					break More
				}
				// skip sync events; wait until first add
				if event.Typ == allocator.AllocatorChangeSync {
					continue
				}
				// Collect more added and deleted labels
				collectEvent(event)
				if leftover != nil {
					break More
				}
			default:
				// No more events available without blocking
				break More
			}
		}
		// Issue collected updates
		w.owner.UpdateIdentities(added, deleted) // disjoint sets
	}
}

// isGlobalIdentityAllocatorInitialized returns true if m.IdentityAllocator is not nil.
// Note: This does not mean that the identities have been synchronized,
// see WaitForInitialGlobalIdentities to wait for a fully populated cache.
func (m *CachingIdentityAllocator) isGlobalIdentityAllocatorInitialized() bool {
	select {
	case <-m.globalIdentityAllocatorInitialized:
		return m.IdentityAllocator != nil
	default:
		return false
	}
}

// LookupIdentity looks up the identity by its labels but does not create it.
// This function will first search through the local cache, then the caches for
// remote kvstores and finally fall back to the main kvstore.
// May return nil for lookups if the allocator has not yet been synchronized.
func (m *CachingIdentityAllocator) LookupIdentity(ctx context.Context, lbls labels.Labels) *identity.Identity {
	if reservedIdentity := identity.LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		return reservedIdentity
	}

	switch identity.ScopeForLabels(lbls) {
	case identity.IdentityScopeLocal:
		return m.localIdentities.lookup(lbls)
	case identity.IdentityScopeRemoteNode:
		return m.localNodeIdentities.lookup(lbls)
	}

	if !m.isGlobalIdentityAllocatorInitialized() {
		return nil
	}

	lblArray := lbls.LabelArray()
	id, err := m.IdentityAllocator.GetIncludeRemoteCaches(ctx, &key.GlobalIdentity{LabelArray: lblArray})
	if err != nil {
		return nil
	}
	if id > identity.MaxNumericIdentity {
		return nil
	}

	if id == idpool.NoID {
		return nil
	}

	return identity.NewIdentityFromLabelArray(identity.NumericIdentity(id), lblArray)
}

var unknownIdentity = identity.NewIdentity(identity.IdentityUnknown, labels.Labels{labels.IDNameUnknown: labels.NewLabel(labels.IDNameUnknown, "", labels.LabelSourceReserved)})

// LookupIdentityByID returns the identity by ID. This function will first
// search through the local cache, then the caches for remote kvstores and
// finally fall back to the main kvstore
// May return nil for lookups if the allocator has not yet been synchronized.
func (m *CachingIdentityAllocator) LookupIdentityByID(ctx context.Context, id identity.NumericIdentity) *identity.Identity {
	if id == identity.IdentityUnknown {
		return unknownIdentity
	}

	if identity := identity.LookupReservedIdentity(id); identity != nil {
		return identity
	}

	switch id.Scope() {
	case identity.IdentityScopeLocal:
		return m.localIdentities.lookupByID(id)
	case identity.IdentityScopeRemoteNode:
		return m.localNodeIdentities.lookupByID(id)
	}

	if !m.isGlobalIdentityAllocatorInitialized() {
		return nil
	}

	allocatorKey, err := m.IdentityAllocator.GetByIDIncludeRemoteCaches(ctx, idpool.ID(id))
	if err != nil {
		return nil
	}

	if gi, ok := allocatorKey.(*key.GlobalIdentity); ok {
		return identity.NewIdentityFromLabelArray(id, gi.LabelArray)
	}

	return nil
}
