// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"log/slog"
	"reflect"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/key"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
	m.logger.Debug("getting identity cache for identity allocator manager")
	cache := identity.IdentityMap{}

	if m.isGlobalIdentityAllocatorInitialized() {
		m.IdentityAllocator.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
			if val != nil {
				if gi, ok := val.(*key.GlobalIdentity); ok {
					cache[identity.NumericIdentity(id)] = gi.LabelArray
				} else {
					m.logger.Warn(
						"Ignoring unknown identity type",
						logfields.Type, reflect.TypeOf(val),
						logfields.Value, val,
					)
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
	logger *slog.Logger
	owner  IdentityAllocatorOwner

	added, deleted identity.IdentityMap
	toClose        []chan<- struct{}
}

// collectEvent records the 'event' as an added or deleted identity,
// and makes sure that any identity is present in only one of the sets
// (added or deleted).
func (w *identityWatcher) collectEvent(event allocator.AllocatorEvent) {
	if event.Done != nil {
		w.toClose = append(w.toClose, event.Done)
	}

	if event.Typ == allocator.AllocatorChangeSync {
		return
	}

	id := identity.NumericIdentity(event.ID)
	// Only create events have the key
	if event.Typ == allocator.AllocatorChangeUpsert {
		if gi, ok := event.Key.(*key.GlobalIdentity); ok {
			// Un-delete the added ID if previously
			// 'deleted' so that collected events can be
			// processed in any order.
			delete(w.deleted, id)
			w.added[id] = gi.LabelArray
		} else {
			w.logger.Warn(
				"collectEvent: Ignoring unknown identity type",
				logfields.Type, reflect.TypeOf(event.Key),
				logfields.Value, event.Key,
			)
		}
		return
	}
	// Reverse an add when subsequently deleted
	delete(w.added, id)
	// record the id deleted even if an add was reversed, as the
	// id may also have previously existed, in which case the
	// result is not no-op!
	w.deleted[id] = labels.LabelArray{}
}

// watch starts the identity watcher
func (w *identityWatcher) watch(events allocator.AllocatorEventRecvChan) {

	go func() {
		for {
			w.added = identity.IdentityMap{}
			w.deleted = identity.IdentityMap{}
			w.toClose = nil

			// Consume first event synchronously
			event, ok := <-events
			// Wait for one identity add or delete or stop
			if !ok {
				// 'events' was closed
				return
			}

			w.collectEvent(event)

		More:
			for {
				// see if there is more, but do not wait nor stop
				select {
				case event, ok := <-events:
					if !ok {
						// 'events' was closed
						break More
					}
					// Collect more added and deleted labels
					w.collectEvent(event)

				default:
					// No more events available without blocking
					break More
				}
			}
			// Issue collected updates
			if len(w.added)+len(w.deleted) > 0 {
				w.owner.UpdateIdentities(w.added, w.deleted) // disjoint sets
			}

			// If requested, inform producers that events have been consumed
			//
			// Note that this does not wait for PolicyMap updates to be distributed
			// via the SelectorCache. This is curently safe, as it is only used during
			// initialization, and thus there are no endpoints (and no policymaps).
			for _, ch := range w.toClose {
				close(ch)
			}
		}
	}()
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
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

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
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

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
