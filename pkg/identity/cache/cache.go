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
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "identity-cache")
)

// IdentityCache is a cache of identity to labels mapping
type IdentityCache map[identity.NumericIdentity]labels.LabelArray

// IdentitiesModel is a wrapper so that we can implement the sort.Interface
// to sort the slice by ID
type IdentitiesModel []*models.Identity

// Less returns true if the element in index `i` is lower than the element
// in index `j`
func (s IdentitiesModel) Less(i, j int) bool {
	return s[i].ID < s[j].ID
}

// FromIdentityCache populates the provided model from an identity cache.
func (s IdentitiesModel) FromIdentityCache(cache IdentityCache) IdentitiesModel {
	for id, lbls := range cache {
		s = append(s, identitymodel.CreateModel(&identity.Identity{
			ID:     id,
			Labels: lbls.Labels(),
		}))
	}
	return s
}

// GetIdentityCache returns a cache of all known identities
func (m *CachingIdentityAllocator) GetIdentityCache() IdentityCache {
	log.Debug("getting identity cache for identity allocator manager")
	cache := IdentityCache{}

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

	return identities
}

type identityWatcher struct {
	owner IdentityAllocatorOwner
}

// collectEvent records the 'event' as an added or deleted identity,
// and makes sure that any identity is present in only one of the sets
// (added or deleted).
func collectEvent(event allocator.AllocatorEvent, added, deleted IdentityCache) bool {
	id := identity.NumericIdentity(event.ID)
	// Only create events have the key
	if event.Typ == kvstore.EventTypeCreate {
		if gi, ok := event.Key.(*key.GlobalIdentity); ok {
			// Un-delete the added ID if previously
			// 'deleted' so that collected events can be
			// processed in any order.
			delete(deleted, id)
			added[id] = gi.LabelArray
			return true
		}
		log.Warningf("collectEvent: Ignoring unknown identity type '%s': %+v",
			reflect.TypeOf(event.Key), event.Key)
		return false
	}
	// Reverse an add when subsequently deleted
	delete(added, id)
	// record the id deleted even if an add was reversed, as the
	// id may also have previously existed, in which case the
	// result is not no-op!
	deleted[id] = labels.LabelArray{}

	return true
}

// watch starts the identity watcher
func (w *identityWatcher) watch(events allocator.AllocatorEventRecvChan) {

	go func() {
		for {
			added := IdentityCache{}
			deleted := IdentityCache{}
		First:
			for {
				// Wait for one identity add or delete or stop
				select {
				case event, ok := <-events:
					if !ok {
						// 'events' was closed
						return
					}
					// Collect first added and deleted labels
					switch event.Typ {
					case kvstore.EventTypeCreate, kvstore.EventTypeDelete:
						if collectEvent(event, added, deleted) {
							// First event collected
							break First
						}
					default:
						// Ignore modify events
					}
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
					// Collect more added and deleted labels
					switch event.Typ {
					case kvstore.EventTypeCreate, kvstore.EventTypeDelete:
						collectEvent(event, added, deleted)
					default:
						// Ignore modify events
					}
				default:
					// No more events available without blocking
					break More
				}
			}
			// Issue collected updates
			w.owner.UpdateIdentities(added, deleted) // disjoint sets
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
	if reservedIdentity := identity.LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		return reservedIdentity
	}

	if !identity.RequiresGlobalIdentity(lbls) {
		return m.localIdentities.lookup(lbls)
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

	if id.HasLocalScope() {
		return m.localIdentities.lookupByID(id)
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
