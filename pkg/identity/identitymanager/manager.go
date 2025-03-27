// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitymanager

import (
	"log/slog"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type IDManager interface {
	Add(identity *identity.Identity)
	GetIdentityModels() []*models.IdentityEndpoints
	Remove(identity *identity.Identity)
	RemoveAll()
	RemoveOldAddNew(old *identity.Identity, new *identity.Identity)
	Subscribe(o Observer)
}

// IdentityManager caches information about a set of identities, currently a
// reference count of how many users there are for each identity.
type IdentityManager struct {
	logger     *slog.Logger
	mutex      lock.RWMutex
	identities map[identity.NumericIdentity]*identityMetadata
	observers  map[Observer]struct{}
}

// NewIDManager returns an initialized IdentityManager.
func NewIDManager(logger *slog.Logger) IDManager {
	return newIdentityManager(logger)
}

type identityMetadata struct {
	identity *identity.Identity
	refCount uint
}

func newIdentityManager(logger *slog.Logger) *IdentityManager {
	return &IdentityManager{
		logger:     logger,
		identities: make(map[identity.NumericIdentity]*identityMetadata),
		observers:  make(map[Observer]struct{}),
	}
}

// Add inserts the identity into the identity manager. If the identity is
// already in the identity manager, the reference count for the identity is
// incremented.
func (idm *IdentityManager) Add(identity *identity.Identity) {
	idm.logger.Debug(
		"Adding identity to identity manager",
		logfields.Identity, identity,
	)

	idm.mutex.Lock()
	defer idm.mutex.Unlock()
	idm.add(identity)
}

func (idm *IdentityManager) add(identity *identity.Identity) {
	if identity == nil {
		return
	}

	idMeta, exists := idm.identities[identity.ID]
	if !exists {
		idm.identities[identity.ID] = &identityMetadata{
			identity: identity,
			refCount: 1,
		}
		for o := range idm.observers {
			o.LocalEndpointIdentityAdded(identity)
		}

	} else {
		idMeta.refCount++
	}
}

// RemoveOldAddNew removes old from the identity manager and inserts new
// into the IdentityManager.
// Caller must have previously added the old identity with Add().
// This is a no-op if both identities have the same numeric ID.
func (idm *IdentityManager) RemoveOldAddNew(old, new *identity.Identity) {
	idm.mutex.Lock()
	defer idm.mutex.Unlock()

	if old == nil && new == nil {
		return
	}
	// The host endpoint will always retain its reserved ID, but its labels may
	// change so we need to update its identity.
	if old != nil && new != nil && old.ID == new.ID && new.ID != identity.ReservedIdentityHost {
		return
	}

	idm.logger.Debug(
		"removing old and adding new identity",
		logfields.Old, old,
		logfields.New, new,
	)

	idm.remove(old)
	idm.add(new)
}

// RemoveAll removes all identities.
func (idm *IdentityManager) RemoveAll() {
	idm.mutex.Lock()
	defer idm.mutex.Unlock()

	for id := range idm.identities {
		idm.remove(idm.identities[id].identity)
	}
}

// Remove deletes the identity from the identity manager. If the identity is
// already in the identity manager, the reference count for the identity is
// decremented. If the identity is not in the cache, this is a no-op. If the
// ref count becomes zero, the identity is removed from the cache.
func (idm *IdentityManager) Remove(identity *identity.Identity) {
	idm.logger.Debug(
		"Removing identity from identity manager",
		logfields.Identity, identity,
	)

	idm.mutex.Lock()
	defer idm.mutex.Unlock()
	idm.remove(identity)
}

func (idm *IdentityManager) remove(identity *identity.Identity) {
	if identity == nil {
		return
	}

	idMeta, exists := idm.identities[identity.ID]
	if !exists {
		idm.logger.Error(
			"removing identity not added to the identity manager!",
			logfields.Identity, identity,
		)
		return
	}
	idMeta.refCount--
	if idMeta.refCount == 0 {
		delete(idm.identities, identity.ID)
		for o := range idm.observers {
			o.LocalEndpointIdentityRemoved(identity)
		}
	}

}

// GetIdentityModels returns the API representation of the IdentityManager.
func (idm *IdentityManager) GetIdentityModels() []*models.IdentityEndpoints {
	idm.mutex.RLock()
	defer idm.mutex.RUnlock()

	identities := make([]*models.IdentityEndpoints, 0, len(idm.identities))

	for _, v := range idm.identities {
		identities = append(identities, &models.IdentityEndpoints{
			Identity: model.CreateModel(v.identity),
			RefCount: int64(v.refCount),
		})
	}

	return identities
}

// Subscribe adds the specified Observer to the global identity manager, to be
// notified upon changes to local identity usage.
func (idm *IdentityManager) Subscribe(o Observer) {
	idm.mutex.Lock()
	defer idm.mutex.Unlock()
	idm.observers[o] = struct{}{}
}

// IdentitiesModel is a wrapper so that we can implement the sort.Interface
// to sort the slice by ID
type IdentitiesModel []*models.IdentityEndpoints

// Less returns true if the element in index `i` is lower than the element
// in index `j`
func (s IdentitiesModel) Less(i, j int) bool {
	return s[i].Identity.ID < s[j].Identity.ID
}
