// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitymanager

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// GlobalIdentityManager is a singleton instance of an IdentityManager, used
	// for easy updating / tracking lifecycles of identities on the local node
	// without having to pass around a specific instance of an IdentityManager
	// throughout Cilium.
	GlobalIdentityManager = NewIdentityManager()
)

// IdentityManager caches information about a set of identities, currently a
// reference count of how many users there are for each identity.
type IdentityManager struct {
	mutex      lock.RWMutex
	identities map[identity.NumericIdentity]*identityMetadata
	observers  map[Observer]struct{}
}

type identityMetadata struct {
	identity *identity.Identity
	refCount uint
}

// NewIdentityManager returns an initialized IdentityManager.
func NewIdentityManager() *IdentityManager {
	return &IdentityManager{
		identities: make(map[identity.NumericIdentity]*identityMetadata),
		observers:  make(map[Observer]struct{}),
	}
}

// Add inserts the identity into the GlobalIdentityManager.
func Add(identity *identity.Identity) {
	GlobalIdentityManager.Add(identity)
}

// Remove deletes the identity from the GlobalIdentityManager.
func Remove(identity *identity.Identity) {
	GlobalIdentityManager.Remove(identity)
}

// RemoveAll deletes all identities from the GlobalIdentityManager.
func RemoveAll() {
	GlobalIdentityManager.RemoveAll()
}

// Add inserts the identity into the identity manager. If the identity is
// already in the identity manager, the reference count for the identity is
// incremented.
func (idm *IdentityManager) Add(identity *identity.Identity) {
	log.WithFields(logrus.Fields{
		logfields.Identity: identity,
	}).Debug("Adding identity to the identity manager")

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

	log.WithFields(logrus.Fields{
		"old": old,
		"new": new,
	}).Debug("removing old and adding new identity")

	idm.remove(old)
	idm.add(new)
}

// RemoveOldAddNew removes old from and inserts new into the
// GlobalIdentityManager.
func RemoveOldAddNew(old, new *identity.Identity) {
	GlobalIdentityManager.RemoveOldAddNew(old, new)
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
	log.WithFields(logrus.Fields{
		logfields.Identity: identity,
	}).Debug("Removing identity from the identity manager")

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
		log.WithFields(logrus.Fields{
			logfields.Identity: identity,
		}).Error("removing identity not added to the identity manager!")
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

func (idm *IdentityManager) subscribe(o Observer) {
	idm.mutex.Lock()
	defer idm.mutex.Unlock()
	idm.observers[o] = struct{}{}
}

// GetIdentityModels returns the API model of all identities in the
// GlobalIdentityManager.
func GetIdentityModels() []*models.IdentityEndpoints {
	return GlobalIdentityManager.GetIdentityModels()
}

// IdentitiesModel is a wrapper so that we can implement the sort.Interface
// to sort the slice by ID
type IdentitiesModel []*models.IdentityEndpoints

// Less returns true if the element in index `i` is lower than the element
// in index `j`
func (s IdentitiesModel) Less(i, j int) bool {
	return s[i].Identity.ID < s[j].Identity.ID
}

// Subscribe adds the specified Observer to the global identity manager, to be
// notified upon changes to local identity usage.
func Subscribe(o Observer) {
	GlobalIdentityManager.subscribe(o)
}
