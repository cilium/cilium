// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nonglobal

import (
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/basicallocator"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	TempIDGCInterval = 2 * time.Minute
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "non-global-identity")
)

// TempSecIDAllocator is responsible for allocating temporary security
// identities. Temporary security identities are used by new pods before a
// global security identity is allocated by cilium-operator.
type TempSecIDAllocator struct {
	allocator          *basicallocator.BasicIDAllocator
	tempIDCache        *TempIDCache
	endpointListerFunc func() []*endpoint.Endpoint
}

// NewTempSecIDAllocator creates a new TempSecIDAllocator for ID values
// between the provided minIDValue and maxIDValue.
func NewTempSecIDAllocator(endpointListerFunc func() []*endpoint.Endpoint) *TempSecIDAllocator {
	return &TempSecIDAllocator{
		allocator:          basicallocator.NewBasicIDAllocator(identity.DefaultMinTempID, identity.DefaultMaxTempID),
		tempIDCache:        NewTempIDCache(),
		endpointListerFunc: endpointListerFunc,
	}
}

type TempIDCache struct {
	mu                lock.RWMutex
	idToIdentity      map[identity.NumericIdentity]*identity.Identity
	keyToIdentity     map[string]*identity.Identity
	markedForDeletion map[identity.NumericIdentity]bool
}

func NewTempIDCache() *TempIDCache {
	return &TempIDCache{
		mu:                lock.RWMutex{},
		idToIdentity:      make(map[identity.NumericIdentity]*identity.Identity),
		keyToIdentity:     make(map[string]*identity.Identity),
		markedForDeletion: make(map[identity.NumericIdentity]bool),
	}
}

// FindOrCreateTempID gets ans existing or creates a temporary security identity
// for the specified labels, to be used before operator creates a global
// security identity.
func (a *TempSecIDAllocator) FindOrCreateTempID(lbls labels.Labels) (*identity.Identity, error) {
	if id, exists := a.LookupByIDKey(&key.GlobalIdentity{LabelArray: lbls.LabelArray()}); exists {
		return id, nil
	}

	a.tempIDCache.mu.Lock()
	defer a.tempIDCache.mu.Unlock()

	allocatedID, err := a.allocator.AllocateRandom()
	if err != nil {
		return nil, err
	}

	numID := identity.NumericIdentity(int64(allocatedID))
	id := identity.NewIdentity(numID, lbls)
	a.insertToCache(id)

	return id, nil
}

func (a *TempSecIDAllocator) LookupByID(numID identity.NumericIdentity) (*identity.Identity, bool) {
	cache := a.tempIDCache
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	id, exists := cache.idToIdentity[numID]
	return id, exists
}

func (a *TempSecIDAllocator) LookupByIDKey(idKey *key.GlobalIdentity) (*identity.Identity, bool) {
	cache := a.tempIDCache
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	id, exists := cache.keyToIdentity[idKey.GetKey()]
	return id, exists
}

func (a *TempSecIDAllocator) insertToCache(id *identity.Identity) {
	numID := id.ID
	if !a.allocator.IsInPoolRange(idpool.ID(numID)) {
		return
	}

	cache := a.tempIDCache
	idKey := &key.GlobalIdentity{LabelArray: id.LabelArray}
	cache.idToIdentity[numID] = id
	cache.keyToIdentity[idKey.GetKey()] = id
}

func (a *TempSecIDAllocator) StartPeriodicGC(stopChan chan struct{}) {
	log.Info("Starting Temp ID periodic garbage collection")

	wait.Until(a.runGC, TempIDGCInterval, stopChan)

	log.Info("Stopping Temp ID periodic garbage collection")
}

// runGC cleans up temp IDs that aren't used by any local endpoints for two
// consecutive GC cycles.
// It finds all temp IDs that aren't used by any local endpoints. It marks
// them for deletion if they aren't already marked. It deletes them if they are
// already marked for deletion in the previous GC run.
func (a *TempSecIDAllocator) runGC() {
	cache := a.tempIDCache
	cache.mu.Lock()
	defer cache.mu.Unlock()

	gcStartTime := time.Now()
	log.Debug("Running Temp ID garbage collection")
	deletedCount := 0
	defer func() {
		gcDuration := time.Since(gcStartTime)
		log.Debugf("Completed Temp ID periodic garbage collection after %v. Deleted Temp IDs: %d", gcDuration, deletedCount)
	}()

	eps := a.endpointListerFunc()
	if len(eps) == 0 {
		return
	}

	usedTempIDs := make(map[identity.NumericIdentity]bool)
	for _, ep := range eps {
		if ep == nil || ep.SecurityIdentity == nil {
			continue
		}

		if identity.IsTempID(ep.SecurityIdentity.ID) {
			usedTempIDs[ep.SecurityIdentity.ID] = true
		}
	}

	for numID, id := range cache.idToIdentity {
		if _, isUsed := usedTempIDs[numID]; isUsed {
			delete(cache.markedForDeletion, numID)
			continue
		}

		if markedforDeletion := cache.markedForDeletion[numID]; !markedforDeletion {
			cache.markedForDeletion[numID] = true
			continue
		}

		idKey := &key.GlobalIdentity{LabelArray: id.Labels.LabelArray()}
		a.allocator.ReturnToAvailablePool(idpool.ID(numID))

		delete(cache.idToIdentity, numID)
		delete(cache.keyToIdentity, idKey.GetKey())
		delete(cache.markedForDeletion, numID)

		deletedCount++
	}
}
