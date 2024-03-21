// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nonglobal

import (
	"context"
	"strconv"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

const ByKeyIndex = "by-key-index"

// lookupGlobalIDByLabels returns a global identity if found, otherwise it
// tries to get a temporary identity.
func (l *LocalOnlyCachingIDAllocator) lookupGlobalOrTempIDByLabels(lbls labels.Labels) *identity.Identity {
	lblArray := lbls.LabelArray()

	cid := l.getCIDByIndex(ByKeyIndex, lblArray)
	if cid != nil {
		id, err := strconv.Atoi(cid.Name)
		if err != nil {
			log.Errorf("LookupIdentity failed cannot convert ID %q", cid.Name)
			return nil
		}
		return identity.NewIdentityFromLabelArray(identity.NumericIdentity(id), lblArray)
	}

	if id, exists := l.tempIDAllocator.LookupByIDKey(&key.GlobalIdentity{LabelArray: lbls.LabelArray()}); exists {
		return id
	}

	return nil
}

func (l *LocalOnlyCachingIDAllocator) getCIDByIndex(indexName string, lblArray labels.LabelArray) *v2.CiliumIdentity {
	k := key.GlobalIdentity{LabelArray: lblArray}
	cidStore, _ := l.ciliumIdentities.Store(l.context)

	cidList, err := cidStore.ByIndex(indexName, k.GetKey())
	if err != nil {
		return nil
	}
	if len(cidList) < 1 {
		return nil
	}

	var selectedID *v2.CiliumIdentity
	var selectedVal int
	for _, cid := range cidList {
		if selectedID == nil {
			selectedVal, err = strconv.Atoi(cid.Name)
			if err == nil {
				selectedID = cid
			}
			continue
		}

		cidVal, err := strconv.Atoi(cid.Name)
		if err != nil {
			continue
		}

		if cidVal < selectedVal {
			selectedID = cid
			selectedVal = cidVal
		}
	}

	return selectedID
}

func (l *LocalOnlyCachingIDAllocator) getCIDByKey(cidName string) *v2.CiliumIdentity {
	cidStore, _ := l.ciliumIdentities.Store(l.context)

	cid, exists, err := cidStore.GetByKey(resource.Key{Name: cidName})
	if err != nil {
		log.Debugf("LookupIdentity failed to GetByKey (%v) from CIDStore: %v", cidName, err)
		return nil
	}
	if !exists {
		log.Debugf("LookupIdentity failed to GetByKey (%v) from CIDStore - doesn't exist", cidName)
		return nil
	}

	return cid
}

func (l *LocalOnlyCachingIDAllocator) ValidateEndpointIDForCIDEvent(eps []*endpoint.Endpoint) {
	for _, ep := range eps {
		if ep == nil {
			continue
		}

		if ep.IsHost() {
			continue
		}

		l.enqueueEndpointReconciliation(ep)
	}
}

// ReconcileSecIDForEndpoint assings a global or a temprary identity to an
// endpoint that doesn't have an assigned identity or have a temporary
// identity.
// All endpoints will be regenerated if a new temporary identity is created.
func (l *LocalOnlyCachingIDAllocator) ReconcileSecIDForEndpoint(ep *endpoint.Endpoint) error {
	if ep == nil {
		return nil
	}

	idCreated, err := l.updateSecurityIdentityForEndpoint(ep)
	if err != nil {
		return err
	}

	if idCreated {
		regenMetadata := &regeneration.ExternalRegenerationMetadata{
			Reason:            "security identity changed",
			RegenerationLevel: regeneration.RegenerateWithoutDatapath,
		}
		// Regenerate all endpoints because a new temporary identity is created.
		for _, ep := range l.endpointListerFunc() {
			ep.RegenerateIfAlive(regenMetadata)
		}
	}

	return err
}

// updateSecurityIdentityForEndpoint ensures that the endpoint has a correct
// security identity and returns if a new temporary identity is created.
func (l *LocalOnlyCachingIDAllocator) updateSecurityIdentityForEndpoint(ep *endpoint.Endpoint) (bool, error) {
	if ep == nil {
		return false, nil
	}

	lbls := ep.OpLabels.IdentityLabels()
	if !identity.RequiresGlobalIdentity(lbls) {
		return false, nil
	}

	idCreated := false
	selectedID := l.lookupGlobalOrTempIDByLabels(lbls)
	if selectedID == nil {
		var err error
		// Assign a temp identity when a global identity is not yet assigned.
		selectedID, err = l.tempIDAllocator.FindOrCreateTempID(lbls)
		if err != nil {
			return false, err
		}

		idCreated = true
	}

	if selectedID == nil {
		log.Warningf("Unable to find or allocate a global or a temporary security identity for endpoint %d", ep.ID)
		return false, nil
	}

	if ep.SecurityIdentity == nil || selectedID.ID != ep.SecurityIdentity.ID {
		err := ep.UpdateSecurityIdentity(selectedID, false)
		if err != nil {
			return idCreated, err
		}
	}

	return idCreated, nil
}

type cidEventTracker struct {
	cidCreatedMap map[string]bool
	mu            lock.RWMutex
}

func newCIDEventTracker() *cidEventTracker {
	return &cidEventTracker{
		cidCreatedMap: make(map[string]bool),
	}
}

func (c *cidEventTracker) add(cidName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cidCreatedMap[cidName] = true
}

func (c *cidEventTracker) remove(cidName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.cidCreatedMap, cidName)
}

func (c *cidEventTracker) isTracked(cidName string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, exists := c.cidCreatedMap[cidName]
	return exists
}

func (l *LocalOnlyCachingIDAllocator) processCiliumIdentityEvents(ctx context.Context) error {
	cidHandlerFunc := func(cid *v2.CiliumIdentity, typ kvstore.EventType) {
		eventsChan := l.events
		if eventsChan == nil {
			log.Warning("cilium identity update handler failed because events channel is not initialized")
			return
		}

		idNum, err := strconv.ParseUint(cid.Name, 10, 64)
		if err != nil {
			log.Warningf("cilium identity update handler failed: %v", err)
			return
		}
		id := idpool.ID(idNum)
		keyFunc := (&key.GlobalIdentity{}).PutKeyFromMap
		cidKey := keyFunc(cid.SecurityLabels)

		if l.endpointListerFunc != nil {
			eps := l.endpointListerFunc()
			l.ValidateEndpointIDForCIDEvent(eps)
		}

		if l.idObserver != nil {
			if typ == kvstore.EventTypeDelete {
				l.idObserver.getEvent(cid, allocator.AllocatorChangeDelete)
			} else {
				l.idObserver.getEvent(cid, allocator.AllocatorChangeUpsert)
			}
		}

		eventsChan <- allocator.AllocatorEvent{Typ: typ, ID: id, Key: cidKey}
	}

	for event := range l.ciliumIdentities.Events(ctx) {
		cid := event.Object

		switch event.Kind {
		case resource.Upsert:
			log.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Upsert Cilium Identity event")

			if l.cidTracker.isTracked(cid.Name) {
				cidHandlerFunc(cid, kvstore.EventTypeModify)
			} else {
				l.cidTracker.add(cid.Name)
				cidHandlerFunc(cid, kvstore.EventTypeCreate)
			}
		case resource.Delete:
			log.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Delete Cilium Identity event")

			l.cidTracker.remove(cid.Name)
			cidHandlerFunc(cid, kvstore.EventTypeDelete)
		}
		event.Done(nil)
	}
	return nil
}
