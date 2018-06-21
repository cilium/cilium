// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package identity

import (
	"reflect"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/trigger"
)

var (
	mutex                 lock.RWMutex
	reservedIdentityCache = map[NumericIdentity]*Identity{}
)

// IdentityCache is a cache of identity to labels mapping
type IdentityCache map[NumericIdentity]labels.LabelArray

// GetIdentityCache returns a cache of all known identities
func GetIdentityCache() IdentityCache {
	cache := IdentityCache{}

	identityAllocator.ForeachCache(func(id allocator.ID, val allocator.AllocatorKey) {
		if val != nil {
			if gi, ok := val.(globalIdentity); ok {
				cache[NumericIdentity(id)] = gi.LabelArray()
			} else {
				log.Warning("Ignoring unknown identity type '%s': %+v",
					reflect.TypeOf(val), val)
			}
		}
	})

	return cache
}

// GetIdentities returns all known identities
func GetIdentities() []*models.Identity {
	identities := []*models.Identity{}

	identityAllocator.ForeachCache(func(id allocator.ID, val allocator.AllocatorKey) {
		if gi, ok := val.(globalIdentity); ok {
			identity := NewIdentity(NumericIdentity(id), gi.Labels)
			identities = append(identities, identity.GetModel())
		}

	})

	return identities
}

func identityWatcher(owner IdentityAllocatorOwner, events allocator.AllocatorEventChan) {
	// The event queue handler is kept as lightweight as possible, it uses
	// a non-blocking trigger to run a background routine which will call
	// TriggerPolicyUpdates() with an enforced minimum interval of one
	// second.
	policyTrigger := trigger.NewTrigger(trigger.Parameters{
		MinInterval: time.Second,
		TriggerFunc: func() {
			owner.TriggerPolicyUpdates(true)
		},
	})

	for {
		event := <-events

		switch event.Typ {
		case kvstore.EventTypeCreate, kvstore.EventTypeDelete:
			policyTrigger.Trigger()

		case kvstore.EventTypeModify:
			// Ignore modify events
		}
	}
}

// LookupIdentity looks up the identity by its labels but does not create it.
// This function will first search through the local cache and fall back to
// querying the kvstore.
func LookupIdentity(lbls labels.Labels) *Identity {
	if reservedIdentity := LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		return reservedIdentity
	}

	if identityAllocator == nil {
		return nil
	}

	id, err := identityAllocator.Get(globalIdentity{lbls})
	if err != nil {
		return nil
	}

	if id == allocator.NoID {
		return nil
	}

	return NewIdentity(NumericIdentity(id), lbls)
}

// LookupReservedIdentityByLabels looks up a reserved identity by its labels and
// returns it if found. Returns nil if not found.
func LookupReservedIdentityByLabels(lbls labels.Labels) *Identity {
	// If there is only one label with the "reserved" source and a well-known
	// key, return the well-known identity for that key.
	if len(lbls) != 1 {
		return nil
	}
	for _, lbl := range lbls {
		if lbl.Source != labels.LabelSourceReserved {
			return nil
		}
		if id := GetReservedID(lbl.Key); id != IdentityUnknown {
			return LookupReservedIdentity(id)
		}
	}
	return nil
}

// LookupReservedIdentity looks up a reserved identity by its labels and
// returns it if found. Returns nil if not found.
func LookupReservedIdentity(ni NumericIdentity) *Identity {
	mutex.RLock()
	defer mutex.RUnlock()
	return reservedIdentityCache[ni]
}

var unknownIdentity = NewIdentity(IdentityUnknown, labels.Labels{labels.IDNameUnknown: labels.NewLabel(labels.IDNameUnknown, "", labels.LabelSourceReserved)})

// LookupIdentityByID returns the identity by ID. This function will first
// search through the local cache and fall back to querying the kvstore.
func LookupIdentityByID(id NumericIdentity) *Identity {
	if id == IdentityUnknown {
		return unknownIdentity
	}

	if identity := LookupReservedIdentity(id); identity != nil {
		return identity
	}

	if identityAllocator == nil {
		return nil
	}

	allocatorKey, err := identityAllocator.GetByID(allocator.ID(id))
	if err != nil {
		return nil
	}

	if gi, ok := allocatorKey.(globalIdentity); ok {
		return NewIdentity(id, gi.Labels)
	}

	return nil
}

func init() {
	mutex.Lock()
	IterateReservedIdentities(func(lbl string, ni NumericIdentity) {
		identity := NewIdentity(ni, labels.Labels{lbl: labels.NewLabel(lbl, "", labels.LabelSourceReserved)})
		// Pre-calculate the SHA256 hash.
		identity.GetLabelsSHA256()
		reservedIdentityCache[ni] = identity
	})
	mutex.Unlock()
}
