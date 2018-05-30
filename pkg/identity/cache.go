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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/labels"
)

var (
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

func identityWatcher(owner IdentityAllocatorOwner) {
	for {
		event := <-identityAllocator.Events

		switch event.Typ {
		case kvstore.EventTypeCreate, kvstore.EventTypeDelete:
			owner.TriggerPolicyUpdates(true)

		case kvstore.EventTypeModify:
			// Ignore modify events
		}
	}
}

// LookupIdentity looks up the identity by its labels but does not create it.
// This function will first search through the local cache and fall back to
// querying the kvstore.
func LookupIdentity(lbls labels.Labels) *Identity {
	if reservedIdentity := LookupReservedIdentity(lbls); reservedIdentity != nil {
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

// LookupReservedIdentity looks up a reserved identity by its labels and
// returns it if found. Returns nil if not found.
func LookupReservedIdentity(lbls labels.Labels) *Identity {
	// If there is only one label with the "reserved" source and a well-known
	// key, return the well-known identity for that key.
	if len(lbls) != 1 {
		return nil
	}
	for _, lbl := range lbls {
		if lbl.Source != labels.LabelSourceReserved {
			return nil
		}
		if id, ok := ReservedIdentities[lbl.Key]; ok {
			return reservedIdentityCache[id]
		}
	}
	return nil
}

// LookupIdentityByID returns the identity by ID. This function will first
// search through the local cache and fall back to querying the kvstore.
func LookupIdentityByID(id NumericIdentity) *Identity {
	if identity, ok := reservedIdentityCache[id]; ok {
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
	for key, val := range ReservedIdentities {
		identity := NewIdentity(val, labels.Labels{key: labels.NewLabel(key, "", labels.LabelSourceReserved)})
		// Pre-calculate the SHA256 hash.
		identity.GetLabelsSHA256()
		reservedIdentityCache[val] = identity
	}
}
