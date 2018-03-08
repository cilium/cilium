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

// IdentityCacheSnapshot is a snapshot of the identity cache
type IdentityCacheSnapshot struct {
	// Cache is a copy of the identity cache
	Cache IdentityCache

	// Revision is the revision of the cache used for the copy
	Revision uint64
}

// GetIdentityCache returns a snapshot of the cache containing all known
// identities
func GetIdentityCache() IdentityCacheSnapshot {
	snapshot := IdentityCacheSnapshot{
		Cache:    IdentityCache{},
		Revision: identityAllocator.GetCacheRevision(),
	}

	identityAllocator.ForeachCache(func(id allocator.ID, val allocator.AllocatorKey) {
		gi := val.(globalIdentity)
		snapshot.Cache[NumericIdentity(id)] = gi.LabelArray()
	})

	return snapshot
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
	for _, identity := range reservedIdentityCache {
		if reflect.DeepEqual(identity.Labels, lbls) {
			return identity
		}
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
		identity := NewIdentity(val, labels.Labels{key: labels.NewLabel(val.String(), "", labels.LabelSourceReserved)})
		reservedIdentityCache[val] = identity
	}
}
