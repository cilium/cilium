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

package cache

import (
	"reflect"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/allocator"
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

// GetIdentityCache returns a cache of all known identities
func GetIdentityCache() IdentityCache {
	cache := IdentityCache{}

	IdentityAllocator.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
		if val != nil {
			if gi, ok := val.(globalIdentity); ok {
				cache[identity.NumericIdentity(id)] = gi.LabelArray()
			} else {
				log.Warningf("Ignoring unknown identity type '%s': %+v",
					reflect.TypeOf(val), val)
			}
		}
	})

	for key, identity := range identity.ReservedIdentityCache {
		cache[key] = identity.Labels.LabelArray()
	}

	for _, identity := range localIdentities.GetIdentities() {
		cache[identity.ID] = identity.Labels.LabelArray()
	}

	return cache
}

// GetIdentities returns all known identities
func GetIdentities() IdentitiesModel {
	identities := IdentitiesModel{}

	IdentityAllocator.ForeachCache(func(id idpool.ID, val allocator.AllocatorKey) {
		if gi, ok := val.(globalIdentity); ok {
			identity := identity.NewIdentity(identity.NumericIdentity(id), gi.Labels)
			identities = append(identities, identity.GetModel())
		}

	})
	// append user reserved identities
	for _, v := range identity.ReservedIdentityCache {
		identities = append(identities, v.GetModel())
	}

	for _, v := range localIdentities.GetIdentities() {
		identities = append(identities, v.GetModel())
	}

	return identities
}

type identityWatcher struct {
	stopChan chan bool
}

// watch starts the identity watcher
func (w *identityWatcher) watch(owner IdentityAllocatorOwner, events allocator.AllocatorEventChan) {
	w.stopChan = make(chan bool)

	go func() {
		for {
			select {
			case event := <-events:

				switch event.Typ {
				case kvstore.EventTypeCreate, kvstore.EventTypeDelete:
					owner.TriggerPolicyUpdates(true, "one or more identities created or deleted")

				case kvstore.EventTypeModify:
					// Ignore modify events
				}

			case <-w.stopChan:
				return
			}
		}
	}()
}

// stop stops the identity watcher
func (w *identityWatcher) stop() {
	close(w.stopChan)
}

// LookupIdentity looks up the identity by its labels but does not create it.
// This function will first search through the local cache and fall back to
// querying the kvstore.
func LookupIdentity(lbls labels.Labels) *identity.Identity {
	if reservedIdentity := LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		return reservedIdentity
	}

	if identity := localIdentities.lookup(lbls); identity != nil {
		return identity
	}

	if IdentityAllocator == nil {
		return nil
	}

	id, err := IdentityAllocator.Get(globalIdentity{lbls})
	if err != nil {
		return nil
	}

	if id == idpool.NoID {
		return nil
	}

	return identity.NewIdentity(identity.NumericIdentity(id), lbls)
}

// LookupReservedIdentityByLabels looks up a reserved identity by its labels and
// returns it if found. Returns nil if not found.
func LookupReservedIdentityByLabels(lbls labels.Labels) *identity.Identity {
	if identity := identity.WellKnown.LookupByLabels(lbls); identity != nil {
		return identity
	}

	for _, lbl := range lbls {
		switch {
		// If the set of labels contain a fixed identity then and exists in
		// the map of reserved IDs then return the identity of that reserved ID.
		case lbl.Key == labels.LabelKeyFixedIdentity:
			id := identity.GetReservedID(lbl.Value)
			if id != identity.IdentityUnknown && identity.IsUserReservedIdentity(id) {
				return identity.LookupReservedIdentity(id)
			}
			// If a fixed identity was not found then we return nil to avoid
			// falling to a reserved identity.
			return nil
		// If it doesn't contain a fixed-identity then make sure the set of
		// labels only contains a single label and that label is of the reserved
		// type. This is to prevent users from adding cilium-reserved labels
		// into the workloads.
		case lbl.Source == labels.LabelSourceReserved:
			if len(lbls) != 1 {
				return nil
			}
			id := identity.GetReservedID(lbl.Key)
			if id != identity.IdentityUnknown && !identity.IsUserReservedIdentity(id) {
				return identity.LookupReservedIdentity(id)
			}
		}
	}
	return nil
}

var unknownIdentity = identity.NewIdentity(identity.IdentityUnknown, labels.Labels{labels.IDNameUnknown: labels.NewLabel(labels.IDNameUnknown, "", labels.LabelSourceReserved)})

// LookupIdentityByID returns the identity by ID. This function will first
// search through the local cache and fall back to querying the kvstore.
func LookupIdentityByID(id identity.NumericIdentity) *identity.Identity {
	if id == identity.IdentityUnknown {
		return unknownIdentity
	}

	if identity := identity.LookupReservedIdentity(id); identity != nil {
		return identity
	}

	if IdentityAllocator == nil {
		return nil
	}

	if identity := localIdentities.lookupByID(id); identity != nil {
		return identity
	}

	allocatorKey, err := IdentityAllocator.GetByID(idpool.ID(id))
	if err != nil {
		return nil
	}

	if gi, ok := allocatorKey.(globalIdentity); ok {
		return identity.NewIdentity(id, gi.Labels)
	}

	return nil
}

// AddUserDefinedNumericIdentitySet adds all key-value pairs from the given map
// to the map of user defined numeric identities and reserved identities.
// The key-value pairs should map a numeric identity to a valid label.
// Is not safe for concurrent use.
func AddUserDefinedNumericIdentitySet(m map[string]string) error {
	// Validate first
	for k := range m {
		ni, err := identity.ParseNumericIdentity(k)
		if err != nil {
			return err
		}
		if !identity.IsUserReservedIdentity(ni) {
			return identity.ErrNotUserIdentity
		}
	}
	for k, lbl := range m {
		ni, _ := identity.ParseNumericIdentity(k)
		identity.AddUserDefinedNumericIdentity(ni, lbl)
		identity.AddReservedIdentity(ni, lbl)
	}
	return nil
}
