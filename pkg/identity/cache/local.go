// Copyright 2018 Authors of Cilium
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
	"fmt"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
)

type localIdentityCache struct {
	mutex               lock.RWMutex
	identitiesByID      map[identity.NumericIdentity]*identity.Identity
	identitiesByLabels  map[string]*identity.Identity
	nextNumericIdentity identity.NumericIdentity
	minID               identity.NumericIdentity
	maxID               identity.NumericIdentity
	events              allocator.AllocatorEventChan
}

func newLocalIdentityCache(minID, maxID identity.NumericIdentity, events allocator.AllocatorEventChan) *localIdentityCache {
	return &localIdentityCache{
		identitiesByID:      map[identity.NumericIdentity]*identity.Identity{},
		identitiesByLabels:  map[string]*identity.Identity{},
		nextNumericIdentity: minID,
		minID:               minID,
		maxID:               maxID,
		events:              events,
	}
}

func (l *localIdentityCache) bumpNextNumericIdentity() {
	if l.nextNumericIdentity == l.maxID {
		l.nextNumericIdentity = l.minID
	} else {
		l.nextNumericIdentity++
	}
}

// getNextFreeNumericIdentity returns the next available numeric identity or an error
// The l.mutex must be held
func (l *localIdentityCache) getNextFreeNumericIdentity() (identity.NumericIdentity, error) {
	firstID := l.nextNumericIdentity
	for {
		idCandidate := l.nextNumericIdentity | identity.LocalIdentityFlag
		if _, ok := l.identitiesByID[idCandidate]; !ok {
			l.bumpNextNumericIdentity()
			return idCandidate, nil
		}

		l.bumpNextNumericIdentity()
		if l.nextNumericIdentity == firstID {
			return 0, fmt.Errorf("out of local identity space")
		}
	}
}

// lookupOrCreate searches for the existence of a local identity with the given
// labels. If it exists, the reference count is incremented and the identity is
// returned. If it does not exist, a new identity is created with a unique
// numeric identity. All identities returned by lookupOrCreate() must be
// released again via localIdentityCache.release().
func (l *localIdentityCache) lookupOrCreate(lbls labels.Labels) (*identity.Identity, bool, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	stringRepresentation := string(lbls.SortedList())
	if id, ok := l.identitiesByLabels[stringRepresentation]; ok {
		id.ReferenceCount++
		return id, false, nil
	}

	numericIdentity, err := l.getNextFreeNumericIdentity()
	if err != nil {
		return nil, false, err
	}

	id := &identity.Identity{
		ID:             numericIdentity,
		Labels:         lbls,
		LabelArray:     lbls.LabelArrayWithHash(),
		ReferenceCount: 1,
	}

	l.identitiesByLabels[stringRepresentation] = id
	l.identitiesByID[numericIdentity] = id

	if l.events != nil {
		l.events <- allocator.AllocatorEvent{
			Typ: kvstore.EventTypeCreate,
		}
	}

	return id, true, nil
}

// release releases a local identity from the cache. true is returned when the
// last use of the identity has been released and the identity has been
// forgotten.
func (l *localIdentityCache) release(id *identity.Identity) bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	stringRepresentation := string(id.Labels.SortedList())
	if id, ok := l.identitiesByLabels[stringRepresentation]; ok {
		switch {
		case id.ReferenceCount > 1:
			id.ReferenceCount--
			return false

		case id.ReferenceCount == 1:
			// Release is only attempted once, when the reference count is
			// hitting the last use
			stringRepresentation := string(id.Labels.SortedList())
			delete(l.identitiesByLabels, stringRepresentation)
			delete(l.identitiesByID, id.ID)

			if l.events != nil {
				l.events <- allocator.AllocatorEvent{
					Typ: kvstore.EventTypeDelete,
				}
			}

			return true
		}
	}

	return false
}

// lookup searches for a local identity matching the given labels and returns
// it. If found, the reference count is NOT incremented and thus release must
// NOT be called.
func (l *localIdentityCache) lookup(lbls labels.Labels) *identity.Identity {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	stringRepresentation := string(lbls.SortedList())
	if id, ok := l.identitiesByLabels[stringRepresentation]; ok {
		return id
	}

	return nil
}

// lookupByID searches for a local identity matching the given ID and returns
// it. If found, the reference count is NOT incremented and thus release must
// NOT be called.
func (l *localIdentityCache) lookupByID(id identity.NumericIdentity) *identity.Identity {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	if id, ok := l.identitiesByID[id]; ok {
		return id
	}

	return nil
}

// GetIdentities returns all local identities
func (l *localIdentityCache) GetIdentities() map[identity.NumericIdentity]*identity.Identity {
	cache := map[identity.NumericIdentity]*identity.Identity{}

	l.mutex.RLock()
	defer l.mutex.RUnlock()

	for key, id := range l.identitiesByID {
		cache[key] = id
	}

	return cache
}
