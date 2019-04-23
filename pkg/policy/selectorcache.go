// Copyright 2019 Authors of Cilium
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

package policy

import (
	"sort"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
)

// CachedSelector represents an identity selector owned by the selector cache
type CachedSelector interface {
	// GetSelections returns the cached set of numeric identities
	// selected by the CachedSelector.  The retuned slice must NOT
	// be modified, as it is shared among multiple users.
	GetSelections() []identity.NumericIdentity

	// String returns the string representation of this selector.
	// Used as a map key.
	String() string
}

// CachedSelectionUser inserts selectors into the cache and gets update
// callbacks whenever the set of selected numeric identities change for
// the CachedSelectors pushed by it.
type CachedSelectionUser interface {
	// IdentitySelectionUpdated implementations MUST NOT call back
	// to selector cache while executing this function!
	IdentitySelectionUpdated(selector CachedSelector, selections, added, deleted []identity.NumericIdentity)
}

// identitySelector is the internal interface for all selectors in the
// selector cache.
//
// identitySelector represents the mapping of an EndpointSelector
// to a slice of identities. These mappings are updated via two
// different processes:
//
// 1. When policy rules are changed these are added and/or deleted
// depending on what selectors the rules contain. Cached selections of
// new identitySelectors are pre-populated from the set of currently
// known identities.
//
// 2. When reachacble identities appear or disappear, either via local
// allocation (CIDRs), or via the KV-store (remote endpoints). In this
// case all existing identitySelectors are walked through and their
// cached selections are updated as necessary.
//
// In both of the above cases the set of existing identitySelectors is
// write locked.
//
// To minimize the upkeep the identity selectors are shared accross
// all IdentityPolicies, so that only one copy exists for each
// identitySelector. Users of the SelectorCache take care of creating
// identitySelectors as needed by identity policies. The set of
// identitySelectors is read locked during an IdentityPolicy update so
// that the the policy is always updated using a coherent set of
// cached selections.
//
// identitySelector is used as a map key, so it must not be implemented by a
// map, slice, or a func, or a runtime panic will be triggered. In all
// cases below identitySelector is being implemented by structs.
type identitySelector interface {
	CachedSelector
	addUser(CachedSelectionUser) (added bool)
	removeUser(CachedSelectionUser) (last bool)
	notifyUsers(added, deleted []identity.NumericIdentity)
}

// SelectorCache caches identities, identity selectors, and the
// subsets of identities each selector selects.
type SelectorCache struct {
	mutex lock.RWMutex

	// idCache contains all known identities as informed by the
	// kv-store and the local identity facility via our
	// UpdateIdentities() function.
	idCache cache.IdentityCache

	// map key is the string representation of the selector being cached.
	selectors map[string]identitySelector
}

// newSelectorCache creates a new SelectorCache.
func newSelectorCache() *SelectorCache {
	return &SelectorCache{
		idCache:   cache.GetIdentityCache(),
		selectors: make(map[string]identitySelector),
	}
}

var (
	// selectorCache is the global selector cache. Additional ones
	// are only created for testing.
	selectorCache = newSelectorCache()
	// Empty slice of numeric identities used for all selectors that select nothing
	emptySelection []identity.NumericIdentity
)

type labelIdentitySelector struct {
	selector         api.EndpointSelector
	key              string
	users            map[CachedSelectionUser]struct{}
	selections       unsafe.Pointer // *[]identity.NumericIdentity
	cachedSelections map[identity.NumericIdentity]struct{}
}

//
// CachedSelector implementation (== Public API)
//
// No locking needed.
//

// GetSelections returns the set of numeric identities currently
// selected.  The cached selections can be concurrently updated. In
// that case GetSelections() will return either the old or new version
// of the selections. If the old version is returned, the user is
// guaranteed to receive a notification including the update.
func (l *labelIdentitySelector) GetSelections() []identity.NumericIdentity {
	return *(*[]identity.NumericIdentity)(atomic.LoadPointer(&l.selections))
}

// String returns the map key for this selector
func (l *labelIdentitySelector) String() string {
	return l.key
}

//
// identitySelector implemenentation (== internal API)
//

// lock must be held
func (l *labelIdentitySelector) addUser(user CachedSelectionUser) (added bool) {
	if _, exists := l.users[user]; exists {
		return false
	}
	l.users[user] = struct{}{}
	return true
}

// lock must be held
func (l *labelIdentitySelector) removeUser(user CachedSelectionUser) (last bool) {
	delete(l.users, user)
	return len(l.users) == 0
}

// lock must be held
func (l *labelIdentitySelector) notifyUsers(added, deleted []identity.NumericIdentity) {
	for user := range l.users {
		user.IdentitySelectionUpdated(l, l.GetSelections(), added, deleted)
	}
}

func (l *labelIdentitySelector) setSelections(selections *[]identity.NumericIdentity) {
	if len(*selections) > 0 {
		atomic.StorePointer(&l.selections, unsafe.Pointer(selections))
	} else {
		atomic.StorePointer(&l.selections, unsafe.Pointer(&emptySelection))
	}
}

// updateSelections updates the immutable slice representation of the
// cached selections after the cached selections have been changed.
//
// lock must be held
func (l *labelIdentitySelector) updateSelections() {
	selections := make([]identity.NumericIdentity, len(l.cachedSelections))
	i := 0
	for nid := range l.cachedSelections {
		selections[i] = nid
		i++
	}
	// Sort the numeric identities so that the map iteration order
	// does not matter. This makes testing easier, but may help
	// identifying changes easier also otherwise.
	sort.Slice(selections, func(i, j int) bool {
		return selections[i] < selections[j]
	})
	l.setSelections(&selections)
}

type fqdnSelector struct {
	labelIdentitySelector
	// fqdnSelections map[string]identity.NumericIdentity // identity.String(): "cidr:1.1.1.1" -> identity of 1.1.1.1
}

// AddIdentitySelector adds the given api.EndpointSelector in to the
// selector cache. If an identical EndpointSelector has already been
// cached, the corresponding CachedSelector is returned, otherwise one
// is created and added to the cache.
func (sc *SelectorCache) AddIdentitySelector(user CachedSelectionUser, selector api.EndpointSelector) (cachedSelector CachedSelector, added bool) {
	// The key returned here may be different for equivalent
	// labelselectors, if the selector's requirements are stored
	// in different orders. When this happens we'll be tracking
	// essentially two copies of the same selector.
	key := selector.LabelSelector.String()
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	idSel, exists := sc.selectors[key]
	if exists {
		return idSel, idSel.addUser(user)
	}

	// Selectors are never modified once a rule is placed in the policy repository,
	// so no need to copy.

	// TODO: FQDNSelector

	newIDSel := &labelIdentitySelector{
		key:              key,
		users:            make(map[CachedSelectionUser]struct{}),
		selector:         selector,
		cachedSelections: make(map[identity.NumericIdentity]struct{}),
	}

	// Add the initial user
	newIDSel.users[user] = struct{}{}

	// Find all matching identities from the identity cache.
	for numericID, lbls := range sc.idCache {
		if selector.Matches(lbls) {
			newIDSel.cachedSelections[numericID] = struct{}{}
		}
	}
	// Create the immutable slice representation of the selected
	// numeric identities
	newIDSel.updateSelections()

	// Note: No notifications are sent for the existing
	// identities. Caller must use GetSelections() to get the
	// current selections after adding a selector. This way the
	// behavior is the same between the two cases here (selector
	// is already cached, or is a new one).

	sc.selectors[key] = newIDSel
	return newIDSel, true
}

// RemoveIdentitySelector removes CachedSelector for the user.
func (sc *SelectorCache) RemoveIdentitySelector(user CachedSelectionUser, selector CachedSelector) {
	key := selector.String()
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	idSel, exists := sc.selectors[key]
	if exists {
		if idSel.removeUser(user) {
			delete(sc.selectors, key)
		}
	}
}

// UpdateIdentities propagates identity updates to selectors
func (sc *SelectorCache) UpdateIdentities(added, deleted cache.IdentityCache) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	// Update idCache so that newly added selectors get
	// prepopulated with all matching numeric identities.
	for numericID := range deleted {
		if _, exists := sc.idCache[numericID]; exists {
			delete(sc.idCache, numericID)
		} else {
			log.WithFields(logrus.Fields{logfields.Identity: numericID}).Warning("UpdateIdentities: Deleting a non-existing identity")
		}
	}
	for numericID, lbls := range added {
		if _, exists := sc.idCache[numericID]; exists {
			log.WithFields(logrus.Fields{logfields.Identity: numericID}).Warning("UpdateIdentities: Adding an existing identity")
		}
		sc.idCache[numericID] = lbls
	}

	// Iterate through all locally used identity selectors and
	// update the cached numeric identities as required.
	for _, sel := range sc.selectors {
		var adds, dels []identity.NumericIdentity
		switch idSel := sel.(type) {
		case *labelIdentitySelector:
			for numericID := range deleted {
				if _, exists := idSel.cachedSelections[numericID]; exists {
					dels = append(dels, numericID)
					delete(idSel.cachedSelections, numericID)
				}
			}
			for numericID, lbls := range added {
				if _, exists := idSel.cachedSelections[numericID]; !exists {
					if idSel.selector.Matches(lbls) {
						adds = append(adds, numericID)
						idSel.cachedSelections[numericID] = struct{}{}
					}
				}
			}
			if len(dels)+len(adds) > 0 {
				idSel.updateSelections()
				idSel.notifyUsers(adds, dels)
			}
		case *fqdnSelector:
			// TODO
		}
	}
}

// Export global functions to interface with the global selector cache

// AddIdentitySelector adds the given api.EndpointSelector in to the
// selector cache. If an identical EndpointSelector has already been
// cached, the corresponding CachedSelector is returned, otherwise one
// is created and added to the cache.
func AddIdentitySelector(user CachedSelectionUser, selector api.EndpointSelector) (cachedSelector CachedSelector, added bool) {
	return selectorCache.AddIdentitySelector(user, selector)
}

// RemoveIdentitySelector removes CachedSelector for the user.
func RemoveIdentitySelector(user CachedSelectionUser, selector CachedSelector) {
	selectorCache.RemoveIdentitySelector(user, selector)
}

// UpdateIdentities propagates identity updates to selectors
func UpdateIdentities(added, deleted cache.IdentityCache) {
	selectorCache.UpdateIdentities(added, deleted)
}
