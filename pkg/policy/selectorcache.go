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
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
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

// Identity is the information we need about a an identity that rules can select
type Identity struct {
	NID       identity.NumericIdentity
	lbls      labels.LabelArray
	namespace string // value of the namespace label, or nil
}

// IdentityCache is a cache of identity to labels mapping
type IdentityCache map[identity.NumericIdentity]Identity

func newIdentity(nid identity.NumericIdentity, lbls labels.LabelArray) Identity {
	return Identity{
		NID:       nid,
		lbls:      lbls,
		namespace: lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel),
	}
}

func getIdentityCache() IdentityCache {
	ids := cache.GetIdentityCache()
	idCache := make(map[identity.NumericIdentity]Identity, len(ids))
	for nid, lbls := range ids {
		idCache[nid] = newIdentity(nid, lbls)
	}
	return idCache
}

// SelectorCache caches identities, identity selectors, and the
// subsets of identities each selector selects.
type SelectorCache struct {
	mutex lock.RWMutex

	// idCache contains all known identities as informed by the
	// kv-store and the local identity facility via our
	// UpdateIdentities() function.
	idCache IdentityCache

	// map key is the string representation of the selector being cached.
	selectors map[string]identitySelector
}

// newSelectorCache creates a new SelectorCache.
func newSelectorCache() *SelectorCache {
	return &SelectorCache{
		idCache:   getIdentityCache(),
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

type selectorManager struct {
	key              string
	selections       unsafe.Pointer // *[]identity.NumericIdentity
	users            map[CachedSelectionUser]struct{}
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
func (s *selectorManager) GetSelections() []identity.NumericIdentity {
	return *(*[]identity.NumericIdentity)(atomic.LoadPointer(&s.selections))
}

// String returns the map key for this selector
func (s *selectorManager) String() string {
	return s.key
}

//
// identitySelector implementation (== internal API)
//

// lock must be held
func (s *selectorManager) addUser(user CachedSelectionUser) (added bool) {
	if _, exists := s.users[user]; exists {
		return false
	}
	s.users[user] = struct{}{}
	return true
}

// lock must be held
func (s *selectorManager) removeUser(user CachedSelectionUser) (last bool) {
	delete(s.users, user)
	return len(s.users) == 0
}

// lock must be held
func (s *selectorManager) notifyUsers(added, deleted []identity.NumericIdentity) {
	for user := range s.users {
		user.IdentitySelectionUpdated(s, s.GetSelections(), added, deleted)
	}
}

// updateSelections updates the immutable slice representation of the
// cached selections after the cached selections have been changed.
//
// lock must be held
func (s *selectorManager) updateSelections() {
	selections := make([]identity.NumericIdentity, len(s.cachedSelections))
	i := 0
	for nid := range s.cachedSelections {
		selections[i] = nid
		i++
	}
	// Sort the numeric identities so that the map iteration order
	// does not matter. This makes testing easier, but may help
	// identifying changes easier also otherwise.
	sort.Slice(selections, func(i, j int) bool {
		return selections[i] < selections[j]
	})
	s.setSelections(&selections)
}

func (s *selectorManager) setSelections(selections *[]identity.NumericIdentity) {
	if len(*selections) > 0 {
		atomic.StorePointer(&s.selections, unsafe.Pointer(selections))
	} else {
		atomic.StorePointer(&s.selections, unsafe.Pointer(&emptySelection))
	}
}

type fqdnSelector struct {
	selectorManager
	selector api.FQDNSelector
}

type labelIdentitySelector struct {
	selectorManager
	selector   api.EndpointSelector
	namespaces []string // allowed namespaces, or nil
}

func (l *labelIdentitySelector) MatchesNamespace(ns string) bool {
	if len(l.namespaces) > 0 {
		if ns != "" {
			for i := range l.namespaces {
				if ns == l.namespaces[i] {
					return true
				}
			}
		}
		// namespace required, but no match
		return false
	}
	// no namespace required, match
	return true
}

func (l *labelIdentitySelector) Matches(identity Identity) bool {
	return l.MatchesNamespace(identity.namespace) && l.selector.Matches(identity.lbls)
}

//
// CachedSelector implementation (== Public API)
//
// No locking needed.
//

// UpdateFQDNSelector updates the mapping of fqdnKey (the FQDNSelector from a
// policy rule as a string) to to the provided list of identities. If the contents
// of the cachedSelections differ from those in the identities slice, all
// users are notified.
func (sc *SelectorCache) UpdateFQDNSelector(fqdnSelec api.FQDNSelector, identities []identity.NumericIdentity) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	sc.updateFQDNSelector(fqdnSelec, identities)
}

func (sc *SelectorCache) updateFQDNSelector(fqdnSelec api.FQDNSelector, identities []identity.NumericIdentity) {
	fqdnKey := fqdnSelec.String()

	var fqdnSel *fqdnSelector

	selector, exists := sc.selectors[fqdnKey]
	if !exists || selector == nil {
		fqdnSel = &fqdnSelector{
			selectorManager: selectorManager{
				key:              fqdnKey,
				users:            make(map[CachedSelectionUser]struct{}),
				cachedSelections: make(map[identity.NumericIdentity]struct{}),
			},
			selector: fqdnSelec,
		}
		sc.selectors[fqdnKey] = fqdnSel
	} else {
		fqdnSel = selector.(*fqdnSelector)
	}

	// Convert identity slice to map for comparison with cachedSelections map.
	idsAsMap := make(map[identity.NumericIdentity]struct{}, len(identities))
	for _, v := range identities {
		idsAsMap[v] = struct{}{}
	}

	var added, deleted []identity.NumericIdentity

	/* TODO - the FQDN side should expose what was changed (IPs added, and removed)
	*  not all IPs corresponding to an FQDN - this will make this diff much
	*  cheaper, but will require more plumbing on the FQDN side. for now, this
	*  is good enough.
	*
	*  Case 1: identities did correspond to this FQDN, but no longer do. Reset
	*  the map
	 */
	if len(identities) == 0 && len(fqdnSel.cachedSelections) != 0 {
		// Need to update deleted to be all in cached selections
		for k := range fqdnSel.cachedSelections {
			deleted = append(deleted, k)
		}
		fqdnSel.cachedSelections = make(map[identity.NumericIdentity]struct{})
	} else if len(identities) != 0 && len(fqdnSel.cachedSelections) == 0 {
		// Case 2: identities now correspond to this FQDN, but didn't before.
		// We don't have to do any comparison of the maps to see what changed
		// and what didn't.
		added = identities
		fqdnSel.cachedSelections = idsAsMap
	} else {
		// Case 3: Something changed resulting in some identities being added
		// and / or removed. Figure out what these sets are (new identities
		// added, or identities deleted).
		for k := range fqdnSel.cachedSelections {
			// If identity in cached selectors isn't in identities which were
			// passed in, mark it as being deleted, and remove it from
			// cachedSelectors.
			if _, ok := idsAsMap[k]; !ok {
				deleted = append(deleted, k)
				delete(fqdnSel.cachedSelections, k)
			}
		}

		// Now iterate over the provided identities to update the
		// cachedSelections accordingly, and so we can see which identities
		// were actually added (removing those which were added already).
		for _, allowedIdentity := range identities {
			if _, ok := fqdnSel.cachedSelections[allowedIdentity]; !ok {
				// This identity was actually added and not already in the map.
				added = append(added, allowedIdentity)
				fqdnSel.cachedSelections[allowedIdentity] = struct{}{}
			}
		}
	}

	// Note: we don't need to go through the identity cache to see what
	// identities match" this selector. This has to be updated via whatever is
	// getting the CIDR identities which correspond to this FQDNSelector. This
	// is the primary difference here between FQDNSelector and IdentitySelector.
	fqdnSel.updateSelections()
	fqdnSel.notifyUsers(added, deleted)
}

// AddFQDNSelector adds the given api.FQDNSelector in to the selector cache. If
// an identical EndpointSelector has already been cached, the corresponding
// CachedSelector is returned, otherwise one is created and added to the cache.
func (sc *SelectorCache) AddFQDNSelector(user CachedSelectionUser, fqdnSelec api.FQDNSelector) (cachedSelector CachedSelector, added bool) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	key := fqdnSelec.String()
	fqdnSel, exists := sc.selectors[key]
	if exists {
		return fqdnSel, fqdnSel.addUser(user)
	}

	newFQDNSel := &fqdnSelector{
		selectorManager: selectorManager{
			key:              key,
			users:            make(map[CachedSelectionUser]struct{}),
			cachedSelections: make(map[identity.NumericIdentity]struct{}),
		},
		selector: fqdnSelec,
	}

	// Add the initial user
	newFQDNSel.users[user] = struct{}{}
	newFQDNSel.updateSelections()

	// Do not go through the identity cache to see what identities "match" this
	// selector. This has to be updated via whatever is getting the CIDR identities
	// which correspond go this FQDNSelector.
	// Alternatively , we could go through the CIDR identities in the cache
	// provided they have some 'field' which shows which FQDNs they correspond
	// to? This would require we keep some set in the Identity for the CIDR.
	// Is this feasible?

	// Note: No notifications are sent for the existing
	// identities. Caller must use GetSelections() to get the
	// current selections after adding a selector. This way the
	// behavior is the same between the two cases here (selector
	// is already cached, or is a new one).
	sc.selectors[key] = newFQDNSel

	return newFQDNSel, true
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
	// so no need to deep copy.

	newIDSel := &labelIdentitySelector{
		selectorManager: selectorManager{
			key:              key,
			users:            make(map[CachedSelectionUser]struct{}),
			cachedSelections: make(map[identity.NumericIdentity]struct{}),
		},
		selector: selector,
	}
	// check is selector has a namespace match or requirement
	if namespaces, ok := selector.GetMatch(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel); ok {
		newIDSel.namespaces = namespaces
	}

	// Add the initial user
	newIDSel.users[user] = struct{}{}

	// Find all matching identities from the identity cache.
	for numericID, identity := range sc.idCache {
		if newIDSel.Matches(identity) {
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

// RemoveSelector removes CachedSelector for the user.
func (sc *SelectorCache) RemoveSelector(user CachedSelectionUser, selector CachedSelector) {
	key := selector.String()
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	sel, exists := sc.selectors[key]
	if exists {
		if sel.removeUser(user) {
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
		sc.idCache[numericID] = newIdentity(numericID, lbls)
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
			for numericID := range added {
				if _, exists := idSel.cachedSelections[numericID]; !exists {
					if idSel.Matches(sc.idCache[numericID]) {
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
			// This is a no-op right now. We don't encode in the identities
			// which FQDNs they correspond to.
		}
	}
}

// RemoveIdentitiesFQDNSelectors removes all identities from being mapped to the
// set of FQDNSelectors.
func (sc *SelectorCache) RemoveIdentitiesFQDNSelectors(fqdnSels []api.FQDNSelector) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	noIdentities := []identity.NumericIdentity{}

	for i := range fqdnSels {
		sc.updateFQDNSelector(fqdnSels[i], noIdentities)
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
	selectorCache.RemoveSelector(user, selector)
}

// UpdateFQDNSelector updates the mapping of fqdnKey (the FQDNSelector from a
// policy rule as a string) to to the provided list of identities. If the
// contents of the cachedSelections differ from those in the identities slice,
// all users are notified.
func UpdateFQDNSelector(fqdnSelector api.FQDNSelector, identities []identity.NumericIdentity) {
	selectorCache.UpdateFQDNSelector(fqdnSelector, identities)
}

// RemoveIdentitiesFQDNSelectors removes all identities from being mapped to the
// set of FQDNSelectors in the global SelectorCache.
func RemoveIdentitiesFQDNSelectors(fqdnSels []api.FQDNSelector) {
	selectorCache.RemoveIdentitiesFQDNSelectors(fqdnSels)
}

// AddFQDNSelector adds the given api.EndpointSelector to the selector cache. If
// an identical FQDNSelector has already been cached, the corresponding
// CachedSelector is returned, otherwise one is created and added to the cache.
func AddFQDNSelector(user CachedSelectionUser, fqdnSelector api.FQDNSelector) (cachedSelector CachedSelector, added bool) {
	return selectorCache.AddFQDNSelector(user, fqdnSelector)
}

// UpdateIdentities propagates identity updates to selectors in the selector
// cache.
func UpdateIdentities(added, deleted cache.IdentityCache) {
	selectorCache.UpdateIdentities(added, deleted)
}
