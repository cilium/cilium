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
	"strings"
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

	// Selects return 'true' if the CachedSelector selects the given
	// numeric identity.
	Selects(nid identity.NumericIdentity) bool

	// IsWildcard returns true if the endpoint selector selects
	// all endpoints.
	IsWildcard() bool

	// String returns the string representation of this selector.
	// Used as a map key.
	String() string

	// XXXMatches returns true if the CachedSelector matches the
	// given labels. This is slow and should only be used for
	// functions for which performance does not matter (such as
	// policy tracing)
	XXXMatches(labels labels.LabelArray) bool
}

// CachedSelectorSlice is a slice of CachedSelectors that can be sorted.
type CachedSelectorSlice []CachedSelector

func (s CachedSelectorSlice) Len() int      { return len(s) }
func (s CachedSelectorSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s CachedSelectorSlice) Less(i, j int) bool {
	return strings.Compare(s[i].String(), s[j].String()) < 0
}

// SelectsAllEndpoints returns whether the CachedSelectorSlice selects all
// endpoints, which is true if the wildcard endpoint selector is present in the
// slice.
func (s CachedSelectorSlice) SelectsAllEndpoints() bool {
	for _, selector := range s {
		if selector.IsWildcard() {
			return true
		}
	}
	return false
}

// Insert in a sorted order? Returns true if inserted, false if cs was already in
func (s *CachedSelectorSlice) Insert(cs CachedSelector) bool {
	for _, selector := range *s {
		if selector == cs {
			return false
		}
	}
	*s = append(*s, cs)
	return true
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

// IdentityCache is a cache of Identities keyed by the numeric identity
type IdentityCache map[identity.NumericIdentity]Identity

func newIdentity(nid identity.NumericIdentity, lbls labels.LabelArray) Identity {
	return Identity{
		NID:       nid,
		lbls:      lbls,
		namespace: lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel),
	}
}

func getIdentityCache(ids cache.IdentityCache) IdentityCache {
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
	idCache         IdentityCache
	idCacheRevision uint64

	// map key is the string representation of the selector being cached.
	selectors map[string]identitySelector
}

// NewSelectorCache creates a new SelectorCache with the given identities.
func NewSelectorCache(ids cache.IdentityCache) *SelectorCache {
	return &SelectorCache{
		idCache:   getIdentityCache(ids),
		selectors: make(map[string]identitySelector),
	}
}

var (
	// Empty slice of numeric identities used for all selectors that select nothing
	emptySelection []identity.NumericIdentity
	// wildcardSelectorKey is used to compare if a key is for a wildcard
	wildcardSelectorKey = api.WildcardEndpointSelector.LabelSelector.String()
)

type labelIdentitySelector struct {
	key              string
	selector         api.EndpointSelector
	namespaces       []string // allowed namespaces, or nil
	users            map[CachedSelectionUser]struct{}
	selections       unsafe.Pointer // *[]identity.NumericIdentity
	cachedSelections map[identity.NumericIdentity]struct{}
}

// Equal is used by checker.Equals, and only considers the identity of the selector,
// ignoring the internal state!
func (a *labelIdentitySelector) Equal(b *labelIdentitySelector) bool {
	return a.key == b.key
}

func (l *labelIdentitySelector) matchesNamespace(ns string) bool {
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

func (l *labelIdentitySelector) matches(identity Identity) (ret bool) {
	return l.matchesNamespace(identity.namespace) && l.selector.Matches(identity.lbls)
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
func (l *labelIdentitySelector) GetSelections() (ret []identity.NumericIdentity) {
	return *(*[]identity.NumericIdentity)(atomic.LoadPointer(&l.selections))
}

// Selects return 'true' if the CachedSelector selects the given
// numeric identity.
func (l *labelIdentitySelector) Selects(nid identity.NumericIdentity) bool {
	if l.IsWildcard() {
		return true
	}
	nids := l.GetSelections()
	idx := sort.Search(len(nids), func(i int) bool { return nids[i] >= nid })
	return idx < len(nids) && nids[idx] == nid
}

// IsWildcard returns true if the endpoint selector selects all
// endpoints.
func (l *labelIdentitySelector) IsWildcard() bool {
	return l.key == wildcardSelectorKey
}

// String returns the map key for this selector
func (l *labelIdentitySelector) String() string {
	return l.key
}

// XXXMatches returns true if the CachedSelector matches given labels.
func (l *labelIdentitySelector) XXXMatches(labels labels.LabelArray) bool {
	return l.selector.Matches(labels)
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

// FindCachedIdentitySelector finds the given api.EndpointSelector in the
// selector cache, returning nil if one can not be found.
func (sc *SelectorCache) FindCachedIdentitySelector(selector api.EndpointSelector) CachedSelector {
	key := selector.LabelSelector.String()
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	idSel := sc.selectors[key]
	return idSel
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

	// TODO: FQDNSelector
	newIDSel := &labelIdentitySelector{
		key:              key,
		users:            make(map[CachedSelectionUser]struct{}),
		selector:         selector,
		cachedSelections: make(map[identity.NumericIdentity]struct{}),
	}
	// check is selector has a namespace match or requirement
	if namespaces, ok := selector.GetMatch(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel); ok {
		newIDSel.namespaces = namespaces
	}

	// Add the initial user
	newIDSel.users[user] = struct{}{}

	// Find all matching identities from the identity cache.
	for numericID, identity := range sc.idCache {
		if newIDSel.matches(identity) {
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
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	key := selector.String()
	idSel, exists := sc.selectors[key]
	if exists {
		if idSel.removeUser(user) {
			delete(sc.selectors, key)
		}
	}
}

// RemoveIdentitySelector removes CachedSelector for the user.
func (sc *SelectorCache) RemoveIdentitySelectors(user CachedSelectionUser, selectors CachedSelectorSlice) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	for _, selector := range selectors {
		key := selector.String()
		idSel, exists := sc.selectors[key]
		if exists {
			if idSel.removeUser(user) {
				delete(sc.selectors, key)
			}
		}
	}
}

// ChangeUser changes the CachedSelectionUser that gets updates on the
// updates on the cached selector.
func (sc *SelectorCache) ChangeUser(from, to CachedSelectionUser, selector CachedSelector) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	key := selector.String()
	idSel, exists := sc.selectors[key]
	if exists {
		idSel.removeUser(from)
		idSel.addUser(to)
	}
}

// UpdateIdentities propagates identity updates to selectors
func (sc *SelectorCache) UpdateIdentities(added, deleted cache.IdentityCache) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	// Update idCache so that newly added selectors get
	// prepopulated with all matching numeric identities.
	for numericID := range deleted {
		if old, exists := sc.idCache[numericID]; exists {
			log.WithFields(logrus.Fields{logfields.Identity: numericID, logfields.Labels: old.lbls}).Debug("UpdateIdentities: Deleting identity")
			delete(sc.idCache, numericID)
		} else {
			log.WithFields(logrus.Fields{logfields.Identity: numericID}).Warning("UpdateIdentities: Skipping Delete of a non-existing identity")
			delete(deleted, numericID)
		}
	}
	for numericID, lbls := range added {
		if old, exists := sc.idCache[numericID]; exists {
			// Skip if no change
			if lbls.String() == old.lbls.String() {
				log.WithFields(logrus.Fields{logfields.Identity: numericID}).Debug("UpdateIdentities: Skipping add an existing identical identity")
				delete(added, numericID)
				continue
			}
			log.WithFields(logrus.Fields{logfields.Identity: numericID, logfields.Labels: old.lbls, logfields.Labels + "(new)": lbls}).Warning("UpdateIdentities: Updating an existing identity")
		} else {
			log.WithFields(logrus.Fields{logfields.Identity: numericID, logfields.Labels: lbls}).Debug("UpdateIdentities: Adding a new identity")
		}
		sc.idCache[numericID] = newIdentity(numericID, lbls)
	}

	if len(deleted)+len(added) > 0 {
		sc.idCacheRevision++

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
						if idSel.matches(sc.idCache[numericID]) {
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
}

// XXXGetIDCacheRevision can be used to figure our if the selections
// may have changed. Should not be used when identity updates are
// properly propagated to the policy realization.
func (sc *SelectorCache) XXXGetIDCacheRevision() uint64 {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	return sc.idCacheRevision
}

func (sc *SelectorCache) XXXGetAllIDs() ([]identity.NumericIdentity, uint64) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	ids := make([]identity.NumericIdentity, 0, len(sc.idCache))
	for nid := range sc.idCache {
		ids = append(ids, nid)
	}
	return ids, sc.idCacheRevision
}
