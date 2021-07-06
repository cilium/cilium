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
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/cilium/api/v1/models"
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

	// IsNone returns true if the selector never selects anything
	IsNone() bool

	// String returns the string representation of this selector.
	// Used as a map key.
	String() string
}

// CachedSelectorSlice is a slice of CachedSelectors that can be sorted.
type CachedSelectorSlice []CachedSelector

// MarshalJSON returns the CachedSelectors as JSON formatted buffer
func (s CachedSelectorSlice) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString("[")
	for i, selector := range s {
		buf, err := json.Marshal(selector.String())
		if err != nil {
			return nil, err
		}

		buffer.Write(buf)
		if i < len(s)-1 {
			buffer.WriteString(",")
		}
	}
	buffer.WriteString("]")
	return buffer.Bytes(), nil
}

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

// CachedSelectionUser inserts selectors into the cache and gets update
// callbacks whenever the set of selected numeric identities change for
// the CachedSelectors pushed by it.
type CachedSelectionUser interface {
	// IdentitySelectionUpdated implementations MUST NOT call back
	// to the name manager or the selector cache while executing this function!
	//
	// The caller is responsible for making sure the same identity is not
	// present in both 'added' and 'deleted'.
	IdentitySelectionUpdated(selector CachedSelector, added, deleted []identity.NumericIdentity)
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
// To minimize the upkeep the identity selectors are shared across
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
//
// Because the selector exposed to the user is used as a map key, it must always
// be passed to the user as a pointer to the actual implementation type.
// For this reason 'notifyUsers' must be implemented by each type separately.
type identitySelector interface {
	CachedSelector
	addUser(CachedSelectionUser) (added bool)

	// Called with NameManager and SelectorCache locks held
	removeUser(CachedSelectionUser, identityNotifier) (last bool)

	// This may be called while the NameManager lock is held. wg.Wait()
	// returns after user notifications have been completed, which may require
	// taking Endpoint and SelectorCache locks, so these locks must not be
	// held when calling wg.Wait().
	notifyUsers(sc *SelectorCache, added, deleted []identity.NumericIdentity, wg *sync.WaitGroup)

	numUsers() int
}

// scIdentity is the information we need about a an identity that rules can select
type scIdentity struct {
	NID       identity.NumericIdentity
	lbls      labels.LabelArray
	namespace string // value of the namespace label, or ""
}

// scIdentityCache is a cache of Identities keyed by the numeric identity
type scIdentityCache map[identity.NumericIdentity]scIdentity

func newIdentity(nid identity.NumericIdentity, lbls labels.LabelArray) scIdentity {
	return scIdentity{
		NID:       nid,
		lbls:      lbls,
		namespace: lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel),
	}
}

func getIdentityCache(ids cache.IdentityCache) scIdentityCache {
	idCache := make(map[identity.NumericIdentity]scIdentity, len(ids))
	for nid, lbls := range ids {
		idCache[nid] = newIdentity(nid, lbls)
	}
	return idCache
}

// userNotification stores the information needed to call
// IdentitySelectionUpdated callbacks to notify users of selector's
// identity changes. These are queued to be able to call the callbacks
// in FIFO order while not holding any locks.
type userNotification struct {
	user     CachedSelectionUser
	selector CachedSelector
	added    []identity.NumericIdentity
	deleted  []identity.NumericIdentity
	wg       *sync.WaitGroup
}

// SelectorCache caches identities, identity selectors, and the
// subsets of identities each selector selects.
type SelectorCache struct {
	mutex lock.RWMutex

	// idCache contains all known identities as informed by the
	// kv-store and the local identity facility via our
	// UpdateIdentities() function.
	idCache scIdentityCache

	// map key is the string representation of the selector being cached.
	selectors map[string]identitySelector

	localIdentityNotifier identityNotifier

	// userCond is a condition variable for receiving signals
	// about addition of new elements in userNotes
	userCond *sync.Cond
	// userMutex protects userNotes and is linked to userCond
	userMutex lock.Mutex
	// userNotes holds a FIFO list of user notifications to be made
	userNotes []userNotification
}

// GetModel returns the API model of the SelectorCache.
func (sc *SelectorCache) GetModel() models.SelectorCache {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	selCacheMdl := make(models.SelectorCache, 0, len(sc.selectors))

	for selector, idSel := range sc.selectors {
		selections := idSel.GetSelections()
		ids := make([]int64, 0, len(selections))
		for i := range selections {
			ids = append(ids, int64(selections[i]))
		}
		selMdl := &models.SelectorIdentityMapping{
			Selector:   selector,
			Identities: ids,
			Users:      int64(idSel.numUsers()),
		}
		selCacheMdl = append(selCacheMdl, selMdl)
	}

	return selCacheMdl
}

func (sc *SelectorCache) handleUserNotifications() {
	for {
		sc.userMutex.Lock()
		for len(sc.userNotes) == 0 {
			sc.userCond.Wait()
		}
		// get the current batch of notifications and release the lock so that SelectorCache
		// can't block on userMutex while we call IdentitySelectionUpdated callbacks below.
		notifications := sc.userNotes
		sc.userNotes = nil
		sc.userMutex.Unlock()

		for _, n := range notifications {
			n.user.IdentitySelectionUpdated(n.selector, n.added, n.deleted)
			n.wg.Done()
		}
	}
}

func (sc *SelectorCache) queueUserNotification(user CachedSelectionUser, selector CachedSelector, added, deleted []identity.NumericIdentity, wg *sync.WaitGroup) {
	wg.Add(1)
	sc.userMutex.Lock()
	sc.userNotes = append(sc.userNotes, userNotification{
		user:     user,
		selector: selector,
		added:    added,
		deleted:  deleted,
		wg:       wg,
	})
	sc.userMutex.Unlock()
	sc.userCond.Signal()
}

// NewSelectorCache creates a new SelectorCache with the given identities.
func NewSelectorCache(ids cache.IdentityCache) *SelectorCache {
	sc := &SelectorCache{
		idCache:   getIdentityCache(ids),
		selectors: make(map[string]identitySelector),
	}
	sc.userCond = sync.NewCond(&sc.userMutex)
	go sc.handleUserNotifications()

	return sc
}

// SetLocalIdentityNotifier injects the provided identityNotifier into the
// SelectorCache. Currently, this is used to inject the FQDN subsystem into
// the SelectorCache so the SelectorCache can notify the FQDN subsystem when
// it should be aware of a given FQDNSelector for which CIDR identities need
// to be provided upon DNS lookups which corespond to said FQDNSelector.
func (sc *SelectorCache) SetLocalIdentityNotifier(pop identityNotifier) {
	sc.localIdentityNotifier = pop
}

var (
	// Empty slice of numeric identities used for all selectors that select nothing
	emptySelection []identity.NumericIdentity
	// wildcardSelectorKey is used to compare if a key is for a wildcard
	wildcardSelectorKey = api.WildcardEndpointSelector.LabelSelector.String()
	// noneSelectorKey is used to compare if a key is for "reserved:none"
	noneSelectorKey = api.EndpointSelectorNone.LabelSelector.String()
)

type selectorManager struct {
	key              string
	selections       unsafe.Pointer // *[]identity.NumericIdentity
	users            map[CachedSelectionUser]struct{}
	cachedSelections map[identity.NumericIdentity]struct{}
}

// Equal is used by checker.Equals, and only considers the identity of the selector,
// ignoring the internal state!
func (s *selectorManager) Equal(b *selectorManager) bool {
	return s.key == b.key
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

// Selects return 'true' if the CachedSelector selects the given
// numeric identity.
func (s *selectorManager) Selects(nid identity.NumericIdentity) bool {
	if s.IsWildcard() {
		return true
	}
	nids := s.GetSelections()
	idx := sort.Search(len(nids), func(i int) bool { return nids[i] >= nid })
	return idx < len(nids) && nids[idx] == nid
}

// IsWildcard returns true if the endpoint selector selects all
// endpoints.
func (s *selectorManager) IsWildcard() bool {
	return s.key == wildcardSelectorKey
}

// IsNone returns true if the endpoint selector never selects anything.
func (s *selectorManager) IsNone() bool {
	return s.key == noneSelectorKey
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
func (s *selectorManager) removeUser(user CachedSelectionUser, dnsProxy identityNotifier) (last bool) {
	delete(s.users, user)
	return len(s.users) == 0
}

// locks must be held for the dnsProxy and the SelectorCache
func (f *fqdnSelector) removeUser(user CachedSelectionUser, dnsProxy identityNotifier) (last bool) {
	delete(f.users, user)
	if len(f.users) == 0 {
		dnsProxy.UnregisterForIdentityUpdatesLocked(f.selector)
		return true
	}
	return false
}

// lock must be held
func (s *selectorManager) numUsers() int {
	return len(s.users)
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

// lock must be held
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (f *fqdnSelector) notifyUsers(sc *SelectorCache, added, deleted []identity.NumericIdentity, wg *sync.WaitGroup) {
	for user := range f.users {
		// pass 'f' to the user as '*fqdnSelector'
		sc.queueUserNotification(user, f, added, deleted, wg)
	}
}

// identityNotifier provides a means for other subsystems to be made aware of a
// given FQDNSelector (currently pkg/fqdn) so that said subsystems can notify
// the SelectorCache about new IPs (via CIDR Identities) which correspond to
// said FQDNSelector. This is necessary since there is nothing intrinsic to a
// CIDR Identity that says that it corresponds to a given FQDNSelector; this
// relationship is contained only via DNS responses, which are handled
// externally.
type identityNotifier interface {
	// Lock must be held during any calls to RegisterForIdentityUpdatesLocked or
	// UnregisterForIdentityUpdatesLocked.
	Lock()

	// Unlock must be called after calls to RegisterForIdentityUpdatesLocked or
	// UnregisterForIdentityUpdatesLocked are done.
	Unlock()

	// RegisterForIdentityUpdatesLocked exposes this FQDNSelector so that identities
	// for IPs contained in a DNS response that matches said selector can be
	// propagated back to the SelectorCache via `UpdateFQDNSelector`. When called,
	// implementers (currently `pkg/fqdn/RuleGen`) should iterate over all DNS
	// names that they are aware of, and see if they match the FQDNSelector.
	// All IPs which correspond to the DNS names which match this Selector will
	// be returned as CIDR identities, as other DNS Names which have already
	// been resolved may match this FQDNSelector.
	// Once this function is called, the SelectorCache will be updated any time
	// new IPs are resolved for DNS names which match this FQDNSelector.
	// This function is only called when the SelectorCache has been made aware
	// of this FQDNSelector for the first time, since we only need to get the
	// set of CIDR identities which match this FQDNSelector already from the
	// identityNotifier on the first pass; any subsequent updates will eventually
	// call `UpdateFQDNSelector`.
	RegisterForIdentityUpdatesLocked(selector api.FQDNSelector) (identities []identity.NumericIdentity)

	// UnregisterForIdentityUpdatesLocked removes this FQDNSelector from the set of
	// FQDNSelectors which are being tracked by the identityNotifier. The result
	// of this is that no more updates for IPs which correspond to said selector
	// are propagated back to the SelectorCache via `UpdateFQDNSelector`.
	// This occurs when there are no more users of a given FQDNSelector for the
	// SelectorCache.
	UnregisterForIdentityUpdatesLocked(selector api.FQDNSelector)
}

type labelIdentitySelector struct {
	selectorManager
	selector   api.EndpointSelector
	namespaces []string // allowed namespaces, or ""
}

// lock must be held
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (l *labelIdentitySelector) notifyUsers(sc *SelectorCache, added, deleted []identity.NumericIdentity, wg *sync.WaitGroup) {
	for user := range l.users {
		// pass 'l' to the user as '*labelIdentitySelector'
		sc.queueUserNotification(user, l, added, deleted, wg)
	}
}

// xxxMatches returns true if the CachedSelector matches given labels.
// This is slow, but only used for policy tracing, so it's OK.
func (l *labelIdentitySelector) xxxMatches(labels labels.LabelArray) bool {
	return l.selector.Matches(labels)
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

func (l *labelIdentitySelector) matches(identity scIdentity) bool {
	return l.matchesNamespace(identity.namespace) && l.selector.Matches(identity.lbls)
}

//
// CachedSelector implementation (== Public API)
//
// No locking needed.
//

// UpdateFQDNSelector updates the mapping of fqdnKey (the FQDNSelector from a
// policy rule as a string) to to the provided list of identities. If the contents
// of the cachedSelections differ from those in the identities slice, all users
// are notified asynchronously. Caller should Wait() on the returned
// sync.WaitGroup before triggering any policy updates. Policy updates may need
// Endpoint locks, so this Wait() can deadlock if the caller is holding any
// endpoint locks.
func (sc *SelectorCache) UpdateFQDNSelector(fqdnSelec api.FQDNSelector, identities []identity.NumericIdentity, wg *sync.WaitGroup) {
	sc.mutex.Lock()
	sc.updateFQDNSelector(fqdnSelec, identities, wg)
	sc.mutex.Unlock()
}

func (sc *SelectorCache) updateFQDNSelector(fqdnSelec api.FQDNSelector, identities []identity.NumericIdentity, wg *sync.WaitGroup) {
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

	// Note that 'added' and 'deleted' are guaranteed to be
	// disjoint, as one of them is left as nil, or an identity
	// being in 'identities' is a precondition for an
	// identity to be appended to 'added', while the inverse is
	// true for 'deleted'.
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
	fqdnSel.notifyUsers(sc, added, deleted, wg) // disjoint sets, see the comment above
}

// AddFQDNSelector adds the given api.FQDNSelector in to the selector cache. If
// an identical EndpointSelector has already been cached, the corresponding
// CachedSelector is returned, otherwise one is created and added to the cache.
func (sc *SelectorCache) AddFQDNSelector(user CachedSelectionUser, fqdnSelec api.FQDNSelector) (cachedSelector CachedSelector, added bool) {
	key := fqdnSelec.String()

	// Lock NameManager before the SelectorCache
	sc.localIdentityNotifier.Lock()
	defer sc.localIdentityNotifier.Unlock()

	// If the selector already exists, use it.
	sc.mutex.Lock()
	fqdnSel, exists := sc.selectors[key]
	if exists {
		added := fqdnSel.addUser(user)
		sc.mutex.Unlock()
		return fqdnSel, added
	}
	sc.mutex.Unlock()

	// Create the new selector. Pulling the identities it selects could
	// cause allocation of new CIDR identities, so we do this while not
	// holding the 'sc.mutex'.
	newFQDNSel := &fqdnSelector{
		selectorManager: selectorManager{
			key:              key,
			users:            make(map[CachedSelectionUser]struct{}),
			cachedSelections: make(map[identity.NumericIdentity]struct{}),
		},
		selector: fqdnSelec,
	}

	// Make the FQDN subsystem aware of this selector and fetch identities
	// that the FQDN subsystem is aware of.
	//
	// If the same 'fqdnSelec' is registered twice here from different
	// goroutines, we do *NOT* need to unregister the second one because
	// 'fqdnSelec' is just a struct passed by value. The call below doesn't
	// retain any references/pointers.
	//
	// If this is called twice, one of the results will arbitrarily contain
	// a real slice of ids, while the other will receive nil. We must fold
	// them together below.
	ids := sc.localIdentityNotifier.RegisterForIdentityUpdatesLocked(newFQDNSel.selector)

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

	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	// Check whether the selectorCache was updated while 'newFQDNSel' was
	// being registered without the 'sc.mutex'. If so, use it. Otherwise
	// we can use the one we just created/configured above.
	if sel, exists := sc.selectors[key]; exists {
		newFQDNSel = sel.(*fqdnSelector)
	} else {
		sc.selectors[key] = newFQDNSel
	}

	// Add the ids from the slice above to the FQDN selector in the cache.
	// This could plausibly happen twice, once with an empty 'ids' slice
	// and once with the real 'ids' slice. Either way, they are added to
	// the selector that is stored in 'sc.selectors[]'
	for _, id := range ids {
		newFQDNSel.cachedSelections[id] = struct{}{}
	}
	newFQDNSel.updateSelections()

	return newFQDNSel, newFQDNSel.addUser(user)
}

// FindCachedIdentitySelector finds the given api.EndpointSelector in the
// selector cache, returning nil if one can not be found.
func (sc *SelectorCache) FindCachedIdentitySelector(selector api.EndpointSelector) CachedSelector {
	key := selector.CachedString()
	sc.mutex.Lock()
	idSel := sc.selectors[key]
	sc.mutex.Unlock()
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
	key := selector.CachedString()
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

// lock must be held
func (sc *SelectorCache) removeSelectorLocked(selector CachedSelector, user CachedSelectionUser) {
	key := selector.String()
	sel, exists := sc.selectors[key]
	if exists {
		if sel.removeUser(user, sc.localIdentityNotifier) {
			delete(sc.selectors, key)
		}
	}
}

// RemoveSelector removes CachedSelector for the user.
func (sc *SelectorCache) RemoveSelector(selector CachedSelector, user CachedSelectionUser) {
	sc.localIdentityNotifier.Lock()
	sc.mutex.Lock()
	sc.removeSelectorLocked(selector, user)
	sc.mutex.Unlock()
	sc.localIdentityNotifier.Unlock()
}

// RemoveSelectors removes CachedSelectorSlice for the user.
func (sc *SelectorCache) RemoveSelectors(selectors CachedSelectorSlice, user CachedSelectionUser) {
	sc.localIdentityNotifier.Lock()
	sc.mutex.Lock()
	for _, selector := range selectors {
		sc.removeSelectorLocked(selector, user)
	}
	sc.mutex.Unlock()
	sc.localIdentityNotifier.Unlock()
}

// ChangeUser changes the CachedSelectionUser that gets updates on the
// updates on the cached selector.
func (sc *SelectorCache) ChangeUser(selector CachedSelector, from, to CachedSelectionUser) {
	key := selector.String()
	sc.mutex.Lock()
	idSel, exists := sc.selectors[key]
	if exists {
		// Add before remove so that the count does not dip to zero in between,
		// as this causes FQDN unregistration (if applicable).
		idSel.addUser(to)
		// ignoring the return value as we have just added a user above
		idSel.removeUser(from, sc.localIdentityNotifier)
	}
	sc.mutex.Unlock()
}

// UpdateIdentities propagates identity updates to selectors
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
//
// Caller should Wait() on the returned sync.WaitGroup before triggering any
// policy updates. Policy updates may need Endpoint locks, so this Wait() can
// deadlock if the caller is holding any endpoint locks.
func (sc *SelectorCache) UpdateIdentities(added, deleted cache.IdentityCache, wg *sync.WaitGroup) {
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
			// Skip if no change. Not skipping if label
			// order is different, but identity labels are
			// sorted for the kv-store, so there should
			// not be too many false negatives.
			if lbls.Equals(old.lbls) {
				log.WithFields(logrus.Fields{logfields.Identity: numericID}).Debug("UpdateIdentities: Skipping add of an existing identical identity")
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
					idSel.notifyUsers(sc, adds, dels, wg)
				}
			case *fqdnSelector:
				// This is a no-op right now. We don't encode in the identities
				// which FQDNs they correspond to.
			}
		}
	}
}

// RemoveIdentitiesFQDNSelectors removes all identities from being mapped to the
// set of FQDNSelectors.
func (sc *SelectorCache) RemoveIdentitiesFQDNSelectors(fqdnSels []api.FQDNSelector, wg *sync.WaitGroup) {
	sc.mutex.Lock()
	noIdentities := []identity.NumericIdentity{}

	for i := range fqdnSels {
		sc.updateFQDNSelector(fqdnSels[i], noIdentities, wg)
	}
	sc.mutex.Unlock()
}
