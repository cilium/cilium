// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// CachedSelector represents an identity selector owned by the selector cache
type CachedSelector interface {
	// GetSelections returns the cached set of numeric identities
	// selected by the CachedSelector.  The retuned slice must NOT
	// be modified, as it is shared among multiple users.
	GetSelections() identity.NumericIdentitySlice

	// GetMetadataLabels returns metadata labels for additional context
	// surrounding the selector. These are typically the labels associated with
	// Cilium rules.
	GetMetadataLabels() labels.LabelArray

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

// fqdnSelector is implemented as an updatable bag-of-labels. Any identity that matches
// any of the labels in wantLabels is selected. Unlike the identitySelector, this selector
// is "mutable" in that the FQDN subsystem may update the set of matched labels arbitrarily.
type fqdnSelector struct {
	selectorManager
	selector   api.FQDNSelector
	wantLabels labels.LabelArray // MUST be sorted
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

// locks must be held for the dnsProxy and the SelectorCache
func (f *fqdnSelector) removeUser(user CachedSelectionUser, dnsProxy identityNotifier) (last bool) {
	delete(f.users, user)
	if len(f.users) == 0 {
		dnsProxy.UnregisterForIPUpdatesLocked(f.selector)
		return true
	}
	return false
}

// setSelectorIPs updates the set of desired labels associated with this selector.
// lock must be held
func (f *fqdnSelector) setSelectorIPs(ips []netip.Addr) {
	lbls := make(labels.LabelArray, 0, len(ips))
	for _, ip := range ips {
		l, err := labels.IPStringToLabel(ip.String())
		if err != nil {
			// not possible
			continue
		}
		lbls = append(lbls, l)
	}
	lbls.Sort()
	f.wantLabels = lbls
}

// matches returns true if the identity contains at least one label
// that is in wantLabels.
// This is reasonably efficient, as it relies on both arrays being sorted.
func (f *fqdnSelector) matches(identity scIdentity) bool {
	wantIdx := 0
	checkIdx := 0

	// Both arrays are sorted; walk through until we get a match
	for wantIdx < len(f.wantLabels) && checkIdx < len(identity.lbls) {
		want := f.wantLabels[wantIdx]
		check := identity.lbls[checkIdx]
		if want == check {
			return true
		}

		// Not equal, bump
		if check.Key < want.Key {
			checkIdx++
		} else {
			wantIdx++
		}
	}

	return false
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

type selectorManager struct {
	key              string
	selections       atomic.Pointer[identity.NumericIdentitySlice]
	users            map[CachedSelectionUser]struct{}
	cachedSelections map[identity.NumericIdentity]struct{}
	metadataLbls     labels.LabelArray
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
func (s *selectorManager) GetSelections() identity.NumericIdentitySlice {
	selections := s.selections.Load()
	if selections == nil {
		return emptySelection
	}
	return *selections
}

func (s *selectorManager) GetMetadataLabels() labels.LabelArray {
	return s.metadataLbls
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

// lock must be held
func (s *selectorManager) numUsers() int {
	return len(s.users)
}

// updateSelections updates the immutable slice representation of the
// cached selections after the cached selections have been changed.
//
// lock must be held
func (s *selectorManager) updateSelections() {
	selections := make(identity.NumericIdentitySlice, len(s.cachedSelections))
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

func (s *selectorManager) setSelections(selections *identity.NumericIdentitySlice) {
	if len(*selections) > 0 {
		s.selections.Store(selections)
	} else {
		s.selections.Store(&emptySelection)
	}
}
