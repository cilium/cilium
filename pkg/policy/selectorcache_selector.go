// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"slices"
	"sort"
	"sync"

	"github.com/hashicorp/go-hclog"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/types"
)

type CachedSelector = types.CachedSelector
type CachedSelectorSlice = types.CachedSelectorSlice
type CachedSelectionUser = types.CachedSelectionUser
type Selector = types.Selector
type Selectors = types.Selectors
type SelectorSnapshot = types.SelectorSnapshot
type SelectorRevision = types.SelectorRevision

// identitySelector is the internal type for all selectors in the
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
// 2. When reachable identities appear or disappear, either via local
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
// that the policy is always updated using a coherent set of
// cached selections.
//
// identitySelector is used as a map key, so it must not be implemented by a
// map, slice, or a func, or a runtime panic will be triggered. In all
// cases below identitySelector is being implemented by structs.
//
// identitySelector is used in the policy engine as a map key,
// so it must always be given to the user as a pointer to the actual type.
// (The public methods only expose the CachedSelector interface.)
type identitySelector struct {
	selectorCache    *SelectorCache
	source           Selector
	key              string
	id               types.SelectorId
	users            map[CachedSelectionUser]struct{}
	cachedSelections map[identity.NumericIdentity]struct{}
	metadataLbls     stringLabels
}

var lastSelectorId types.SelectorId

func newIdentitySelector(sc *SelectorCache, key string, source Selector, lbls stringLabels) *identitySelector {
	lastSelectorId++
	return &identitySelector{
		selectorCache:    sc,
		key:              key,
		id:               lastSelectorId,
		users:            make(map[CachedSelectionUser]struct{}),
		cachedSelections: make(map[identity.NumericIdentity]struct{}),
		source:           source,
		metadataLbls:     lbls,
	}
}

func (i *identitySelector) MaySelectPeers() bool {
	for user := range i.users {
		if user.IsPeerSelector() {
			return true
		}
	}
	return false
}

// identitySelector implements CachedSelector
var _ CachedSelector = (*identitySelector)(nil)

// lock must be held
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (i *identitySelector) notifyUsers(sc *SelectorCache, added, deleted []identity.NumericIdentity, wg *sync.WaitGroup) {
	for user := range i.users {
		// pass 'f' to the user as '*fqdnSelector'
		sc.queueUserNotification(user, i, added, deleted, wg)
	}
}

// Equal is used by checker.Equals, and only considers the identity of the selector,
// ignoring the internal state!
func (i *identitySelector) Equal(b *identitySelector) bool {
	return i.key == b.key
}

//
// CachedSelector implementation (== Public API)
//
// No locking needed and selector cache must not be locked when making these calls!
// (SelectorCache.GetReadTxn() takes a read lock)
//

// GetSelectionsAt returns the set of numeric identities currently
// selected.  The cached selections can be concurrently updated. In
// that case GetSelectionsAt() will return either the old or new version
// of the selections. If the old version is returned, the user is
// guaranteed to receive a notification including the update.
func (i *identitySelector) GetSelections() identity.NumericIdentitySlice {
	return i.GetSelectionsAt(i.selectorCache.GetSelectorSnapshot())
}

// GetSelectionsAt returns the set of numeric identities currently
// selected.  The cached selections can be concurrently updated. In
// that case GetSelectionsAt() will return either the old or new version
// of the selections. If the old version is returned, the user is
// guaranteed to receive a notification including the update.
func (i *identitySelector) GetSelectionsAt(selectors SelectorSnapshot) identity.NumericIdentitySlice {
	if !selectors.IsValid() || i.id == 0 {
		msg := "GetSelectionsAt: Invalid selector snapshot finds nothing"
		if i.id == 0 {
			msg = "GetSelectionsAt: Uninitialized identitySelector"
		}
		i.selectorCache.logger.Error(
			msg,
			logfields.Version, selectors,
			logfields.Stacktrace, hclog.Stacktrace(),
		)
		return identity.NumericIdentitySlice{}
	}
	return selectors.Get(i.id)
}

func (i *identitySelector) GetMetadataLabels() labels.LabelArray {
	return labels.LabelArrayFromString(string(i.metadataLbls.Value()))
}

// Selects return 'true' if the CachedSelector selects the given
// numeric identity.
func (i *identitySelector) Selects(nid identity.NumericIdentity) bool {
	if i.IsWildcard() {
		return true
	}
	nids := i.GetSelections()
	idx := sort.Search(len(nids), func(i int) bool { return nids[i] >= nid })
	return idx < len(nids) && nids[idx] == nid
}

// IsWildcard returns true if the endpoint selector selects all
// endpoints.
func (i *identitySelector) IsWildcard() bool {
	return i.key == wildcardSelectorKey
}

// IsNone returns true if the endpoint selector never selects anything.
func (i *identitySelector) IsNone() bool {
	return i.key == noneSelectorKey
}

// String returns the map key for this selector
func (i *identitySelector) String() string {
	return i.key
}

//
// identitySelector implementation (== internal API)
//

// lock must be held
func (i *identitySelector) addUser(user CachedSelectionUser, idNotifier identityNotifier) (added bool) {
	if _, exists := i.users[user]; exists {
		return false
	}
	i.users[user] = struct{}{}

	// register FQDN on first user
	if len(i.users) == 1 && idNotifier != nil {
		// Check if need to register with the dns proxy
		if fqdn, ok := i.source.GetFQDNSelector(); ok {
			// Make the FQDN subsystem aware of this selector
			idNotifier.RegisterFQDNSelector(*fqdn)
		}
	}

	return true
}

// locks must be held for the dnsProxy and the SelectorCache (if the selector is a FQDN selector)
func (i *identitySelector) removeUser(user CachedSelectionUser, idNotifier identityNotifier) (last bool) {
	if _, exists := i.users[user]; exists {
		delete(i.users, user)

		if len(i.users) == 0 {
			if idNotifier != nil {
				if fqdn, ok := i.source.GetFQDNSelector(); ok {
					idNotifier.UnregisterFQDNSelector(*fqdn)
				}
			}
			return true
		}
	}
	return false
}

// lock must be held
func (i *identitySelector) numUsers() int {
	return len(i.users)
}

// updateSelections updates the immutable slice representation of the
// cached selections after the cached selections have been changed.
//
// lock must be held
func (i *identitySelector) updateSelections() {
	if len(i.cachedSelections) == 0 {
		i.selectorCache.writeableSelections.Delete(i.id)
		return
	}

	ids := make(identity.NumericIdentitySlice, 0, len(i.cachedSelections))

	for nid := range i.cachedSelections {
		ids = append(ids, nid)
	}

	// Sort the numeric identities so that the map iteration order
	// does not matter. This makes testing easier, but may help
	// identifying changes easier also otherwise.
	slices.Sort(ids)

	i.selectorCache.writeableSelections.Set(i.id, ids)
}
