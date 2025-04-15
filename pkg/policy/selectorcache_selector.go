// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"log/slog"
	"slices"
	"sort"
	"sync"

	"github.com/hashicorp/go-hclog"

	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

type CachedSelector types.CachedSelector
type CachedSelectorSlice types.CachedSelectorSlice
type CachedSelectionUser types.CachedSelectionUser

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
	logger           *slog.Logger
	source           selectorSource
	key              string
	selections       versioned.Value[identity.NumericIdentitySlice]
	users            map[CachedSelectionUser]struct{}
	cachedSelections map[identity.NumericIdentity]struct{}
	metadataLbls     stringLabels
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
var _ types.CachedSelector = (*identitySelector)(nil)

type selectorSource interface {
	matches(scIdentity) bool

	remove(identityNotifier)

	metricsClass() string
}

// fqdnSelector implements the selectorSource for a FQDNSelector. A fqdnSelector
// matches an identity if the identity has a `fqdn:` label matching the FQDN
// selector string.
// In addition, the remove implementation calls back into the DNS name manager
// to unregister the FQDN selector.
type fqdnSelector struct {
	selector api.FQDNSelector
}

func (f *fqdnSelector) remove(dnsProxy identityNotifier) {
	dnsProxy.UnregisterFQDNSelector(f.selector)
}

// matches returns true if the identity contains at least one label
// that matches the FQDNSelector's IdentityLabel string
func (f *fqdnSelector) matches(identity scIdentity) bool {
	return identity.lbls.Intersects(labels.LabelArray{f.selector.IdentityLabel()})
}

func (f *fqdnSelector) metricsClass() string {
	return LabelValueSCFQDN
}

type labelIdentitySelector struct {
	selector   api.EndpointSelector
	namespaces []string // allowed namespaces, or ""
}

// xxxMatches returns true if the CachedSelector matches given labels.
// This is slow, but only used for policy tracing, so it's OK.
func (l *labelIdentitySelector) xxxMatches(labels labels.LabelArray) bool {
	return l.selector.Matches(labels)
}

func (l *labelIdentitySelector) matchesNamespace(ns string) bool {
	if len(l.namespaces) > 0 {
		if ns != "" {
			if slices.Contains(l.namespaces, ns) {
				return true
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

func (l *labelIdentitySelector) remove(_ identityNotifier) {
	// only useful for fqdn selectors
}

func (l *labelIdentitySelector) metricsClass() string {
	if l.selector.DeepEqual(&api.EntitySelectorMapping[api.EntityCluster][0]) {
		return LabelValueSCCluster
	}
	for _, entity := range api.EntitySelectorMapping[api.EntityWorld] {
		if l.selector.DeepEqual(&entity) {
			return LabelValueSCWorld
		}
	}

	return LabelValueSCOther
}

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
// No locking needed.
//

// GetSelections returns the set of numeric identities currently
// selected.  The cached selections can be concurrently updated. In
// that case GetSelections() will return either the old or new version
// of the selections. If the old version is returned, the user is
// guaranteed to receive a notification including the update.
func (i *identitySelector) GetSelections(version *versioned.VersionHandle) identity.NumericIdentitySlice {
	if !version.IsValid() {
		i.logger.Error(
			"GetSelections: Invalid VersionHandle finds nothing",
			logfields.Version, version,
			logfields.Stacktrace, hclog.Stacktrace(),
		)
		return identity.NumericIdentitySlice{}
	}
	return i.selections.At(version)
}

func (i *identitySelector) GetMetadataLabels() labels.LabelArray {
	return labels.LabelArrayFromString(string(i.metadataLbls.Value()))
}

// Selects return 'true' if the CachedSelector selects the given
// numeric identity.
func (i *identitySelector) Selects(version *versioned.VersionHandle, nid identity.NumericIdentity) bool {
	if i.IsWildcard() {
		return true
	}
	nids := i.GetSelections(version)
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
func (i *identitySelector) addUser(user CachedSelectionUser) (added bool) {
	if _, exists := i.users[user]; exists {
		return false
	}
	i.users[user] = struct{}{}
	return true
}

// locks must be held for the dnsProxy and the SelectorCache (if the selector is a FQDN selector)
func (i *identitySelector) removeUser(user CachedSelectionUser) (last bool) {
	delete(i.users, user)
	return len(i.users) == 0
}

// lock must be held
func (i *identitySelector) numUsers() int {
	return len(i.users)
}

// updateSelections updates the immutable slice representation of the
// cached selections after the cached selections have been changed.
//
// lock must be held
func (i *identitySelector) updateSelections(nextVersion *versioned.Tx) {
	selections := make(identity.NumericIdentitySlice, len(i.cachedSelections))
	idx := 0
	for nid := range i.cachedSelections {
		selections[idx] = nid
		idx++
	}
	// Sort the numeric identities so that the map iteration order
	// does not matter. This makes testing easier, but may help
	// identifying changes easier also otherwise.
	slices.Sort(selections)
	i.setSelections(selections, nextVersion)
}

func (i *identitySelector) setSelections(selections identity.NumericIdentitySlice, nextVersion *versioned.Tx) {
	var err error
	if len(selections) > 0 {
		err = i.selections.SetAt(selections, nextVersion)
	} else {
		err = i.selections.RemoveAt(nextVersion)
	}
	if err != nil {
		i.logger.Error(
			"setSelections failed",
			logfields.Error, err,
			logfields.Stacktrace, hclog.Stacktrace(),
		)
	}
}
