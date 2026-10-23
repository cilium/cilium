// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

func testNewSelectorCache(tb testing.TB, logger *slog.Logger, ids identity.IdentityMap) *SelectorCache {
	sc := NewSelectorCache(logger, ids)
	sc.userHandlerDone = make(chan struct{})
	sc.SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
	tb.Cleanup(sc.StopNotificationHandler)
	return sc
}

// StopNotificationHandler drains pending notifications and terminates the
// handler goroutine. Idempotent.
func (sc *SelectorCache) StopNotificationHandler() {
	sc.userMutex.Lock()
	defer sc.userMutex.Unlock()

	if sc.userHandlerDone == nil {
		return
	}

	handlerWasStarted := true
	sc.startNotificationsHandlerOnce.Do(func() {
		handlerWasStarted = false
	})

	if handlerWasStarted {
		sc.userNotes = append(sc.userNotes, userNotification{})
		sc.userMutex.Unlock()
		sc.userCond.Signal()
		<-sc.userHandlerDone
		sc.userMutex.Lock()
	}

	sc.userHandlerDone = nil
}

type selectorUpdate struct {
	selector       policytypes.CachedSelector
	added, deleted []identity.NumericIdentity
}

type cachedSelectionUser struct {
	t    *testing.T
	sc   *SelectorCache
	name string

	updateMutex   lock.Mutex
	updateCond    *sync.Cond
	selections    map[CachedSelector][]identity.NumericIdentity
	notifications int
	adds          int
	deletes       int

	updates []selectorUpdate
}

func (sc *SelectorCache) haveUserNotifications() bool {
	sc.userMutex.Lock()
	defer sc.userMutex.Unlock()
	return len(sc.userNotes) > 0
}

func newUser(t *testing.T, name string, sc *SelectorCache) *cachedSelectionUser {
	csu := &cachedSelectionUser{
		t:          t,
		sc:         sc,
		name:       name,
		selections: make(map[CachedSelector][]identity.NumericIdentity),
	}
	csu.updateCond = sync.NewCond(&csu.updateMutex)
	return csu
}

func haveNid(nid identity.NumericIdentity, selections []identity.NumericIdentity) bool {
	return slices.Contains(selections, nid)
}

// findCachedIdentitySelector finds the given api.EndpointSelector in the
// selector cache, returning nil if one can not be found.
// NOTE: Only used for testing.
func (sc *SelectorCache) findCachedIdentitySelector(selector api.EndpointSelector) types.CachedSelector {
	key := selector.CachedString()
	sc.mutex.RLock()
	sel, _ := sc.selectors.Get(key)
	sc.mutex.RUnlock()
	return sel
}

func (csu *cachedSelectionUser) AddIdentitySelector(sel api.EndpointSelector) CachedSelector {
	csu.updateMutex.Lock()
	defer csu.updateMutex.Unlock()

	cached, added := csu.sc.AddIdentitySelectorForTest(csu, sel)
	require.NotNil(csu.t, cached)

	_, exists := csu.selections[cached]
	// Not added if already exists for this user
	require.Equal(csu.t, !exists, added)
	csu.selections[cached] = cached.GetSelections()

	// Pre-existing selections are not notified as updates
	require.False(csu.t, csu.sc.haveUserNotifications())

	return cached
}

func (csu *cachedSelectionUser) AddFQDNSelector(sel api.FQDNSelector) CachedSelector {
	csu.updateMutex.Lock()
	defer csu.updateMutex.Unlock()

	var cached types.CachedSelector
	css, added := csu.sc.AddSelectors(csu, types.ToSelectors(sel)...)
	cached = css[0]

	require.NotNil(csu.t, cached)

	_, exists := csu.selections[cached]
	// Not added if already exists for this user
	require.Equal(csu.t, !exists, added)
	csu.selections[cached] = cached.GetSelections()

	// Pre-existing selections are not notified as updates
	require.False(csu.t, csu.sc.haveUserNotifications())

	return cached
}

func (csu *cachedSelectionUser) RemoveSelector(sel CachedSelector) {
	csu.updateMutex.Lock()
	defer csu.updateMutex.Unlock()

	csu.sc.RemoveSelector(sel, csu)
	delete(csu.selections, sel)

	// No notifications for a removed selector
	require.False(csu.t, csu.sc.haveUserNotifications())
}

func (csu *cachedSelectionUser) Reset() {
	csu.updateMutex.Lock()
	defer csu.updateMutex.Unlock()
	csu.notifications = 0
}

func (csu *cachedSelectionUser) WaitForUpdate() (adds, deletes int) {
	csu.updateMutex.Lock()
	defer csu.updateMutex.Unlock()
	for csu.notifications == 0 {
		csu.updateCond.Wait()
	}
	return csu.adds, csu.deletes
}

func (csu *cachedSelectionUser) IdentitySelectionUpdated(logger *slog.Logger, selector policytypes.CachedSelector, added, deleted []identity.NumericIdentity) {
	csu.updateMutex.Lock()
	defer csu.updateMutex.Unlock()

	csu.notifications++
	csu.adds += len(added)
	csu.deletes += len(deleted)

	// collect updates as the changes may not be visible in selections before Commit
	csu.updates = append(csu.updates, selectorUpdate{
		selector: selector,
		added:    slices.Clone(added),
		deleted:  slices.Clone(deleted),
	})
}

func (csu *cachedSelectionUser) IdentitySelectionCommit(logger *slog.Logger, txn SelectorSnapshot) {
	csu.updateMutex.Lock()
	defer csu.updateMutex.Unlock()

	for i := range csu.updates {
		selector := csu.updates[i].selector
		added := csu.updates[i].added
		deleted := csu.updates[i].deleted

		selections := selector.GetSelectionsAt(txn)

		// Validate added & deleted against the selections
		for _, add := range added {
			require.True(csu.t, haveNid(add, selections))
		}
		for _, del := range deleted {
			require.False(csu.t, haveNid(del, selections))
		}

		// update selections
		csu.selections[selector] = selections
	}
	csu.updates = nil
	csu.updateCond.Signal()
}

func (csu *cachedSelectionUser) IsPeerSelector() bool {
	return true
}

func (csu *cachedSelectionUser) GetRuleLabels(cs CachedSelector) labels.LabelArrayList {
	return nil
}

// Mock CachedSelector for unit testing.
//
// testCachedSelector is used in isolation so there is no point to implement versioning for it.
type testCachedSelector struct {
	name       string
	wildcard   bool
	selections []identity.NumericIdentity
}

func newTestCachedSelector(name string, wildcard bool, selections ...int) *testCachedSelector {
	cs := &testCachedSelector{
		name:       name,
		wildcard:   wildcard,
		selections: make([]identity.NumericIdentity, 0, len(selections)),
	}
	cs.addSelections(selections...)
	return cs
}

// returns selections as []identity.NumericIdentity
func (cs *testCachedSelector) addSelections(selections ...int) (adds []identity.NumericIdentity) {
	for _, id := range selections {
		nid := identity.NumericIdentity(id)
		// hack: expand 0 to all aggregates
		if nid == 0 {
			adds = append(adds, AllAggregates...)
		} else {
			adds = append(adds, nid)
		}
		if cs == nil {
			continue
		}
		if !cs.Selects(nid) {
			cs.selections = append(cs.selections, nid)
		}
	}
	return adds
}

// returns selections as []identity.NumericIdentity
func (cs *testCachedSelector) deleteSelections(selections ...int) (deletes []identity.NumericIdentity) {
	for _, id := range selections {
		nid := identity.NumericIdentity(id)
		deletes = append(deletes, nid)
		if cs == nil {
			continue
		}
		for i := 0; i < len(cs.selections); i++ {
			if nid == cs.selections[i] {
				cs.selections = slices.Delete(cs.selections, i, i+1)
				i--
			}
		}
	}
	return deletes
}

// CachedSelector interface

func (cs *testCachedSelector) GetSelections() identity.NumericIdentitySlice {
	return cs.selections
}

func (cs *testCachedSelector) GetSelectionsAt(SelectorSnapshot) identity.NumericIdentitySlice {
	return cs.selections
}

func (cs *testCachedSelector) GetMetadataLabels() labels.LabelArrayList {
	return nil
}
func (cs *testCachedSelector) Selects(nid identity.NumericIdentity) bool {
	return slices.Contains(cs.selections, nid)
}

func (cs *testCachedSelector) IsWildcard() bool {
	return cs.wildcard
}

func (cs *testCachedSelector) IsNone() bool {
	return false
}

func (cs *testCachedSelector) String() string {
	return cs.name
}

func TestAddRemoveSelector(t *testing.T) {
	sc := testNewSelectorCache(t, hivetest.Logger(t), nil)

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		1234: labels.FromSlice(labels.NewLabel("app", "test", labels.LabelSourceK8s),
			labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s)),
		2345: labels.FromSlice(labels.NewLabel("app", "test2", labels.LabelSourceK8s)),
	}, nil, wg)
	wg.Wait()

	testSelector := api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s))

	user1 := newUser(t, "user1", sc)
	cached := user1.AddIdentitySelector(testSelector)

	// Current selections contain the numeric identities of existing identities that match
	selections := cached.GetSelections()
	require.Len(t, selections, 1)
	require.Equal(t, identity.NumericIdentity(1234), selections[0])

	// Try add the same selector from the same user the second time
	testSelector = api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s))
	cached2 := user1.AddIdentitySelector(testSelector)
	require.Equal(t, cached, cached2)

	// Add the same selector from a different user
	testSelector = api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s))
	user2 := newUser(t, "user2", sc)
	cached3 := user2.AddIdentitySelector(testSelector)

	// Same old CachedSelector is returned, nothing new is cached
	require.Equal(t, cached, cached3)

	// Removing the first user does not remove the cached selector
	user1.RemoveSelector(cached)
	// Remove is idempotent
	user1.RemoveSelector(cached)

	// Removing the last user removes the cached selector
	user2.RemoveSelector(cached3)
	// Remove is idempotent
	user2.RemoveSelector(cached3)

	// All identities removed
	require.True(t, sc.selectors.Empty())
}

func TestMultipleIdentitySelectors(t *testing.T) {
	sc := testNewSelectorCache(t, hivetest.Logger(t), nil)

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	li1 := identity.IdentityScopeLocal
	li2 := li1 + 1
	sc.UpdateIdentities(identity.IdentityMap{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)},
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)},

		li1: labels.GetCIDRLabels(netip.MustParsePrefix("10.0.0.1/32")),
		li2: labels.GetCIDRLabels(netip.MustParsePrefix("10.0.0.0/8")),
	}, nil, wg)
	wg.Wait()

	testSelector := api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceAny))
	test2Selector := api.NewESFromLabels(labels.NewLabel("app", "test2", labels.LabelSourceAny))

	// Test both exact and broader CIDR selectors
	cidr32Selector := api.NewESFromLabels(labels.NewLabel("cidr:10.0.0.1/32", "", labels.LabelSourceCIDR))
	cidr24Selector := api.NewESFromLabels(labels.NewLabel("cidr:10.0.0.0/24", "", labels.LabelSourceCIDR))
	cidr8Selector := api.NewESFromLabels(labels.NewLabel("cidr:10.0.0.0/8", "", labels.LabelSourceCIDR))
	cidr7Selector := api.NewESFromLabels(labels.NewLabel("cidr:10.0.0.0/7", "", labels.LabelSourceCIDR))

	user1 := newUser(t, "user1", sc)
	cached := user1.AddIdentitySelector(testSelector)

	// Current selections contain the numeric identities of existing identities that match
	selections := cached.GetSelections()
	require.Len(t, selections, 1)
	require.Equal(t, identity.NumericIdentity(1234), selections[0])

	// Add another selector from the same user
	cached2 := user1.AddIdentitySelector(test2Selector)
	require.NotEqual(t, cached, cached2)

	// Current selections contain the numeric identities of existing identities that match
	selections2 := cached2.GetSelections()
	require.Len(t, selections2, 1)
	require.Equal(t, identity.NumericIdentity(2345), selections2[0])

	shouldSelect := func(sel api.EndpointSelector, wantIDs ...identity.NumericIdentity) {
		csel := user1.AddIdentitySelector(sel)
		selections := csel.GetSelections()
		require.Equal(t, identity.NumericIdentitySlice(wantIDs), selections)
		user1.RemoveSelector(csel)
	}

	shouldSelect(cidr32Selector, li1)
	shouldSelect(cidr24Selector, li1)
	shouldSelect(cidr8Selector, li1, li2)
	shouldSelect(cidr7Selector, li1, li2)

	user1.RemoveSelector(cached)
	user1.RemoveSelector(cached2)

	// All identities removed
	require.True(t, sc.selectors.Empty())
}

func TestIdentityUpdates(t *testing.T) {
	sc := testNewSelectorCache(t, hivetest.Logger(t), nil)

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)},
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)},
	}, nil, wg)
	wg.Wait()

	testSelector := api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceAny))
	test2Selector := api.NewESFromLabels(labels.NewLabel("app", "test2", labels.LabelSourceAny))

	user1 := newUser(t, "user1", sc)
	cached := user1.AddIdentitySelector(testSelector)

	// Current selections contain the numeric identities of existing identities that match
	selections := cached.GetSelections()
	require.Len(t, selections, 1)
	require.Equal(t, identity.NumericIdentity(1234), selections[0])

	// Add another selector from the same user
	cached2 := user1.AddIdentitySelector(test2Selector)
	require.NotEqual(t, cached, cached2)

	// Current selections contain the numeric identities of existing identities that match
	selections2 := cached2.GetSelections()
	require.Len(t, selections2, 1)
	require.Equal(t, identity.NumericIdentity(2345), selections2[0])

	user1.Reset()
	// Add some identities to the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		12345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)},
	}, nil, wg)
	wg.Wait()

	adds, deletes := user1.WaitForUpdate()
	require.Equal(t, 1, adds)
	require.Equal(t, 0, deletes)

	// Current selections contain the numeric identities of existing identities that match
	selections = cached.GetSelections()
	require.Len(t, selections, 2)
	require.Equal(t, identity.NumericIdentity(1234), selections[0])
	require.Equal(t, identity.NumericIdentity(12345), selections[1])

	user1.Reset()
	// Remove some identities from the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(nil, identity.IdentityMap{
		12345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)},
	}, wg)
	wg.Wait()

	adds, deletes = user1.WaitForUpdate()
	require.Equal(t, 1, adds)
	require.Equal(t, 1, deletes)

	// Current selections contain the numeric identities of existing identities that match
	selections = cached.GetSelections()
	require.Len(t, selections, 1)
	require.Equal(t, identity.NumericIdentity(1234), selections[0])

	user1.RemoveSelector(cached)
	user1.RemoveSelector(cached2)

	// All identities removed
	require.True(t, sc.selectors.Empty())
}

func TestIdentityUpdatesMultipleUsers(t *testing.T) {
	sc := testNewSelectorCache(t, hivetest.Logger(t), nil)

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)},
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)},
	}, nil, wg)
	wg.Wait()

	testSelector := api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s))

	user1 := newUser(t, "user1", sc)
	cached := user1.AddIdentitySelector(testSelector)

	// Add same selector from a different user
	user2 := newUser(t, "user2", sc)
	cached2 := user2.AddIdentitySelector(testSelector)
	require.Equal(t, cached, cached2)

	user1.Reset()
	user2.Reset()
	// Add some identities to the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		123: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)},
		234: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)},
		345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)},
	}, nil, wg)
	wg.Wait()

	adds, deletes := user1.WaitForUpdate()
	require.Equal(t, 2, adds)
	require.Equal(t, 0, deletes)
	adds, deletes = user2.WaitForUpdate()
	require.Equal(t, 2, adds)
	require.Equal(t, 0, deletes)

	// Current selections contain the numeric identities of existing identities that match
	selections := cached.GetSelections()
	require.Len(t, selections, 3)
	require.Equal(t, identity.NumericIdentity(123), selections[0])
	require.Equal(t, identity.NumericIdentity(345), selections[1])
	require.Equal(t, identity.NumericIdentity(1234), selections[2])

	require.Equal(t, cached2.GetSelections(), cached.GetSelections())

	user1.Reset()
	user2.Reset()
	// Remove some identities from the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(nil, identity.IdentityMap{
		123: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)},
		234: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)},
	}, wg)
	wg.Wait()

	adds, deletes = user1.WaitForUpdate()
	require.Equal(t, 2, adds)
	require.Equal(t, 1, deletes)
	adds, deletes = user2.WaitForUpdate()
	require.Equal(t, 2, adds)
	require.Equal(t, 1, deletes)

	// Current selections contain the numeric identities of existing identities that match
	selections = cached.GetSelections()
	require.Len(t, selections, 2)
	require.Equal(t, identity.NumericIdentity(345), selections[0])
	require.Equal(t, identity.NumericIdentity(1234), selections[1])

	require.Equal(t, cached2.GetSelections(), cached.GetSelections())

	user1.RemoveSelector(cached)
	user2.RemoveSelector(cached2)

	// All identities removed
	require.True(t, sc.selectors.Empty())
}

func TestTransactionalUpdate(t *testing.T) {
	sc := testNewSelectorCache(t, hivetest.Logger(t), nil)

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	li1 := identity.IdentityScopeLocal
	li2 := li1 + 1
	sc.UpdateIdentities(identity.IdentityMap{
		li1: labels.GetCIDRLabels(netip.MustParsePrefix("10.0.0.1/32")),
		li2: labels.GetCIDRLabels(netip.MustParsePrefix("10.0.0.0/8")),
	}, nil, wg)
	wg.Wait()

	// Test both exact and broader CIDR selectors
	cidr32Selector := api.NewESFromLabels(labels.NewLabel("cidr:10.0.0.1/32", "", labels.LabelSourceCIDR))
	cidr24Selector := api.NewESFromLabels(labels.NewLabel("cidr:10.0.0.0/24", "", labels.LabelSourceCIDR))
	cidr8Selector := api.NewESFromLabels(labels.NewLabel("cidr:10.0.0.0/8", "", labels.LabelSourceCIDR))
	cidr7Selector := api.NewESFromLabels(labels.NewLabel("cidr:10.0.0.0/7", "", labels.LabelSourceCIDR))

	user1 := newUser(t, "user1", sc)

	cs32 := user1.AddIdentitySelector(cidr32Selector)
	cs24 := user1.AddIdentitySelector(cidr24Selector)
	cs8 := user1.AddIdentitySelector(cidr8Selector)
	cs7 := user1.AddIdentitySelector(cidr7Selector)

	txn := sc.GetSelectorSnapshot()

	require.Equal(t, identity.NumericIdentitySlice{li1}, cs32.GetSelectionsAt(txn))
	require.Equal(t, identity.NumericIdentitySlice{li1}, cs24.GetSelectionsAt(txn))
	require.Equal(t, identity.NumericIdentitySlice{li1, li2}, cs8.GetSelectionsAt(txn))
	require.Equal(t, identity.NumericIdentitySlice{li1, li2}, cs7.GetSelectionsAt(txn))

	// Add some identities to the identity cache
	li3 := li2 + 1
	li4 := li3 + 1
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		li3: labels.GetCIDRLabels(netip.MustParsePrefix("10.0.0.0/31")),
		li4: labels.GetCIDRLabels(netip.MustParsePrefix("10.0.0.0/7")),
	}, nil, wg)
	wg.Wait()

	// Old version handle still gets the same selections as before
	require.Equal(t, identity.NumericIdentitySlice{li1}, cs32.GetSelectionsAt(txn))
	require.Equal(t, identity.NumericIdentitySlice{li1}, cs24.GetSelectionsAt(txn))
	require.Equal(t, identity.NumericIdentitySlice{li1, li2}, cs8.GetSelectionsAt(txn))
	require.Equal(t, identity.NumericIdentitySlice{li1, li2}, cs7.GetSelectionsAt(txn))

	// New version handle sees the new updates on all selectors
	txn2 := sc.GetSelectorSnapshot()

	require.Equal(t, identity.NumericIdentitySlice{li1}, cs32.GetSelectionsAt(txn2))
	require.Equal(t, identity.NumericIdentitySlice{li1, li3}, cs24.GetSelectionsAt(txn2))
	require.Equal(t, identity.NumericIdentitySlice{li1, li2, li3}, cs8.GetSelectionsAt(txn2))
	require.Equal(t, identity.NumericIdentitySlice{li1, li2, li3, li4}, cs7.GetSelectionsAt(txn2))

	// Remove some identities from the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(nil, identity.IdentityMap{
		li1: labels.GetCIDRLabels(netip.MustParsePrefix("10.0.0.1/32")),
	}, wg)
	wg.Wait()

	// Oldest version handle still gets the same selections as before
	require.Equal(t, identity.NumericIdentitySlice{li1}, cs32.GetSelectionsAt(txn))
	require.Equal(t, identity.NumericIdentitySlice{li1}, cs24.GetSelectionsAt(txn))
	require.Equal(t, identity.NumericIdentitySlice{li1, li2}, cs8.GetSelectionsAt(txn))
	require.Equal(t, identity.NumericIdentitySlice{li1, li2}, cs7.GetSelectionsAt(txn))

	require.Equal(t, identity.NumericIdentitySlice{li1}, cs32.GetSelectionsAt(txn2))
	require.Equal(t, identity.NumericIdentitySlice{li1, li3}, cs24.GetSelectionsAt(txn2))
	require.Equal(t, identity.NumericIdentitySlice{li1, li2, li3}, cs8.GetSelectionsAt(txn2))
	require.Equal(t, identity.NumericIdentitySlice{li1, li2, li3, li4}, cs7.GetSelectionsAt(txn2))

	// New version handle sees the removal
	txn3 := sc.GetSelectorSnapshot()

	require.Equal(t, identity.NumericIdentitySlice(nil), cs32.GetSelectionsAt(txn3))
	require.Equal(t, identity.NumericIdentitySlice{li3}, cs24.GetSelectionsAt(txn3))
	require.Equal(t, identity.NumericIdentitySlice{li2, li3}, cs8.GetSelectionsAt(txn3))
	require.Equal(t, identity.NumericIdentitySlice{li2, li3, li4}, cs7.GetSelectionsAt(txn3))

	user1.RemoveSelector(cs32)
	user1.RemoveSelector(cs24)
	user1.RemoveSelector(cs8)
	user1.RemoveSelector(cs7)

	// All identities removed
	require.True(t, sc.selectors.Empty())
}

func TestSelectorCacheCanSkipUpdate(t *testing.T) {
	id1 := identity.NewIdentity(1001, labels.LabelArray{labels.NewLabel("id", "a", labels.LabelSourceK8s)}.Labels())
	id2 := identity.NewIdentity(1002, labels.LabelArray{labels.NewLabel("id", "b", labels.LabelSourceK8s)}.Labels())

	toIdentityMap := func(ids ...*identity.Identity) identity.IdentityMap {
		idMap := identity.IdentityMap{}
		for _, id := range ids {
			idMap[id.ID] = id.Labels
		}
		return idMap
	}

	sc := testNewSelectorCache(t, hivetest.Logger(t), nil)
	wg := &sync.WaitGroup{}

	require.False(t, sc.CanSkipUpdate(toIdentityMap(id1), nil))
	sc.UpdateIdentities(toIdentityMap(id1), nil, wg)
	wg.Wait()

	require.True(t, sc.CanSkipUpdate(nil, toIdentityMap(id2)))
	require.True(t, sc.CanSkipUpdate(toIdentityMap(id1), toIdentityMap(id2)))

	require.False(t, sc.CanSkipUpdate(toIdentityMap(id2), nil))
	sc.UpdateIdentities(toIdentityMap(id2), nil, wg)
	wg.Wait()

	require.True(t, sc.CanSkipUpdate(toIdentityMap(id2), nil))
	require.False(t, sc.CanSkipUpdate(nil, toIdentityMap(id2)))
	require.False(t, sc.CanSkipUpdate(nil, toIdentityMap(id1, id2)))
	sc.UpdateIdentities(nil, toIdentityMap(id1, id2), wg)
	wg.Wait()
}

func TestSelectorManagerCanGetBeforeSet(t *testing.T) {
	defer func() {
		r := recover()
		require.Nil(t, r)
	}()

	sc := testNewSelectorCache(t, hivetest.Logger(t), nil)
	sel := newIdentitySelector(sc, "test", nil)

	selections := sel.GetSelections()
	require.Empty(t, selections)
}

// benchPoolLabelKey mimics the pod label the resource-churn scenarios select on.
const benchPoolLabelKey = "kfuzz.cilium.io/pool"

// benchPoolIdentities returns an identity cache of numIdentities identities,
// each carrying one of numPools values of benchPoolLabelKey.
func benchPoolIdentities(numIdentities, numPools int) identity.IdentityMap {
	ids := generateNumIdentities(numIdentities)
	for nid, lbls := range ids {
		lbl := labels.NewLabel(benchPoolLabelKey, strconv.Itoa(int(nid)%numPools), labels.LabelSourceK8s)
		lbls[lbl.Key] = lbl
	}
	return ids
}

// benchPoolSelectors returns count distinct label selectors, each selecting the
// identities of setSize out of numPools pools.
func benchPoolSelectors(count, numPools, setSize int) []Selector {
	key := labels.NewLabel(benchPoolLabelKey, "", labels.LabelSourceK8s)
	rng := rand.New(rand.NewPCG(42, 42))
	sels := make([]Selector, 0, count)
	seen := make(map[string]struct{}, count)
	for len(sels) < count {
		values := make([]string, 0, setSize)
		for _, pool := range rng.Perm(numPools)[:setSize] {
			values = append(values, strconv.Itoa(pool))
		}
		slices.Sort(values)
		es := api.NewESFromMatchRequirements(nil, []slim_metav1.LabelSelectorRequirement{{
			Key:      key.GetExtendedKey(),
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   values,
		}})
		sel := types.NewLabelSelector(es)
		if _, dup := seen[sel.Key()]; dup {
			continue
		}
		seen[sel.Key()] = struct{}{}
		sels = append(sels, sel)
	}
	return sels
}

// BenchmarkSelectorCacheAddSelector measures the add_selector operation of
// cilium_policy_selector_cache_operation_duration_seconds, which is observed
// only for selectors that are not already cached and whose cost is dominated by
// the scan of the identity cache in addSelectorLocked. The selector is removed
// again with the timer stopped so that every add is a cache miss and the
// selector cache does not grow over the run.
func BenchmarkSelectorCacheAddSelector(b *testing.B) {
	const (
		numPools    = 64
		poolsPerSel = 4
		numSels     = 64
	)

	for _, numIdentities := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("identities=%d", numIdentities), func(b *testing.B) {
			sc := testNewSelectorCache(b, hivetest.Logger(b), benchPoolIdentities(numIdentities, numPools))
			sels := benchPoolSelectors(numSels, numPools, poolsPerSel)

			// Guard against silently measuring a selector that matches nothing.
			css, _ := sc.AddSelectors(dummySelectorCacheUser, sels[0])
			selections := len(css[0].GetSelections())
			sc.RemoveSelector(css[0], dummySelectorCacheUser)
			if selections == 0 {
				b.Fatal("benchmark selector matches no identities")
			}

			b.ReportAllocs()
			i := 0
			for b.Loop() {
				css, _ := sc.AddSelectors(dummySelectorCacheUser, sels[i])

				b.StopTimer()
				sc.RemoveSelector(css[0], dummySelectorCacheUser)
				i = (i + 1) % len(sels)
				b.StartTimer()
			}

			// b.Loop resets extra metrics, so this has to come after it.
			b.ReportMetric(float64(selections), "selections/op")
		})
	}
}

func BenchmarkSelectorCacheIdentityUpdates(b *testing.B) {
	td := newTestData(b, hivetest.Logger(b))
	td.bootstrapRepo(GenerateMatchAllRules, 1, b)
	ids := generateNumIdentities(10000)
	wg := &sync.WaitGroup{}
	for k, v := range ids {
		td.sc.UpdateIdentities(identity.IdentityMap{k: v}, nil, wg)
	}

	wg.Wait()

	b.ReportAllocs()
	for b.Loop() {
		wg := &sync.WaitGroup{}
		td.sc.UpdateIdentities(nil, identity.IdentityMap{fooIdentity.ID: fooIdentity.Labels}, wg)
		wg.Wait()
		td.sc.UpdateIdentities(identity.IdentityMap{fooIdentity.ID: fooIdentity.Labels}, nil, wg)
		wg.Wait()

	}
}
