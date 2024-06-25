// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

type DummySelectorCacheUser struct{}

func (d *DummySelectorCacheUser) IdentitySelectionUpdated(selector CachedSelector, added, deleted []identity.NumericIdentity) {
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
	for i := range selections {
		if selections[i] == nid {
			return true
		}
	}
	return false
}

func (csu *cachedSelectionUser) AddIdentitySelector(sel api.EndpointSelector) CachedSelector {
	csu.updateMutex.Lock()
	defer csu.updateMutex.Unlock()

	cached, added := csu.sc.AddIdentitySelector(csu, nil, sel)
	require.NotEqual(csu.t, nil, cached)

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

	cached, added := csu.sc.AddFQDNSelector(csu, nil, sel)
	require.NotEqual(csu.t, nil, cached)

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

func (csu *cachedSelectionUser) IdentitySelectionUpdated(selector CachedSelector, added, deleted []identity.NumericIdentity) {
	csu.updateMutex.Lock()
	defer csu.updateMutex.Unlock()

	csu.notifications++
	csu.adds += len(added)
	csu.deletes += len(deleted)

	selections := selector.GetSelections()

	// Validate added & deleted against the selections
	for _, add := range added {
		require.True(csu.t, haveNid(add, selections))
	}
	for _, del := range deleted {
		require.False(csu.t, haveNid(del, selections))
	}

	// update selections
	csu.selections[selector] = selections

	csu.updateCond.Signal()
}

// Mock CachedSelector for unit testing.

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
		adds = append(adds, nid)
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
				cs.selections = append(cs.selections[:i], cs.selections[i+1:]...)
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
func (cs *testCachedSelector) GetMetadataLabels() labels.LabelArray {
	return nil
}
func (cs *testCachedSelector) Selects(nid identity.NumericIdentity) bool {
	for _, id := range cs.selections {
		if id == nid {
			return true
		}
	}
	return false
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
	sc := testNewSelectorCache(identity.IdentityMap{})

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s),
			k8sConst.PodNamespaceLabel: labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	}, nil, wg)
	wg.Wait()

	testSelector := api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s))

	user1 := newUser(t, "user1", sc)
	cached := user1.AddIdentitySelector(testSelector)

	// Current selections contain the numeric identities of existing identities that match
	selections := cached.GetSelections()
	require.Equal(t, 1, len(selections))
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
	require.Equal(t, 0, len(sc.selectors))
}

func TestMultipleIdentitySelectors(t *testing.T) {
	sc := testNewSelectorCache(identity.IdentityMap{})

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	li1 := identity.IdentityScopeLocal
	li2 := li1 + 1
	sc.UpdateIdentities(identity.IdentityMap{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),

		li1: labels.GetCIDRLabels(netip.MustParsePrefix("10.0.0.1/32")).LabelArray(),
		li2: labels.GetCIDRLabels(netip.MustParsePrefix("10.0.0.0/8")).LabelArray(),
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
	require.Equal(t, 1, len(selections))
	require.Equal(t, identity.NumericIdentity(1234), selections[0])

	// Add another selector from the same user
	cached2 := user1.AddIdentitySelector(test2Selector)
	require.NotEqual(t, cached, cached2)

	// Current selections contain the numeric identities of existing identities that match
	selections2 := cached2.GetSelections()
	require.Equal(t, 1, len(selections2))
	require.Equal(t, identity.NumericIdentity(2345), selections2[0])

	shouldSelect := func(sel api.EndpointSelector, wantIDs ...identity.NumericIdentity) {
		csel := user1.AddIdentitySelector(sel)
		selections := csel.GetSelections()
		require.EqualValues(t, identity.NumericIdentitySlice(wantIDs), selections)
		user1.RemoveSelector(csel)
	}

	shouldSelect(cidr32Selector, li1)
	shouldSelect(cidr24Selector, li1)
	shouldSelect(cidr8Selector, li1, li2)
	shouldSelect(cidr7Selector, li1, li2)

	user1.RemoveSelector(cached)
	user1.RemoveSelector(cached2)

	// All identities removed
	require.Equal(t, 0, len(sc.selectors))
}

func TestIdentityUpdates(t *testing.T) {
	sc := testNewSelectorCache(identity.IdentityMap{})

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	}, nil, wg)
	wg.Wait()

	testSelector := api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceAny))
	test2Selector := api.NewESFromLabels(labels.NewLabel("app", "test2", labels.LabelSourceAny))

	user1 := newUser(t, "user1", sc)
	cached := user1.AddIdentitySelector(testSelector)

	// Current selections contain the numeric identities of existing identities that match
	selections := cached.GetSelections()
	require.Equal(t, 1, len(selections))
	require.Equal(t, identity.NumericIdentity(1234), selections[0])

	// Add another selector from the same user
	cached2 := user1.AddIdentitySelector(test2Selector)
	require.NotEqual(t, cached, cached2)

	// Current selections contain the numeric identities of existing identities that match
	selections2 := cached2.GetSelections()
	require.Equal(t, 1, len(selections2))
	require.Equal(t, identity.NumericIdentity(2345), selections2[0])

	user1.Reset()
	// Add some identities to the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		12345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
	}, nil, wg)
	wg.Wait()

	adds, deletes := user1.WaitForUpdate()
	require.Equal(t, 1, adds)
	require.Equal(t, 0, deletes)

	// Current selections contain the numeric identities of existing identities that match
	selections = cached.GetSelections()
	require.Equal(t, 2, len(selections))
	require.Equal(t, identity.NumericIdentity(1234), selections[0])
	require.Equal(t, identity.NumericIdentity(12345), selections[1])

	user1.Reset()
	// Remove some identities from the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(nil, identity.IdentityMap{
		12345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
	}, wg)
	wg.Wait()

	adds, deletes = user1.WaitForUpdate()
	require.Equal(t, 1, adds)
	require.Equal(t, 1, deletes)

	// Current selections contain the numeric identities of existing identities that match
	selections = cached.GetSelections()
	require.Equal(t, 1, len(selections))
	require.Equal(t, identity.NumericIdentity(1234), selections[0])

	user1.RemoveSelector(cached)
	user1.RemoveSelector(cached2)

	// All identities removed
	require.Equal(t, 0, len(sc.selectors))
}

func TestIdentityUpdatesMultipleUsers(t *testing.T) {
	sc := testNewSelectorCache(identity.IdentityMap{})

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
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
		123: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		234: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
		345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
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
	require.Equal(t, 3, len(selections))
	require.Equal(t, identity.NumericIdentity(123), selections[0])
	require.Equal(t, identity.NumericIdentity(345), selections[1])
	require.Equal(t, identity.NumericIdentity(1234), selections[2])

	require.EqualValues(t, cached2.GetSelections(), cached.GetSelections())

	user1.Reset()
	user2.Reset()
	// Remove some identities from the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(nil, identity.IdentityMap{
		123: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		234: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
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
	require.Equal(t, 2, len(selections))
	require.Equal(t, identity.NumericIdentity(345), selections[0])
	require.Equal(t, identity.NumericIdentity(1234), selections[1])

	require.EqualValues(t, cached2.GetSelections(), cached.GetSelections())

	user1.RemoveSelector(cached)
	user2.RemoveSelector(cached2)

	// All identities removed
	require.Equal(t, 0, len(sc.selectors))
}

func TestSelectorManagerCanGetBeforeSet(t *testing.T) {
	defer func() {
		r := recover()
		require.Equal(t, nil, r)
	}()

	idSel := identitySelector{
		key:   "test",
		users: make(map[CachedSelectionUser]struct{}),
	}
	selections := idSel.GetSelections()
	require.NotEqual(t, nil, selections)
	require.Equal(t, 0, len(selections))
}

func testNewSelectorCache(ids identity.IdentityMap) *SelectorCache {
	sc := NewSelectorCache(ids)
	sc.SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
	return sc
}

func Test_getLocalScopePrefix(t *testing.T) {
	prefix := getLocalScopePrefix(identity.ReservedIdentityWorld, nil)
	require.False(t, prefix.IsValid())

	prefix = getLocalScopePrefix(identity.ReservedIdentityWorld, labels.LabelArray{labels.Label{Source: labels.LabelSourceCIDR, Key: "0.0.0.0/0"}})
	require.False(t, prefix.IsValid())

	prefix = getLocalScopePrefix(identity.IdentityScopeLocal, labels.LabelArray{labels.Label{Source: labels.LabelSourceCIDR, Key: "0.0.0.0/0"}})
	require.True(t, prefix.IsValid())
	require.Equal(t, "0.0.0.0/0", prefix.String())

	prefix = getLocalScopePrefix(identity.IdentityScopeLocal, labels.LabelArray{labels.Label{Source: labels.LabelSourceCIDR, Key: "::/0"}})
	require.True(t, prefix.IsValid())
	require.Equal(t, "::/0", prefix.String())

	prefix = getLocalScopePrefix(identity.IdentityScopeLocal, labels.LabelArray{labels.Label{Source: labels.LabelSourceCIDR, Key: "--/0"}})
	require.True(t, prefix.IsValid())
	require.Equal(t, "::/0", prefix.String())

	prefix = getLocalScopePrefix(identity.IdentityScopeLocal, labels.LabelArray{
		labels.Label{Source: labels.LabelSourceCIDR, Key: "ff--/8"},
		labels.Label{Source: labels.LabelSourceCIDR, Key: "--/0"},
		labels.Label{Source: labels.LabelSourceCIDR, Key: "--1/128"},
	})
	require.True(t, prefix.IsValid())
	require.Equal(t, "::1/128", prefix.String())
}
