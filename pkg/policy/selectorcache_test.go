// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"sync"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

type SelectorCacheTestSuite struct{}

var _ = Suite(&SelectorCacheTestSuite{})

type DummySelectorCacheUser struct{}

func (d *DummySelectorCacheUser) IdentitySelectionUpdated(selector CachedSelector, added, deleted []identity.NumericIdentity) {
}

type cachedSelectionUser struct {
	c    *C
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

func newUser(c *C, name string, sc *SelectorCache) *cachedSelectionUser {
	csu := &cachedSelectionUser{
		c:          c,
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

	cached, added := csu.sc.AddIdentitySelector(csu, sel)
	csu.c.Assert(cached, Not(Equals), nil)

	_, exists := csu.selections[cached]
	// Not added if already exists for this user
	csu.c.Assert(added, Equals, !exists)
	csu.selections[cached] = cached.GetSelections()

	// Pre-existing selections are not notified as updates
	csu.c.Assert(csu.sc.haveUserNotifications(), Equals, false)

	return cached
}

func (csu *cachedSelectionUser) AddFQDNSelector(sel api.FQDNSelector) CachedSelector {
	csu.updateMutex.Lock()
	defer csu.updateMutex.Unlock()

	cached, added := csu.sc.AddFQDNSelector(csu, sel)
	csu.c.Assert(cached, Not(Equals), nil)

	_, exists := csu.selections[cached]
	// Not added if already exists for this user
	csu.c.Assert(added, Equals, !exists)
	csu.selections[cached] = cached.GetSelections()

	// Pre-existing selections are not notified as updates
	csu.c.Assert(csu.sc.haveUserNotifications(), Equals, false)

	return cached
}

func (csu *cachedSelectionUser) RemoveSelector(sel CachedSelector) {
	csu.updateMutex.Lock()
	defer csu.updateMutex.Unlock()

	csu.sc.RemoveSelector(sel, csu)
	delete(csu.selections, sel)

	// No notifications for a removed selector
	csu.c.Assert(csu.sc.haveUserNotifications(), Equals, false)
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
		csu.c.Assert(haveNid(add, selections), Equals, true)
	}
	for _, del := range deleted {
		csu.c.Assert(haveNid(del, selections), Equals, false)
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

func (cs *testCachedSelector) GetSelections() []identity.NumericIdentity {
	return cs.selections
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

func (ds *SelectorCacheTestSuite) SetUpTest(c *C) {
}

func (ds *SelectorCacheTestSuite) TearDownTest(c *C) {
}

func (ds *SelectorCacheTestSuite) TestAddRemoveSelector(c *C) {
	sc := testNewSelectorCache(cache.IdentityCache{})

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(cache.IdentityCache{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s),
			k8sConst.PodNamespaceLabel: labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	}, nil, wg)
	wg.Wait()

	testSelector := api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s))

	user1 := newUser(c, "user1", sc)
	cached := user1.AddIdentitySelector(testSelector)

	// Current selections contain the numeric identities of existing identities that match
	selections := cached.GetSelections()
	c.Assert(len(selections), Equals, 1)
	c.Assert(selections[0], Equals, identity.NumericIdentity(1234))

	// Try add the same selector from the same user the second time
	testSelector = api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s))
	cached2 := user1.AddIdentitySelector(testSelector)
	c.Assert(cached2, Equals, cached)

	// Add the same selector from a different user
	testSelector = api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s))
	user2 := newUser(c, "user2", sc)
	cached3 := user2.AddIdentitySelector(testSelector)

	// Same old CachedSelector is returned, nothing new is cached
	c.Assert(cached3, Equals, cached)

	// Removing the first user does not remove the cached selector
	user1.RemoveSelector(cached)
	// Remove is idempotent
	user1.RemoveSelector(cached)

	// Removing the last user removes the cached selector
	user2.RemoveSelector(cached3)
	// Remove is idempotent
	user2.RemoveSelector(cached3)

	// All identities removed
	c.Assert(len(sc.selectors), Equals, 0)
}

func (ds *SelectorCacheTestSuite) TestMultipleIdentitySelectors(c *C) {
	sc := testNewSelectorCache(cache.IdentityCache{})

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(cache.IdentityCache{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	}, nil, wg)
	wg.Wait()

	testSelector := api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s))
	test2Selector := api.NewESFromLabels(labels.NewLabel("app", "test2", labels.LabelSourceK8s))

	user1 := newUser(c, "user1", sc)
	cached := user1.AddIdentitySelector(testSelector)

	// Current selections contain the numeric identities of existing identities that match
	selections := cached.GetSelections()
	c.Assert(len(selections), Equals, 1)
	c.Assert(selections[0], Equals, identity.NumericIdentity(1234))

	// Add another selector from the same user
	cached2 := user1.AddIdentitySelector(test2Selector)
	c.Assert(cached2, Not(Equals), cached)

	// Current selections contain the numeric identities of existing identities that match
	selections2 := cached2.GetSelections()
	c.Assert(len(selections2), Equals, 1)
	c.Assert(selections2[0], Equals, identity.NumericIdentity(2345))

	user1.RemoveSelector(cached)
	user1.RemoveSelector(cached2)

	// All identities removed
	c.Assert(len(sc.selectors), Equals, 0)
}

func (ds *SelectorCacheTestSuite) TestIdentityUpdates(c *C) {
	sc := testNewSelectorCache(cache.IdentityCache{})

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(cache.IdentityCache{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	}, nil, wg)
	wg.Wait()

	testSelector := api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s))
	test2Selector := api.NewESFromLabels(labels.NewLabel("app", "test2", labels.LabelSourceK8s))

	user1 := newUser(c, "user1", sc)
	cached := user1.AddIdentitySelector(testSelector)

	// Current selections contain the numeric identities of existing identities that match
	selections := cached.GetSelections()
	c.Assert(len(selections), Equals, 1)
	c.Assert(selections[0], Equals, identity.NumericIdentity(1234))

	// Add another selector from the same user
	cached2 := user1.AddIdentitySelector(test2Selector)
	c.Assert(cached2, Not(Equals), cached)

	// Current selections contain the numeric identities of existing identities that match
	selections2 := cached2.GetSelections()
	c.Assert(len(selections2), Equals, 1)
	c.Assert(selections2[0], Equals, identity.NumericIdentity(2345))

	user1.Reset()
	// Add some identities to the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(cache.IdentityCache{
		12345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
	}, nil, wg)
	wg.Wait()

	adds, deletes := user1.WaitForUpdate()
	c.Assert(adds, Equals, 1)
	c.Assert(deletes, Equals, 0)

	// Current selections contain the numeric identities of existing identities that match
	selections = cached.GetSelections()
	c.Assert(len(selections), Equals, 2)
	c.Assert(selections[0], Equals, identity.NumericIdentity(1234))
	c.Assert(selections[1], Equals, identity.NumericIdentity(12345))

	user1.Reset()
	// Remove some identities from the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(nil, cache.IdentityCache{
		12345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
	}, wg)
	wg.Wait()

	adds, deletes = user1.WaitForUpdate()
	c.Assert(adds, Equals, 1)
	c.Assert(deletes, Equals, 1)

	// Current selections contain the numeric identities of existing identities that match
	selections = cached.GetSelections()
	c.Assert(len(selections), Equals, 1)
	c.Assert(selections[0], Equals, identity.NumericIdentity(1234))

	user1.RemoveSelector(cached)
	user1.RemoveSelector(cached2)

	// All identities removed
	c.Assert(len(sc.selectors), Equals, 0)
}

func (ds *SelectorCacheTestSuite) TestFQDNSelectorUpdates(c *C) {
	sc := testNewSelectorCache(cache.IdentityCache{})

	// Add some identities to the identity cache
	googleSel := api.FQDNSelector{MatchName: "google.com"}
	ciliumSel := api.FQDNSelector{MatchName: "cilium.io"}

	googleIdentities := []identity.NumericIdentity{321, 456, 987}
	ciliumIdentities := []identity.NumericIdentity{123, 456, 789}

	wg := &sync.WaitGroup{}
	sc.UpdateFQDNSelector(ciliumSel, ciliumIdentities, wg)
	sc.UpdateFQDNSelector(googleSel, googleIdentities, wg)
	wg.Wait()

	_, exists := sc.selectors[ciliumSel.String()]
	c.Assert(exists, Equals, true)

	user1 := newUser(c, "user1", sc)
	cached := user1.AddFQDNSelector(ciliumSel)

	selections := cached.GetSelections()
	c.Assert(len(selections), Equals, 3)
	for i, selection := range selections {
		c.Assert(selection, Equals, ciliumIdentities[i])
	}

	// Add another selector from the same user
	cached2 := user1.AddFQDNSelector(googleSel)
	c.Assert(cached2, Not(Equals), cached)

	// Current selections contain the numeric identities of existing identities that match
	selections2 := cached2.GetSelections()
	c.Assert(len(selections2), Equals, 3)
	for i, selection := range selections2 {
		c.Assert(selection, Equals, googleIdentities[i])
	}

	// Add some identities to the identity cache
	user1.Reset()
	ciliumIdentities = append(ciliumIdentities, identity.NumericIdentity(123456))
	wg = &sync.WaitGroup{}
	sc.UpdateFQDNSelector(ciliumSel, ciliumIdentities, wg)
	wg.Wait()

	adds, deletes := user1.WaitForUpdate()
	c.Assert(adds, Equals, 1)
	c.Assert(deletes, Equals, 0)

	user1.Reset()
	ciliumIdentities = ciliumIdentities[:1]
	wg = &sync.WaitGroup{}
	sc.UpdateFQDNSelector(ciliumSel, ciliumIdentities, wg)
	wg.Wait()

	adds, deletes = user1.WaitForUpdate()
	c.Assert(adds, Equals, 1)
	c.Assert(deletes, Equals, 3)

	user1.Reset()
	ciliumIdentities = []identity.NumericIdentity{}
	wg = &sync.WaitGroup{}
	sc.UpdateFQDNSelector(ciliumSel, ciliumIdentities, wg)
	wg.Wait()

	adds, deletes = user1.WaitForUpdate()
	c.Assert(adds, Equals, 1)
	c.Assert(deletes, Equals, 4)

	user1.RemoveSelector(cached)
	user1.RemoveSelector(cached2)

	// All identities removed
	c.Assert(len(sc.selectors), Equals, 0)

	yahooSel := api.FQDNSelector{MatchName: "yahoo.com"}
	_, added := sc.AddFQDNSelector(user1, yahooSel)
	c.Assert(added, Equals, true)
}

func (ds *SelectorCacheTestSuite) TestRemoveIdentitiesFQDNSelectors(c *C) {
	sc := testNewSelectorCache(cache.IdentityCache{})

	// Add some identities to the identity cache
	googleSel := api.FQDNSelector{MatchName: "google.com"}
	ciliumSel := api.FQDNSelector{MatchName: "cilium.io"}

	googleIdentities := []identity.NumericIdentity{321, 456, 987}
	ciliumIdentities := []identity.NumericIdentity{123, 456, 789}

	wg := &sync.WaitGroup{}
	sc.UpdateFQDNSelector(ciliumSel, ciliumIdentities, wg)
	sc.UpdateFQDNSelector(googleSel, googleIdentities, wg)
	wg.Wait()

	_, exists := sc.selectors[ciliumSel.String()]
	c.Assert(exists, Equals, true)

	user1 := newUser(c, "user1", sc)
	cached := user1.AddFQDNSelector(ciliumSel)

	selections := cached.GetSelections()
	c.Assert(len(selections), Equals, 3)
	for i, selection := range selections {
		c.Assert(selection, Equals, ciliumIdentities[i])
	}

	// Add another selector from the same user
	cached2 := user1.AddFQDNSelector(googleSel)
	c.Assert(cached2, Not(Equals), cached)

	// Current selections contain the numeric identities of existing identities that match
	selections2 := cached2.GetSelections()
	c.Assert(len(selections2), Equals, 3)
	for i, selection := range selections2 {
		c.Assert(selection, Equals, googleIdentities[i])
	}

	wg = &sync.WaitGroup{}
	sc.RemoveIdentitiesFQDNSelectors([]api.FQDNSelector{
		googleSel,
		ciliumSel,
	}, wg)
	wg.Wait()

	selections = cached.GetSelections()
	c.Assert(len(selections), Equals, 0)

	selections2 = cached2.GetSelections()
	c.Assert(len(selections2), Equals, 0)
}

func (ds *SelectorCacheTestSuite) TestIdentityUpdatesMultipleUsers(c *C) {
	sc := testNewSelectorCache(cache.IdentityCache{})

	// Add some identities to the identity cache
	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(cache.IdentityCache{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	}, nil, wg)
	wg.Wait()

	testSelector := api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s))

	user1 := newUser(c, "user1", sc)
	cached := user1.AddIdentitySelector(testSelector)

	// Add same selector from a different user
	user2 := newUser(c, "user2", sc)
	cached2 := user2.AddIdentitySelector(testSelector)
	c.Assert(cached2, Equals, cached)

	user1.Reset()
	user2.Reset()
	// Add some identities to the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(cache.IdentityCache{
		123: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		234: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
		345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
	}, nil, wg)
	wg.Wait()

	adds, deletes := user1.WaitForUpdate()
	c.Assert(adds, Equals, 2)
	c.Assert(deletes, Equals, 0)
	adds, deletes = user2.WaitForUpdate()
	c.Assert(adds, Equals, 2)
	c.Assert(deletes, Equals, 0)

	// Current selections contain the numeric identities of existing identities that match
	selections := cached.GetSelections()
	c.Assert(len(selections), Equals, 3)
	c.Assert(selections[0], Equals, identity.NumericIdentity(123))
	c.Assert(selections[1], Equals, identity.NumericIdentity(345))
	c.Assert(selections[2], Equals, identity.NumericIdentity(1234))

	c.Assert(cached.GetSelections(), checker.DeepEquals, cached2.GetSelections())

	user1.Reset()
	user2.Reset()
	// Remove some identities from the identity cache
	wg = &sync.WaitGroup{}
	sc.UpdateIdentities(nil, cache.IdentityCache{
		123: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		234: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	}, wg)
	wg.Wait()

	adds, deletes = user1.WaitForUpdate()
	c.Assert(adds, Equals, 2)
	c.Assert(deletes, Equals, 1)
	adds, deletes = user2.WaitForUpdate()
	c.Assert(adds, Equals, 2)
	c.Assert(deletes, Equals, 1)

	// Current selections contain the numeric identities of existing identities that match
	selections = cached.GetSelections()
	c.Assert(len(selections), Equals, 2)
	c.Assert(selections[0], Equals, identity.NumericIdentity(345))
	c.Assert(selections[1], Equals, identity.NumericIdentity(1234))

	c.Assert(cached.GetSelections(), checker.DeepEquals, cached2.GetSelections())

	user1.RemoveSelector(cached)
	user2.RemoveSelector(cached2)

	// All identities removed
	c.Assert(len(sc.selectors), Equals, 0)
}

func testNewSelectorCache(ids cache.IdentityCache) *SelectorCache {
	sc := NewSelectorCache(testidentity.NewMockIdentityAllocator(ids), ids)
	sc.SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
	return sc
}
