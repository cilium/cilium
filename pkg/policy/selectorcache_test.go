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

// +build !privileged_tests

package policy

import (
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

type SelectorCacheTestSuite struct{}

var _ = Suite(&SelectorCacheTestSuite{})

type cachedSelectionUser struct {
	c             *C
	sc            *SelectorCache
	name          string
	selections    map[CachedSelector][]identity.NumericIdentity
	notifications int
	adds          int
	deletes       int
}

func newUser(c *C, name string, sc *SelectorCache) *cachedSelectionUser {
	return &cachedSelectionUser{
		c:          c,
		sc:         sc,
		name:       name,
		selections: make(map[CachedSelector][]identity.NumericIdentity),
	}
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
	notifications := csu.notifications
	cached, added := csu.sc.AddIdentitySelector(csu, sel)
	csu.c.Assert(cached, Not(Equals), nil)

	_, exists := csu.selections[cached]
	// Not added if already exists for this user
	csu.c.Assert(added, Equals, !exists)
	csu.selections[cached] = cached.GetSelections()

	// Pre-existing selections are not notified as updates
	csu.c.Assert(csu.notifications, Equals, notifications)

	return cached
}

func (csu *cachedSelectionUser) AddFQDNSelector(sel api.FQDNSelector) CachedSelector {
	notifications := csu.notifications
	cached, added := csu.sc.AddFQDNSelector(csu, sel)
	csu.c.Assert(cached, Not(Equals), nil)

	_, exists := csu.selections[cached]
	// Not added if already exists for this user
	csu.c.Assert(added, Equals, !exists)
	csu.selections[cached] = cached.GetSelections()

	// Pre-existing selections are not notified as updates
	csu.c.Assert(csu.notifications, Equals, notifications)

	return cached
}

func (csu *cachedSelectionUser) RemoveIdentitySelector(sel CachedSelector) {
	notifications := csu.notifications
	csu.sc.RemoveSelector(csu, sel)
	delete(csu.selections, sel)

	// No notifications for a removed selector
	csu.c.Assert(csu.notifications, Equals, notifications)
}

func (csu *cachedSelectionUser) IdentitySelectionUpdated(selector CachedSelector, selections, added, deleted []identity.NumericIdentity) {
	csu.notifications++
	csu.adds += len(added)
	csu.deletes += len(deleted)

	// Validate added & deleted against the selections
	for _, add := range added {
		csu.c.Assert(haveNid(add, selections), Equals, true)
	}
	for _, del := range deleted {
		csu.c.Assert(haveNid(del, selections), Equals, false)
	}

	// update selections
	csu.selections[selector] = selections
}

func (ds *SelectorCacheTestSuite) SetUpTest(c *C) {
}

func (ds *SelectorCacheTestSuite) TearDownTest(c *C) {
}

func (ds *SelectorCacheTestSuite) TestAddRemoveIdentitySelector(c *C) {
	sc := newSelectorCache()
	// Add some identities to the identity cache
	sc.UpdateIdentities(cache.IdentityCache{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s),
			k8sConst.PodNamespaceLabel: labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	}, nil)

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
	user1.RemoveIdentitySelector(cached)
	// Remove is idempotent
	user1.RemoveIdentitySelector(cached)

	// Removing the last user removes the cached selector
	user2.RemoveIdentitySelector(cached3)
	// Remove is idempotent
	user2.RemoveIdentitySelector(cached3)

	// All identities removed
	c.Assert(len(sc.selectors), Equals, 0)
}

func (ds *SelectorCacheTestSuite) TestMultipleIdentitySelectors(c *C) {
	sc := newSelectorCache()
	// Add some identities to the identity cache
	sc.UpdateIdentities(cache.IdentityCache{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	}, nil)

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

	user1.RemoveIdentitySelector(cached)
	user1.RemoveIdentitySelector(cached2)

	// All identities removed
	c.Assert(len(sc.selectors), Equals, 0)
}

func (ds *SelectorCacheTestSuite) TestIdentityUpdates(c *C) {
	sc := newSelectorCache()
	// Add some identities to the identity cache
	sc.UpdateIdentities(cache.IdentityCache{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	}, nil)

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

	// Add some identities to the identity cache
	sc.UpdateIdentities(cache.IdentityCache{
		12345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
	}, nil)
	c.Assert(user1.adds, Equals, 1)
	c.Assert(user1.deletes, Equals, 0)

	// Current selections contain the numeric identities of existing identities that match
	selections = cached.GetSelections()
	c.Assert(len(selections), Equals, 2)
	c.Assert(selections[0], Equals, identity.NumericIdentity(1234))
	c.Assert(selections[1], Equals, identity.NumericIdentity(12345))

	// Remove some identities from the identity cache
	sc.UpdateIdentities(nil, cache.IdentityCache{
		12345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
	})
	c.Assert(user1.adds, Equals, 1)
	c.Assert(user1.deletes, Equals, 1)

	// Current selections contain the numeric identities of existing identities that match
	selections = cached.GetSelections()
	c.Assert(len(selections), Equals, 1)
	c.Assert(selections[0], Equals, identity.NumericIdentity(1234))

	user1.RemoveIdentitySelector(cached)
	user1.RemoveIdentitySelector(cached2)

	// All identities removed
	c.Assert(len(sc.selectors), Equals, 0)
}

func (ds *SelectorCacheTestSuite) TestFQDNSelectorUpdates(c *C) {
	sc := newSelectorCache()
	// Add some identities to the identity cache
	googleSel := api.FQDNSelector{MatchName: "google.com"}
	ciliumSel := api.FQDNSelector{MatchName: "cilium.io"}

	googleIdentities := []identity.NumericIdentity{321, 456, 987}
	ciliumIdentities := []identity.NumericIdentity{123, 456, 789}

	sc.UpdateFQDNSelector(ciliumSel, ciliumIdentities)
	sc.UpdateFQDNSelector(googleSel, googleIdentities)

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
	ciliumIdentities = append(ciliumIdentities, identity.NumericIdentity(123456))
	sc.UpdateFQDNSelector(ciliumSel, ciliumIdentities)
	c.Assert(user1.adds, Equals, 1)
	c.Assert(user1.deletes, Equals, 0)

	ciliumIdentities = ciliumIdentities[:1]
	sc.UpdateFQDNSelector(ciliumSel, ciliumIdentities)
	c.Assert(user1.adds, Equals, 1)
	c.Assert(user1.deletes, Equals, 3)

	ciliumIdentities = []identity.NumericIdentity{}
	sc.UpdateFQDNSelector(ciliumSel, ciliumIdentities)
	c.Assert(user1.deletes, Equals, 4)

	user1.RemoveIdentitySelector(cached)
	user1.RemoveIdentitySelector(cached2)

	// All identities removed
	c.Assert(len(sc.selectors), Equals, 0)

	yahooSel := api.FQDNSelector{MatchName: "yahoo.com"}
	_, added := sc.AddFQDNSelector(user1, yahooSel)
	c.Assert(added, Equals, true)
}

func (ds *SelectorCacheTestSuite) TestRemoveIdentitiesFQDNSelectors(c *C) {
	sc := newSelectorCache()
	// Add some identities to the identity cache
	googleSel := api.FQDNSelector{MatchName: "google.com"}
	ciliumSel := api.FQDNSelector{MatchName: "cilium.io"}

	googleIdentities := []identity.NumericIdentity{321, 456, 987}
	ciliumIdentities := []identity.NumericIdentity{123, 456, 789}

	sc.UpdateFQDNSelector(ciliumSel, ciliumIdentities)
	sc.UpdateFQDNSelector(googleSel, googleIdentities)

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

	sc.RemoveIdentitiesFQDNSelectors([]api.FQDNSelector{
		googleSel,
		ciliumSel,
	})

	selections = cached.GetSelections()
	c.Assert(len(selections), Equals, 0)

	selections2 = cached2.GetSelections()
	c.Assert(len(selections2), Equals, 0)

}

func (ds *SelectorCacheTestSuite) TestIdentityUpdatesMultipleUsers(c *C) {
	sc := newSelectorCache()
	// Add some identities to the identity cache
	sc.UpdateIdentities(cache.IdentityCache{
		1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	}, nil)

	testSelector := api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s))

	user1 := newUser(c, "user1", sc)
	cached := user1.AddIdentitySelector(testSelector)

	// Add same selector from a different user
	user2 := newUser(c, "user2", sc)
	cached2 := user2.AddIdentitySelector(testSelector)
	c.Assert(cached2, Equals, cached)

	// Add some identities to the identity cache
	sc.UpdateIdentities(cache.IdentityCache{
		123: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		234: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
		345: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
	}, nil)
	c.Assert(user1.adds, Equals, 2)
	c.Assert(user1.deletes, Equals, 0)
	c.Assert(user2.adds, Equals, 2)
	c.Assert(user2.deletes, Equals, 0)

	// Current selections contain the numeric identities of existing identities that match
	selections := cached.GetSelections()
	c.Assert(len(selections), Equals, 3)
	c.Assert(selections[0], Equals, identity.NumericIdentity(123))
	c.Assert(selections[1], Equals, identity.NumericIdentity(345))
	c.Assert(selections[2], Equals, identity.NumericIdentity(1234))

	c.Assert(cached.GetSelections(), checker.DeepEquals, cached2.GetSelections())

	// Remove some identities from the identity cache
	sc.UpdateIdentities(nil, cache.IdentityCache{
		123: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s)}.LabelArray(),
		234: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
	})
	c.Assert(user1.adds, Equals, 2)
	c.Assert(user1.deletes, Equals, 1)
	c.Assert(user2.adds, Equals, 2)
	c.Assert(user2.deletes, Equals, 1)

	// Current selections contain the numeric identities of existing identities that match
	selections = cached.GetSelections()
	c.Assert(len(selections), Equals, 2)
	c.Assert(selections[0], Equals, identity.NumericIdentity(345))
	c.Assert(selections[1], Equals, identity.NumericIdentity(1234))

	c.Assert(cached.GetSelections(), checker.DeepEquals, cached2.GetSelections())

	user1.RemoveIdentitySelector(cached)
	user2.RemoveIdentitySelector(cached2)

	// All identities removed
	c.Assert(len(sc.selectors), Equals, 0)
}
