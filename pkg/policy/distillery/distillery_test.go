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

package distillery

import (
	"fmt"
	"testing"

	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type DistilleryTestSuite struct{}

var (
	_ = Suite(&DistilleryTestSuite{})

	ep1 = newTestEP()
	ep2 = newTestEP()
)

// testEP wraps the testutils endpoint implementation to provide
// LookupRedirectPort() until tproxy support makes this redundant.
// This avoids import cycles when adding policy to the imports in testutils.
type testEP struct {
	testutils.TestEndpoint
}

func newTestEP() *testEP {
	return &testEP{
		testutils.NewTestEndpoint(),
	}
}

func (ep *testEP) WithIdentity(id int64) *testEP {
	ep.SetIdentity(id)
	return ep
}

func (ep *testEP) LookupRedirectPort(l4 *policy.L4Filter) uint16 {
	return 42
}

type testPolicyRepo struct {
	err      error
	revision uint64
}

func (repo *testPolicyRepo) GetRevision() uint64 {
	return repo.revision
}

func (repo *testPolicyRepo) ResolvePolicyLocked(*identityPkg.Identity) (*policy.SelectorPolicy, error) {
	return policy.NewSelectorPolicy(repo.revision), repo.err
}

func (s *DistilleryTestSuite) TestCacheManagement(c *C) {
	cache := newPolicyCache()

	identity := ep1.GetSecurityIdentity()
	c.Assert(ep2.GetSecurityIdentity(), Equals, identity)
	_, err := cache.remove(ep1)
	c.Assert(err, NotNil)

	// Upsert ep1 once, ep2 twice.
	policy1, _ := cache.upsert(identity, ep1)
	policy2, _ := cache.upsert(identity, ep2)
	c.Assert(policy1, Equals, policy2)

	// Despite three upsert calls, there should only be one reference from
	// each endpoint; removing both should clear the cache.
	cacheCleared, err := cache.remove(ep1)
	c.Assert(err, IsNil)
	c.Assert(cacheCleared, Equals, false)
	cacheCleared, err = cache.remove(ep1)
	c.Assert(err, IsNil)
	c.Assert(cacheCleared, Equals, false)
	cacheCleared, err = cache.remove(ep2)
	c.Assert(err, IsNil)
	c.Assert(cacheCleared, Equals, true)
	_, err = cache.remove(ep2)
	c.Assert(err, NotNil)

	// TODO: If we implement deferred SelectorPolicy expiry, then
	// re-inserting ep1 would reuse the same policy.
}

func (s *DistilleryTestSuite) TestCachePopulation(c *C) {
	cache := newPolicyCache()
	repo := &testPolicyRepo{revision: 42}

	identity1 := ep1.GetSecurityIdentity()
	c.Assert(ep2.GetSecurityIdentity(), Equals, identity1)

	// Upsert ep1, ep2
	policy1, computed := cache.upsert(identity1, ep1)
	c.Assert(computed, Equals, false)
	policy2, computed := cache.upsert(identity1, ep2)
	c.Assert(computed, Equals, false)
	c.Assert(policy1, Equals, policy2)

	// Calculate the policy and observe that it's cached
	updated, err := cache.updateSelectorPolicy(repo, ep1)
	c.Assert(err, IsNil)
	c.Assert(updated, Equals, true)
	updated, err = cache.updateSelectorPolicy(repo, ep1)
	c.Assert(err, IsNil)
	c.Assert(updated, Equals, false)
	updated, err = cache.updateSelectorPolicy(repo, ep2)
	c.Assert(err, IsNil)
	c.Assert(updated, Equals, false)
	policy2, computed = cache.upsert(identity1, ep2)
	c.Assert(computed, Equals, true)
	idp1 := policy1.(*cachedSelectorPolicy).getPolicy()
	idp2 := policy2.(*cachedSelectorPolicy).getPolicy()
	c.Assert(idp1, Equals, idp2)

	// Remove ep1 and observe that ep2 still has access to the policy
	cacheCleared, err := cache.remove(ep1)
	c.Assert(err, IsNil)
	c.Assert(cacheCleared, Equals, false)
	updated, err = cache.updateSelectorPolicy(repo, ep2)
	c.Assert(err, IsNil)
	c.Assert(updated, Equals, false)

	// Attempt to update policy for non-cached endpoint and observe failure
	ep3 := newTestEP().WithIdentity(1234)
	_, err = cache.updateSelectorPolicy(repo, ep3)
	c.Assert(err, NotNil)
	c.Assert(updated, Equals, false)

	// Insert endpoint with different identity and observe that the cache
	// is different from ep1, ep2
	identity3 := ep3.GetSecurityIdentity()
	policy3, computed := cache.upsert(identity3, ep3)
	c.Assert(policy3, Not(Equals), policy1)
	c.Assert(computed, Equals, false)
	updated, err = cache.updateSelectorPolicy(repo, ep3)
	c.Assert(err, IsNil)
	c.Assert(updated, Equals, true)
	idp3 := policy3.(*cachedSelectorPolicy).getPolicy()
	c.Assert(idp3, Not(Equals), idp1)

	// If there's an error during policy resolution, update should fail
	repo.err = fmt.Errorf("not implemented!")
	repo.revision++
	_, err = cache.updateSelectorPolicy(repo, ep3)
	c.Assert(err, NotNil)
}
