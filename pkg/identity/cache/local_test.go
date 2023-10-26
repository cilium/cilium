// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"fmt"
	"net/netip"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

func (s *IdentityCacheTestSuite) TestBumpNextNumericIdentity(c *C) {
	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(5)
	scope := identity.NumericIdentity(0x42_00_00_00)
	cache := newLocalIdentityCache(scope, minID, maxID, nil)

	for i := minID; i <= maxID; i++ {
		c.Assert(cache.nextNumericIdentity, Equals, i)
		cache.bumpNextNumericIdentity()
	}

	// ID must have overflowed and must be back to minID
	c.Assert(cache.nextNumericIdentity, Equals, minID)
}

func (s *IdentityCacheTestSuite) TestLocalIdentityCache(c *C) {
	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(5)
	scope := identity.NumericIdentity(0x42_00_00_00)
	cache := newLocalIdentityCache(scope, minID, maxID, nil)

	identities := map[identity.NumericIdentity]*identity.Identity{}

	// allocate identities for all available numeric identities with a
	// unique label
	for i := minID; i <= maxID; i++ {
		id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)}), identity.InvalidIdentity)
		c.Assert(err, IsNil)
		c.Assert(isNew, Equals, true)
		c.Assert(id.ID, Equals, scope+i)
		identities[id.ID] = id
	}

	// allocate the same labels again. This must be successful and the same
	// identities must be returned.
	for i := minID; i <= maxID; i++ {
		id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)}), identity.InvalidIdentity)
		c.Assert(isNew, Equals, false)
		c.Assert(err, IsNil)

		// The returned identity must be identical
		c.Assert(id, checker.DeepEquals, identities[id.ID])
	}

	// Allocation must fail as we are out of IDs
	_, _, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{"foo"}), identity.InvalidIdentity)
	c.Assert(err, Not(IsNil))

	// release all identities, this must decrement the reference count but not release the identities yet
	for _, id := range identities {
		c.Assert(cache.release(id), Equals, false)
	}

	// lookup must still be successful
	for i := minID; i <= maxID; i++ {
		c.Assert(cache.lookup(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)})), Not(IsNil))
		c.Assert(cache.lookupByID(i|scope), Not(IsNil))
	}

	// release the identities a second time, this must cause the identity
	// to be forgotten
	for _, id := range identities {
		c.Assert(cache.release(id), Equals, true)
	}

	// allocate all identities again
	for i := minID; i <= maxID; i++ {
		id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)}), identity.InvalidIdentity)
		c.Assert(err, IsNil)
		c.Assert(isNew, Equals, true)
		identities[id.ID] = id
	}

	// release a random identity in the middle
	randomID := identity.NumericIdentity(3) | scope
	c.Assert(cache.release(identities[randomID]), Equals, true)

	id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{"foo"}), identity.InvalidIdentity)
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
	// the selected numeric identity must be the one released before
	c.Assert(id.ID, Equals, randomID)
}

func TestOldNID(t *testing.T) {
	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(10)
	scope := identity.NumericIdentity(0x42_00_00_00)
	c := newLocalIdentityCache(scope, minID, maxID, nil)

	// Request identity, it should work
	l := labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.1/32"))
	id, _, _ := c.lookupOrCreate(l, scope)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope, id.ID)

	// Re-request identity, it should not
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.2/32"))
	id, _, _ = c.lookupOrCreate(l, scope)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope+1, id.ID)

	// Withhold the next identity, it should be skipped
	c.withhold([]identity.NumericIdentity{scope + 2})

	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.3/32"))
	id, _, _ = c.lookupOrCreate(l, 0)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope+3, id.ID)

	// Request a withheld identity, it should succeed
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.4/32"))
	id2, _, _ := c.lookupOrCreate(l, scope+2)
	assert.NotNil(t, id2)
	assert.EqualValues(t, scope+2, id2.ID)

	// Request a withheld and allocated identity, it should be ignored
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.5/32"))
	id, _, _ = c.lookupOrCreate(l, scope+2)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope+4, id.ID)

	// Unwithhold and release an identity, requesting should now succeed
	c.unwithhold([]identity.NumericIdentity{scope + 2})
	c.release(id2)
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.6/32"))
	id, _, _ = c.lookupOrCreate(l, scope+2)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope+2, id.ID)

	// Request an identity out of scope, it should not be honored
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.7/32"))
	id, _, _ = c.lookupOrCreate(l, scope-2)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope+5, id.ID)

	// Withhold all identities; allocator should fall back to a (random) withheld identity
	c.withhold([]identity.NumericIdentity{scope + 6, scope + 7, scope + 8, scope + 9, scope + 10})

	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.8/32"))
	id, _, _ = c.lookupOrCreate(l, scope-2)
	assert.NotNil(t, id)
	// actual value is random, just need it to succeed
	assert.True(t, id.ID >= scope+6 && id.ID <= scope+10, "%d <= %d <= %d", scope+6, id.ID, scope+10)
}
