// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"fmt"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

func (s *IdentityCacheTestSuite) TestBumpNextNumericIdentity(c *C) {
	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(5)
	cache := newLocalIdentityCache(minID, maxID, nil)

	for i := minID; i <= maxID; i++ {
		c.Assert(cache.nextNumericIdentity, Equals, i)
		cache.bumpNextNumericIdentity()
	}

	// ID must have overflowed and must be back to minID
	c.Assert(cache.nextNumericIdentity, Equals, minID)
}

func (s *IdentityCacheTestSuite) TestLocalIdentityCache(c *C) {
	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(5)
	cache := newLocalIdentityCache(minID, maxID, nil)

	identities := map[identity.NumericIdentity]*identity.Identity{}

	// allocate identities for all available numeric identities with a
	// unique label
	for i := minID; i <= maxID; i++ {
		id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)}), identity.InvalidIdentity)
		c.Assert(err, IsNil)
		c.Assert(isNew, Equals, true)
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
		c.Assert(cache.lookupByID(i|identity.LocalIdentityFlag), Not(IsNil))
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
	randomID := identity.NumericIdentity(3) | identity.LocalIdentityFlag
	c.Assert(cache.release(identities[randomID]), Equals, true)

	id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{"foo"}), identity.InvalidIdentity)
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
	// the selected numeric identity must be the one released before
	c.Assert(id.ID, Equals, randomID)
}
