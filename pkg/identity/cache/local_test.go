// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestBumpNextNumericIdentity(t *testing.T) {
	testutils.IntegrationTest(t)

	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(5)
	scope := identity.NumericIdentity(0x42_00_00_00)
	cache := newLocalIdentityCache(scope, minID, maxID, nil)

	for i := minID; i <= maxID; i++ {
		require.Equal(t, i, cache.nextNumericIdentity)
		cache.bumpNextNumericIdentity()
	}

	// ID must have overflowed and must be back to minID
	require.Equal(t, minID, cache.nextNumericIdentity)
}

func TestLocalIdentityCache(t *testing.T) {
	testutils.IntegrationTest(t)

	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(5)
	scope := identity.NumericIdentity(0x42_00_00_00)
	cache := newLocalIdentityCache(scope, minID, maxID, nil)

	identities := map[identity.NumericIdentity]*identity.Identity{}

	// allocate identities for all available numeric identities with a
	// unique label
	for i := minID; i <= maxID; i++ {
		id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)}), identity.InvalidIdentity, false)
		require.NoError(t, err)
		require.True(t, isNew)
		require.Equal(t, scope+i, id.ID)
		identities[id.ID] = id
	}

	// allocate the same labels again. This must be successful and the same
	// identities must be returned.
	for i := minID; i <= maxID; i++ {
		id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)}), identity.InvalidIdentity, false)
		require.False(t, isNew)
		require.NoError(t, err)

		// The returned identity must be identical
		require.EqualValues(t, identities[id.ID], id)
	}

	// Allocation must fail as we are out of IDs
	_, _, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{"foo"}), identity.InvalidIdentity, false)
	require.Error(t, err)

	// release all identities, this must decrement the reference count but not release the identities yet
	for _, id := range identities {
		require.False(t, cache.release(id, false))
	}

	// lookup must still be successful
	for i := minID; i <= maxID; i++ {
		require.NotNil(t, cache.lookup(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)})))
		require.NotNil(t, cache.lookupByID(i|scope))
	}

	// release the identities a second time, this must cause the identity
	// to be forgotten
	for _, id := range identities {
		require.True(t, cache.release(id, false))
	}

	// allocate all identities again
	for i := minID; i <= maxID; i++ {
		id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)}), identity.InvalidIdentity, false)
		require.NoError(t, err)
		require.True(t, isNew)
		identities[id.ID] = id
	}

	// release a random identity in the middle
	randomID := identity.NumericIdentity(3) | scope
	require.True(t, cache.release(identities[randomID], false))

	id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{"foo"}), identity.InvalidIdentity, false)
	require.NoError(t, err)
	require.True(t, isNew)
	// the selected numeric identity must be the one released before
	require.Equal(t, randomID, id.ID)
}

func TestOldNID(t *testing.T) {
	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(10)
	scope := identity.NumericIdentity(0x42_00_00_00)
	c := newLocalIdentityCache(scope, minID, maxID, nil)

	// Request identity, it should work
	l := labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.1/32"))
	id, _, _ := c.lookupOrCreate(l, scope, false)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope, id.ID)

	// Re-request identity, it should not
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.2/32"))
	id, _, _ = c.lookupOrCreate(l, scope, false)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope+1, id.ID)

	// Withhold the next identity, it should be skipped
	c.withhold([]identity.NumericIdentity{scope + 2})

	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.3/32"))
	id, _, _ = c.lookupOrCreate(l, 0, false)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope+3, id.ID)

	// Request a withheld identity, it should succeed
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.4/32"))
	id2, _, _ := c.lookupOrCreate(l, scope+2, false)
	assert.NotNil(t, id2)
	assert.EqualValues(t, scope+2, id2.ID)

	// Request a withheld and allocated identity, it should be ignored
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.5/32"))
	id, _, _ = c.lookupOrCreate(l, scope+2, false)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope+4, id.ID)

	// Unwithhold and release an identity, requesting should now succeed
	c.unwithhold([]identity.NumericIdentity{scope + 2})
	c.release(id2, false)
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.6/32"))
	id, _, _ = c.lookupOrCreate(l, scope+2, false)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope+2, id.ID)

	// Request an identity out of scope, it should not be honored
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.7/32"))
	id, _, _ = c.lookupOrCreate(l, scope-2, false)
	assert.NotNil(t, id)
	assert.EqualValues(t, scope+5, id.ID)

	// Withhold all identities; allocator should fall back to a (random) withheld identity
	c.withhold([]identity.NumericIdentity{scope + 6, scope + 7, scope + 8, scope + 9, scope + 10})

	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.8/32"))
	id, _, _ = c.lookupOrCreate(l, scope-2, false)
	assert.NotNil(t, id)
	// actual value is random, just need it to succeed
	assert.True(t, id.ID >= scope+6 && id.ID <= scope+10, "%d <= %d <= %d", scope+6, id.ID, scope+10)
}
